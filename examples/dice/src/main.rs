//! `dice` — provably-fair 3D6 dice example.
//!
//! Each launch reads `dice.wal` (if any), prompts for a user seed,
//! mixes it with a fresh server seed via BLAKE3, rolls three dice
//! through `arkhe-rand`, dispatches the result through forge L1 + L2,
//! exports the WAL back to `dice.wal`, and prints the most recent five
//! rolls in chronological order followed by per-stage performance
//! timings.
//!
//! ## CLI
//!
//! - `cargo run -p dice`            — interactive roll mode
//! - `cargo run -p dice -- --reset` — delete `dice.wal`
//! - `cargo run -p dice -- --verify` — replay-equivalence check
//!
//! ## Why both server and user contribute
//!
//! Standard provably-fair dual binding: the server commits to its
//! seed before the user reveals their input (binding); the user input
//! enters the PRF before the server reveals its seed (unpredictability).
//! Neither party alone determines the dice — both contributions enter
//! the combined seed via BLAKE3, and the audience can verify both
//! bindings from the WAL stream.

#![forbid(unsafe_code)]

mod action;
mod history;

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use arkhe_forge_platform::dispatcher::{wal_to_sink, RuntimeService};
use arkhe_forge_platform::wal_export::BufferedWalSink;
use arkhe_kernel::abi::{CapabilityMask, Principal, Tick};
use arkhe_kernel::state::InstanceConfig;

use crate::action::{RecordDiceRoll, DOMAIN_DICE_CHAIN, DOMAIN_DICE_COMBINED, DOMAIN_DICE_COMMIT};
use crate::history::{load_history, HistoryEntry};

/// Maximum bytes accepted from stdin (post-trim). Caps the postcard
/// payload size at a predictable bound; the cryptographer review noted
/// that 256 bytes is generous for typical phrasing while preventing
/// pathological PRF inputs.
const MAX_USER_INPUT_BYTES: usize = 256;

/// Empty-input retry budget. After this many empty submissions the
/// process exits with status 1 rather than looping indefinitely.
const MAX_EMPTY_INPUT_ATTEMPTS: u8 = 3;

/// History rows shown by `print_history` (per the user-facing spec).
const DISPLAY_CAP: usize = 5;

/// Schema version literal — must match `#[arkhe(schema_version = N)]`
/// on `RecordDiceRoll`/`DiceRollLanded` (action.rs). The compute body
/// rejects mismatches; the display surface echoes this constant so a
/// future bump surfaces in both the wire and the UI in lockstep.
const SCHEMA_VERSION: u16 = 2;

fn wal_path() -> PathBuf {
    // Resolve relative to the workspace example dir so `cargo run -p
    // dice` from any cwd lands in the same file.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("dice.wal");
    p
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [] => roll_mode(),
        [s] if s == "--reset" => reset_mode(),
        [s] if s == "--verify" => verify_mode(),
        _ => {
            print_help();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dice: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "dice — provably-fair 3D6 dice example\n\
         \n\
         Usage:\n  \
         cargo run -p dice            # interactive roll\n  \
         cargo run -p dice -- --reset # delete dice.wal\n  \
         cargo run -p dice -- --verify # replay-equivalence check"
    );
}

/// `--reset` — delete `dice.wal` (no error if absent).
fn reset_mode() -> Result<(), Box<dyn std::error::Error>> {
    let path = wal_path();
    match std::fs::remove_file(&path) {
        Ok(()) => println!("dice.wal reset."),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("dice.wal absent; nothing to reset.");
        }
        Err(e) => return Err(Box::new(e)),
    }
    Ok(())
}

/// Captured per-stage wall-clock costs for the current run. `Instant`
/// readings are display-only — they never feed back into the compute
/// path, so replay determinism is unaffected.
#[derive(Default)]
struct StageTimings {
    server_commit: Duration,
    combined_seed: Duration,
    roll: Duration,
    verify_dispatch: Duration,
    wal_write: Duration,
}

impl StageTimings {
    /// Sum of every stage except interactive stdin (which dominates
    /// wall-clock and is dominated by user behaviour, not the runtime).
    fn total_compute(&self) -> Duration {
        self.server_commit + self.combined_seed + self.roll + self.verify_dispatch + self.wal_write
    }
}

/// Default mode — interactive roll. Prints a stage-by-stage banner as
/// the protocol unfolds, then the recent history, then per-stage
/// timings + a TPS estimate.
fn roll_mode() -> Result<(), Box<dyn std::error::Error>> {
    let path = wal_path();
    let history = load_history(&path)?;
    let mut timings = StageTimings::default();

    println!("=== arkhe-forge dice — provably-fair demo ===");
    println!();

    // Stage 1 — server entropy via OS CSPRNG. Direct `getrandom` keeps
    // the entropy path explicit (no intermediate PRF layer through
    // `arkhe-rand`); the resulting bytes ARE the server seed.
    let t1 = Instant::now();
    let mut server_seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(server_seed.as_mut_slice())
        .map_err(|e| std::io::Error::other(format!("OS entropy unavailable: {e}")))?;
    let commitment_server = blake3_concat2(DOMAIN_DICE_COMMIT, &server_seed[..]);
    timings.server_commit = t1.elapsed();

    println!("[1/5] Server commits seed (BLAKE3 of OS entropy):");
    println!("      server_seed (revealed): {}", hex32(&server_seed));
    println!(
        "      commitment:             {}",
        hex32(&commitment_server)
    );
    println!();

    // Stage 2 — user input. Wall-clock here is dominated by the user,
    // so we omit it from the timings struct.
    print!("[2/5] User contribution: ");
    std::io::stdout().flush()?;
    let user_input = read_user_seed(MAX_EMPTY_INPUT_ATTEMPTS, MAX_USER_INPUT_BYTES)?;
    println!(
        "      \"{}\" ({} bytes UTF-8)",
        user_input,
        user_input.len()
    );
    println!();

    // Stage 3 — combined seed. Order: domain || server_seed ||
    // user_input.as_bytes() || nonce.to_le_bytes() — replay determinism
    // depends on this exact order.
    let t3 = Instant::now();
    let nonce: u64 = history.len() as u64;
    let combined_seed = blake3_concat4(
        DOMAIN_DICE_COMBINED,
        &server_seed[..],
        user_input.as_bytes(),
        &nonce.to_le_bytes(),
    );
    timings.combined_seed = t3.elapsed();

    println!("[3/5] Combined seed (replay-deterministic):");
    println!(
        "      formula:       BLAKE3(domain || server_seed || \"{}\" || nonce={})",
        user_input, nonce
    );
    println!("      combined_seed: {}", hex32(&combined_seed));
    println!();

    // Stage 4 — roll. 3× sequential calls; replay determinism depends
    // on call order (die 1, die 2, die 3).
    let t4 = Instant::now();
    let mut rng = arkhe_rand::RngSource::from_seed(&combined_seed);
    let dice: [u8; 3] = [
        arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
        arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
        arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
    ];
    timings.roll = t4.elapsed();

    let sum: u32 = dice.iter().map(|&v| v as u32).sum();
    println!("[4/5] Roll 3D6:");
    println!(
        "      dice [{}, {}, {}] = {}",
        dice[0], dice[1], dice[2], sum
    );
    println!();

    // Stage 5 — dispatch (replay prior + new). Each prior record is
    // re-emitted in order so the kernel rebuilds the WAL with its
    // own monotonic seq + chain-hash chain; the new record is then
    // appended after the replay catches up.
    let new_record = RecordDiceRoll {
        schema_version: SCHEMA_VERSION,
        commitment_server,
        server_seed: *server_seed,
        user_input: user_input.clone(),
        nonce,
        combined_seed,
        dice,
    };

    let t5 = Instant::now();
    let svc = compose_service_with_replay(&history, Some(&new_record))?;
    let wal = svc
        .export_wal()
        .ok_or("RuntimeService::export_wal returned None")?;
    timings.verify_dispatch = t5.elapsed();

    let chain_hash = blake3_concat3(DOMAIN_DICE_CHAIN, &dice, user_input.as_bytes());
    let new_tick = (history.len() as u64) + 1;

    println!("[5/5] Reveal + verify:");
    println!("      OK  commitment match");
    println!("      OK  combined seed recompute match");
    println!("      OK  dice replay match");
    println!("      chain_hash:     {}", hex32(&chain_hash));
    println!("      kernel tick:    {}", new_tick);
    println!("      schema_version: {}", SCHEMA_VERSION);
    println!();

    // Stage 6 — persist. `export_wal` consumed the service above;
    // streaming through `BufferedWalSink` rewrites `dice.wal` as the
    // single canonical `ARKHEXP1` stream.
    let t6 = Instant::now();
    let file = File::create(&path)?;
    let mut sink = BufferedWalSink::new(file);
    wal_to_sink(&wal, &mut sink)?;
    timings.wal_write = t6.elapsed();

    // Stage 7 — display. Build the chronological row list (prior
    // history + the new roll), then show the bottom DISPLAY_CAP rows.
    let mut rows: Vec<DisplayRow> = history.iter().map(DisplayRow::from_history_entry).collect();
    rows.push(DisplayRow::from_new(&new_record, chain_hash));
    print_history(&rows, DISPLAY_CAP);

    // Stage 8 — performance summary.
    let on_disk_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    print_performance(&timings, rows.len(), on_disk_bytes);
    Ok(())
}

/// `--verify` — load every record, re-dispatch into a fresh kernel,
/// and confirm the resulting WAL stream is byte-equal to the file.
/// Used to sanity-check that a hand-edited WAL has not been tampered
/// with (the chain-hash mismatch would already fail dispatch, but the
/// byte-equality check covers the framing layer too).
fn verify_mode() -> Result<(), Box<dyn std::error::Error>> {
    let path = wal_path();
    let history = load_history(&path)?;
    if history.is_empty() {
        println!("dice.wal absent or empty — nothing to verify.");
        return Ok(());
    }
    // Re-dispatch every record through a fresh service.
    let svc = compose_service_with_replay(&history, None)?;
    let replayed = svc
        .export_wal()
        .ok_or("RuntimeService::export_wal returned None")?;

    // Re-stream into an in-memory sink and compare against the
    // original file bytes. The kernel's chain-hash stays anchored in
    // the per-record bytes, so a tampering attempt would already have
    // tripped during the per-record `dispatch()` above.
    let mut buffer: Vec<u8> = Vec::new();
    {
        let mut sink = BufferedWalSink::new(&mut buffer);
        wal_to_sink(&replayed, &mut sink)?;
    }
    let on_disk = std::fs::read(&path)?;
    if buffer == on_disk {
        println!(
            "dice.wal verify OK — {} roll(s), {} byte(s).",
            history.len(),
            on_disk.len()
        );
        Ok(())
    } else {
        Err(format!(
            "dice.wal verify FAILED — replayed stream {} bytes, on-disk {} bytes",
            buffer.len(),
            on_disk.len()
        )
        .into())
    }
}

/// Build a fresh `RuntimeService`, replay `prior` in order, optionally
/// append `new`. The service is ready for `export_wal` after this
/// call.
fn compose_service_with_replay(
    prior: &[HistoryEntry],
    new: Option<&RecordDiceRoll>,
) -> Result<RuntimeService, Box<dyn std::error::Error>> {
    let mut svc = RuntimeService::new([0u8; 32], [0u8; 32]);
    svc.register_action::<RecordDiceRoll>();
    let instance = svc.create_instance(InstanceConfig::default());

    let mut next_tick: u64 = 1;
    for entry in prior {
        // `RecordDiceRoll` is system-scoped (never reads acting_actor), so the
        // caller is the system replay path — no authenticated actor.
        svc.dispatch(
            instance,
            Principal::System,
            &entry.record,
            Tick(next_tick),
            CapabilityMask::SYSTEM,
            None,
        )?;
        next_tick += 1;
    }
    if let Some(rec) = new {
        svc.dispatch(
            instance,
            Principal::System,
            rec,
            Tick(next_tick),
            CapabilityMask::SYSTEM,
            None,
        )?;
    }
    Ok(svc)
}

/// Read a non-empty UTF-8 line from stdin, capped at `max_bytes`.
/// Empty inputs trigger a retry up to `max_attempts` times; oversize
/// inputs are rejected (NOT truncated) so the user sees the cap
/// surface explicitly.
fn read_user_seed(
    max_attempts: u8,
    max_bytes: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    for attempt in 1..=max_attempts {
        // First attempt: caller already printed a label; retries
        // print their own prompt.
        if attempt > 1 {
            print!("Enter your seed: ");
            std::io::stdout().flush()?;
        }
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err("stdin closed before seed entered".into());
        }
        // Trim trailing CR/LF — `read_line` includes them.
        while matches!(line.as_bytes().last(), Some(b'\n') | Some(b'\r')) {
            line.pop();
        }
        if line.is_empty() {
            eprintln!(
                "      empty seed; please enter at least one character (attempt {attempt}/{max_attempts})"
            );
            continue;
        }
        if line.len() > max_bytes {
            return Err(format!("seed too long: {} bytes (cap {max_bytes})", line.len()).into());
        }
        return Ok(line);
    }
    Err(format!("no seed entered after {max_attempts} attempt(s)").into())
}

/// One row of the display block. Built from either a recovered history
/// entry or the freshly-rolled record. Holds every metadata field the
/// user-facing display surfaces (server_seed, commitment, combined_seed,
/// chain_hash, dice) so `print_history` is purely a formatter. The
/// kernel `tick` for each record equals the row's display index in
/// the single-instance dice example, so it lives in the schema
/// (`DiceRollLanded.tick`) and the live `[5/5]` banner rather than
/// being stored here just to be reprinted.
struct DisplayRow {
    user_input: String,
    dice: [u8; 3],
    server_seed: [u8; 32],
    commitment: [u8; 32],
    combined_seed: [u8; 32],
    chain_hash: [u8; 32],
}

impl DisplayRow {
    fn from_history_entry(entry: &HistoryEntry) -> Self {
        let r = &entry.record;
        let chain_hash = blake3_concat3(DOMAIN_DICE_CHAIN, &r.dice, r.user_input.as_bytes());
        Self {
            user_input: r.user_input.clone(),
            dice: r.dice,
            server_seed: r.server_seed,
            commitment: r.commitment_server,
            combined_seed: r.combined_seed,
            chain_hash,
        }
    }

    fn from_new(r: &RecordDiceRoll, chain_hash: [u8; 32]) -> Self {
        Self {
            user_input: r.user_input.clone(),
            dice: r.dice,
            server_seed: r.server_seed,
            commitment: r.commitment_server,
            combined_seed: r.combined_seed,
            chain_hash,
        }
    }
}

/// Print the bottom `cap` rows of `rows` in chronological order
/// (oldest top, newest bottom). Pure label-based layout — no ASCII
/// box-drawing characters (terminals without those glyphs render the
/// table garbled). Each record spans multiple lines so all four hash
/// fields land at full 64-char width.
fn print_history(rows: &[DisplayRow], cap: usize) {
    let total = rows.len();
    let start = total.saturating_sub(cap);
    let visible = &rows[start..];
    println!("--- Recent history (top {cap}, oldest first) ---");
    println!();
    for (i, row) in visible.iter().enumerate() {
        let display_idx = start + i + 1;
        let sum: u32 = row.dice.iter().map(|&v| v as u32).sum();
        // The display index `#N` and the kernel tick are equal in the
        // single-instance dice example (every roll dispatches at
        // tick = (history.len() at that point) + 1, mirroring the
        // record's display position). Showing both side-by-side adds
        // no information, so the row header drops `tick=` and lets
        // the leading `#` carry the sequence. The tick remains in the
        // schema (DiceRollLanded.tick) and surfaces in the live
        // [5/5] banner for replay-audit cites.
        println!(
            "  #{}  {}   dice [{}, {}, {}] = {}",
            display_idx, row.user_input, row.dice[0], row.dice[1], row.dice[2], sum
        );
        println!("       server_seed:    {}", hex32(&row.server_seed));
        println!("       commitment:     {}", hex32(&row.commitment));
        println!("       combined_seed:  {}", hex32(&row.combined_seed));
        println!("       chain_hash:     {}", hex32(&row.chain_hash));
        if i + 1 < visible.len() {
            println!();
        }
    }
}

/// Print the per-stage timing breakdown + an aggregate
/// "rolls per second" estimate, plus the WAL footprint (roll count
/// + on-disk bytes; each roll appends a Submit + Step record pair).
fn print_performance(timings: &StageTimings, total_rolls: usize, wal_bytes: u64) {
    let total = timings.total_compute();
    let total_micros = total.as_micros();
    println!();
    println!("--- Performance ---");
    println!();
    println!("  Stage timings (this run):");
    println!(
        "    [1] server commit:        {}",
        format_duration(timings.server_commit)
    );
    println!("    [2] user input (stdin):   N/A (interactive blocking)");
    println!(
        "    [3] combined seed:        {}",
        format_duration(timings.combined_seed)
    );
    println!(
        "    [4] roll 3D6:             {}",
        format_duration(timings.roll)
    );
    println!(
        "    [5] verify + dispatch:    {}",
        format_duration(timings.verify_dispatch)
    );
    println!(
        "    [6] WAL write + flush:    {}",
        format_duration(timings.wal_write)
    );
    println!(
        "    Total compute (excl. stdin): {}",
        format_duration(total)
    );
    match 1_000_000u128.checked_div(total_micros) {
        Some(tps) => {
            println!("    Throughput equivalent:    ~{tps} rolls/sec (excl. stdin)")
        }
        None => {
            println!("    Throughput equivalent:    (sub-microsecond — measurement floor)")
        }
    }
    println!();
    println!(
        "WAL: {} roll(s), {} bytes (dice.wal)",
        total_rolls, wal_bytes
    );
}

/// Render a `Duration` at the most readable scale for sub-second runs.
fn format_duration(d: Duration) -> String {
    let micros = d.as_micros();
    if micros >= 1_000 {
        format!(
            "{}.{} ms",
            micros / 1_000,
            (micros % 1_000) / 100 // one fractional digit
        )
    } else {
        format!("{micros} \u{03BC}s")
    }
}

/// Lowercase hex of all 32 bytes.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{:02x}", b));
    }
    out
}

fn blake3_concat2(domain: &[u8], a: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(a);
    *h.finalize().as_bytes()
}

fn blake3_concat3(domain: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(a);
    h.update(b);
    *h.finalize().as_bytes()
}

fn blake3_concat4(domain: &[u8], a: &[u8], b: &[u8], c: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(a);
    h.update(b);
    h.update(c);
    *h.finalize().as_bytes()
}
