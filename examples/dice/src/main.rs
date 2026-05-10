//! `dice-forge` — provably-fair 3D6 dice example.
//!
//! Each launch reads `dice.wal` (if any), prompts for a user seed,
//! mixes it with a fresh server seed via BLAKE3, rolls three dice
//! through `arkhe-rand`, dispatches the result through forge L1 + L2,
//! exports the WAL back to `dice.wal`, and prints the most recent five
//! rolls in chronological order.
//!
//! ## CLI
//!
//! - `cargo run -p dice-forge`            — interactive roll mode
//! - `cargo run -p dice-forge -- --reset` — delete `dice.wal`
//! - `cargo run -p dice-forge -- --verify` — replay-equivalence check
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

fn wal_path() -> PathBuf {
    // Resolve relative to the workspace example dir so `cargo run -p
    // dice-forge` from any cwd lands in the same file.
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
            eprintln!("dice-forge: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "dice-forge — provably-fair 3D6 dice example\n\
         \n\
         Usage:\n  \
         cargo run -p dice-forge            # interactive roll\n  \
         cargo run -p dice-forge -- --reset # delete dice.wal\n  \
         cargo run -p dice-forge -- --verify # replay-equivalence check"
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

/// Default mode — interactive roll.
fn roll_mode() -> Result<(), Box<dyn std::error::Error>> {
    let path = wal_path();
    let history = load_history(&path)?;

    // Stage 1 — server entropy via OS CSPRNG. Direct `getrandom` keeps
    // the entropy path explicit (no intermediate PRF layer through
    // `arkhe-rand`); the resulting bytes ARE the server seed.
    let mut server_seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(server_seed.as_mut_slice())
        .map_err(|e| std::io::Error::other(format!("OS entropy unavailable: {e}")))?;

    let commitment_server = blake3_concat2(DOMAIN_DICE_COMMIT, &server_seed[..]);
    println!(
        "Commitment (server-side, broadcast pre-roll): {}",
        hex32(&commitment_server)
    );

    // Stage 2 — user input.
    let user_input = read_user_seed(MAX_EMPTY_INPUT_ATTEMPTS, MAX_USER_INPUT_BYTES)?;

    // Stage 3 — combined seed. Order: domain || server_seed ||
    // user_input.as_bytes() || nonce.to_le_bytes() — replay determinism
    // depends on this exact order.
    let nonce: u64 = history.len() as u64;
    let combined_seed = blake3_concat4(
        DOMAIN_DICE_COMBINED,
        &server_seed[..],
        user_input.as_bytes(),
        &nonce.to_le_bytes(),
    );

    // Stage 4 — roll. 3× sequential calls; replay determinism depends
    // on call order (die 1, die 2, die 3).
    let mut rng = arkhe_rand::RngSource::from_seed(&combined_seed);
    let dice: [u8; 3] = [
        arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
        arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
        arkhe_rand::gen_range_inclusive(&mut rng, 1u32..=6) as u8,
    ];

    // Stage 5 — dispatch (replay prior + new). Each prior record is
    // re-emitted in order so the kernel rebuilds the WAL with its
    // own monotonic seq + chain-hash chain; the new record is then
    // appended after the replay catches up.
    let new_record = RecordDiceRoll {
        schema_version: 2,
        commitment_server,
        server_seed: *server_seed,
        user_input: user_input.clone(),
        nonce,
        combined_seed,
        dice,
    };

    let svc = compose_service_with_replay(&history, Some(&new_record))?;

    // Stage 6 — persist. `export_wal` consumes the service; the
    // resulting `Wal` is streamed through `BufferedWalSink` into a
    // freshly truncated `dice.wal`. Each launch overwrites the file
    // with the full canonical stream (single `ARKHEXP1` header per
    // file — append-only invariant intact within a stream).
    let wal = svc
        .export_wal()
        .ok_or("RuntimeService::export_wal returned None")?;
    let file = File::create(&path)?;
    let mut sink = BufferedWalSink::new(file);
    wal_to_sink(&wal, &mut sink)?;

    // Stage 7 — display. Build the chronological row list (prior
    // history + the new roll), then show the bottom DISPLAY_CAP rows.
    let mut rows: Vec<DisplayRow> = history.iter().map(DisplayRow::from_history_entry).collect();
    rows.push(DisplayRow::from_new(&new_record));
    print_history(&rows, DISPLAY_CAP, /*new_marker_last=*/ true);
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
            "dice.wal verify OK — {} record(s), {} byte(s).",
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
        svc.dispatch(
            instance,
            Principal::System,
            &entry.record,
            Tick(next_tick),
            CapabilityMask::SYSTEM,
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
        print!("Enter your seed: ");
        std::io::stdout().flush()?;
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
                "empty seed; please enter at least one character (attempt {attempt}/{max_attempts})"
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

/// One row of the display table. Built from either a recovered history
/// entry or the freshly-rolled record.
struct DisplayRow {
    user_input: String,
    dice: [u8; 3],
    chain_hash: [u8; 32],
}

impl DisplayRow {
    fn from_history_entry(entry: &HistoryEntry) -> Self {
        let r = &entry.record;
        let chain_hash = blake3_concat3(DOMAIN_DICE_CHAIN, &r.dice, r.user_input.as_bytes());
        Self {
            user_input: r.user_input.clone(),
            dice: r.dice,
            chain_hash,
        }
    }

    fn from_new(r: &RecordDiceRoll) -> Self {
        let chain_hash = blake3_concat3(DOMAIN_DICE_CHAIN, &r.dice, r.user_input.as_bytes());
        Self {
            user_input: r.user_input.clone(),
            dice: r.dice,
            chain_hash,
        }
    }
}

/// Print the bottom `cap` rows of `rows` in chronological order
/// (oldest top, newest bottom). The `#` column is a 1-indexed display
/// counter — the kernel-side `tick` field is preserved in the WAL but
/// hidden here per the user-facing display spec.
fn print_history(rows: &[DisplayRow], cap: usize, new_marker_last: bool) {
    let total = rows.len();
    let start = total.saturating_sub(cap);
    let visible = &rows[start..];
    println!();
    println!("─── Recent history (top {cap}) ─────────────────────────────────────");
    println!("┌──────┬────────────────┬─────────────┬─────┬────────────┐");
    println!("│  #   │ user_input     │ dice        │ sum │ chain_hash │");
    println!("├──────┼────────────────┼─────────────┼─────┼────────────┤");
    for (idx, row) in visible.iter().enumerate() {
        let display_idx = start + idx + 1;
        let user_disp = truncate_display(&row.user_input, 14);
        let sum: u32 = row.dice.iter().map(|&v| v as u32).sum();
        let dice_str = format!("[{},{},{}]", row.dice[0], row.dice[1], row.dice[2]);
        let chain_short = format!("{}...", hex_prefix(&row.chain_hash, 4));
        let marker = if new_marker_last && idx + 1 == visible.len() {
            "  ← NEW"
        } else {
            ""
        };
        println!(
            "│ {:>4} │ {:<14} │ {:<11} │ {:>3} │ {:<10} │{}",
            display_idx, user_disp, dice_str, sum, chain_short, marker
        );
    }
    println!("└──────┴────────────────┴─────────────┴─────┴────────────┘");
}

/// Truncate a display string to `max` chars (Rust char count, NOT
/// bytes). Multi-byte chars stay intact.
fn truncate_display(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Lowercase hex of the first `n` bytes.
fn hex_prefix(bytes: &[u8], n: usize) -> String {
    let take = bytes.len().min(n);
    let mut out = String::with_capacity(take * 2);
    for b in &bytes[..take] {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{:02x}", b));
    }
    out
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
