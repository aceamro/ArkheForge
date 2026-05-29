//! Dice WAL load helper — read a `dice.wal` stream produced by a
//! previous run and recover the chronological list of `RecordDiceRoll`
//! payloads. Replay = re-dispatch of every payload through a freshly
//! built `RuntimeService`, so the on-disk file is a *complete* history,
//! not a delta log.

use std::fs::File;
use std::path::Path;

use arkhe_forge_platform::wal_export::{StreamingWalReader, WalStreamReader};
use arkhe_kernel::WalRecord;

use crate::action::RecordDiceRoll;

/// One entry in the recovered history. Holds the original Action
/// payload — caller re-dispatches this verbatim to repopulate the
/// kernel's WAL on launch. The kernel re-derives its own `seq` + `at`
/// during dispatch, so the per-record envelope is recomputed and not
/// stored here.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// Recorded Action payload (deserialized from `WalRecord.action_bytes`).
    pub record: RecordDiceRoll,
}

/// Errors surfaced by [`load_history`]. All variants are fail-loud:
/// the binary's `roll_mode` exits with a non-zero status if any of
/// these fire so corruption never silently degrades the history.
#[derive(Debug, thiserror::Error)]
pub enum HistoryLoadError {
    /// The WAL file exists but is unreadable (permissions, mid-flight
    /// truncation, etc.).
    #[error("WAL file I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Stream framing rejected by the reader (header magic, length
    /// prefix, append-only seq, etc.). See
    /// [`arkhe_forge_platform::wal_export::WalExportError`].
    #[error("WAL framing: {0}")]
    Framing(#[from] arkhe_forge_platform::wal_export::WalExportError),
    /// Postcard rejected the framed payload (kernel `WalRecord` shape
    /// mismatch — should never fire under the wire pin).
    #[error("WAL record decode: {0}")]
    WalRecordDecode(postcard::Error),
    /// Postcard rejected the embedded Action bytes (wire-shape skew
    /// vs the `RecordDiceRoll` schema).
    #[error("RecordDiceRoll decode: {0}")]
    ActionDecode(postcard::Error),
}

/// Type-code filter — only records whose `action_type_code` matches
/// `RecordDiceRoll::TYPE_CODE` are returned. Other types are silently
/// skipped so a future co-tenant Action would not break replay (the
/// dice-only WAL today has no co-tenants, but the filter keeps the
/// helper future-proof).
const RECORD_DICE_ROLL_TYPE_CODE: u32 = 0x0200_0001;

/// Load every `RecordDiceRoll` from `dice.wal` in chronological order.
/// Returns `Ok(vec![])` if the file is absent (first launch).
///
/// The returned vector preserves the WAL append order — index 0 is
/// the first roll, index N-1 is the most recent. The dispatch loop in
/// `roll_mode` re-emits these in this exact order so the kernel's seq
/// monotonicity invariant holds.
pub fn load_history(path: &Path) -> Result<Vec<HistoryEntry>, HistoryLoadError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(HistoryLoadError::Io(e)),
    };
    let mut reader = StreamingWalReader::open_v1(file)?;
    let mut out = Vec::new();
    while let Some(payload) = reader.next_record()? {
        let wal_record: WalRecord =
            postcard::from_bytes(payload).map_err(HistoryLoadError::WalRecordDecode)?;
        if wal_record.action_type_code.0 != RECORD_DICE_ROLL_TYPE_CODE {
            // Forward-compatibility: skip any non-dice record without
            // failing the load. Today there are none; tomorrow a
            // co-tenant might appear.
            continue;
        }
        let record: RecordDiceRoll = postcard::from_bytes(&wal_record.action_bytes)
            .map_err(HistoryLoadError::ActionDecode)?;
        out.push(HistoryEntry { record });
    }
    Ok(out)
}
