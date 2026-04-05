use std::path::Path;

use lago_journal::RedbJournal;

/// Open a `RedbJournal` from the given data directory.
///
/// The redb database file is expected at `{data_dir}/journal.redb`.
/// The data directory and database file are created if they do not exist.
pub fn open_journal(data_dir: &Path) -> Result<RedbJournal, lago_core::LagoError> {
    std::fs::create_dir_all(data_dir).map_err(lago_core::LagoError::Io)?;
    let db_path = data_dir.join("journal.redb");
    RedbJournal::open(db_path)
}
