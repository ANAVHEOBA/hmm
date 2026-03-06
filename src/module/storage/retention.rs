use super::archive::ArchiveStore;
use super::errors::StorageError;
use super::index::{IndexEntry, IndexStore};

pub fn enforce_max_archives(
    index_store: &IndexStore,
    archive_store: &ArchiveStore,
    max_archives: usize,
) -> Result<usize, StorageError> {
    let mut entries = index_store.read_all()?;
    if entries.len() <= max_archives {
        return Ok(0);
    }

    entries.sort_by_key(|entry| entry.created_at_epoch_secs);
    let to_remove = entries.len() - max_archives;

    let remove_ids: Vec<String> = entries
        .iter()
        .take(to_remove)
        .map(|entry| entry.id.clone())
        .collect();
    let keep: Vec<IndexEntry> = entries.into_iter().skip(to_remove).collect();

    for id in &remove_ids {
        archive_store.delete(id)?;
    }
    index_store.replace_all(&keep)?;

    Ok(to_remove)
}
