use {
    solana_entry::entry::EntrySummary,
    solana_sdk::clock::Slot,
    std::sync::{Arc, RwLock},
};

pub trait EntryNotifier {
    fn notify_entry(&self, slot: Slot, index: usize, entry: &EntrySummary, last_one: bool);
}

pub type EntryNotifierLock = Arc<RwLock<dyn EntryNotifier + Sync + Send>>;
