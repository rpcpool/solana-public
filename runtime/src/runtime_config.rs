use std::sync::Arc;

use solana_program_runtime::compute_budget::ComputeBudget;

use crate::program_inclusions::ProgramDatumInclusions;

/// Encapsulates flags that can be used to tweak the runtime behavior.
#[derive(AbiExample, Debug, Default, Clone)]
pub struct RuntimeConfig {
    pub compute_budget: Option<ComputeBudget>,
    pub log_messages_bytes_limit: Option<usize>,
    pub transaction_account_lock_limit: Option<usize>,
    pub program_datum_inclusions: Arc<ProgramDatumInclusions>,
}
