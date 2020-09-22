//! This account contains the serialized transaction instructions
//!

use crate::instruction::Instruction;
use crate::sanitize::SanitizeError;
use crate::sysvar::Sysvar;

pub type Instructions = Vec<Instruction>;

crate::declare_sysvar_id!("instructions1111111111111111111111111111111", Instructions);

impl Sysvar for Instructions {}

#[cfg(not(feature = "program"))]
use crate::clock::Epoch;
#[cfg(not(feature = "program"))]
use crate::genesis_config::ClusterType;

#[cfg(not(feature = "program"))]
pub fn is_enabled(_epoch: Epoch, cluster_type: ClusterType) -> bool {
    cluster_type == ClusterType::Development
}

pub fn get_current_instruction(data: &[u8]) -> u16 {
    let mut instr_fixed_data = [0u8; 2];
    let len = data.len();
    instr_fixed_data.copy_from_slice(&data[len - 2..len]);
    u16::from_le_bytes(instr_fixed_data)
}

pub fn store_current_instruction(data: &mut [u8], instruction_index: u16) {
    let last_index = data.len() - 2;
    data[last_index..last_index + 2].copy_from_slice(&instruction_index.to_le_bytes());
}

pub fn get_instruction(index: usize, data: &[u8]) -> Result<Instruction, SanitizeError> {
    solana_sdk::message::Message::deserialize_instruction(index, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_store_instruction() {
        let mut data = [4u8; 10];
        store_current_instruction(&mut data, 3);
        assert_eq!(get_current_instruction(&data), 3);
        assert_eq!([4u8; 8], data[0..8]);
    }
}
