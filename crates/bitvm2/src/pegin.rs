use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::{Network, Script, script};

use crate::types::get_magic_bytes;

pub fn check_pegin_opreturn(network: &Network, script: &Script) -> bool {
    if !script.is_op_return() {
        return false;
    }
    // Display decoded pushes
    let instructions = script.instructions();
    for instr in instructions {
        match instr {
            Ok(script::Instruction::PushBytes(bytes)) => {
                println!("Data pushed: {}", hex::encode(bytes));
                let magic_bytes = get_magic_bytes(network);
                if !bytes.as_bytes().starts_with(&magic_bytes)
                    || bytes.len() != magic_bytes.len() + 20
                {
                    return false;
                };
                return true;
            }
            Ok(opcode) => {
                println!("Opcode: {:?}", opcode);
                if opcode != Instruction::Op(OP_RETURN) {
                    return false;
                }
            }
            Err(e) => {
                println!("Script parsing error: {:?}", e);
                return false;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{pegin::check_pegin_opreturn, types::get_magic_bytes};
    use bitcoin::Network;
    use goat::scripts::generate_opreturn_script;

    #[test]
    fn test_peg_opreturn_script() {
        let evm_address = "8943545177806ED17B9F23F0a21ee5948eCaa776";
        let evm_address = hex::decode(evm_address).unwrap();
        let network = Network::Bitcoin;
        let magic = get_magic_bytes(&network);
        let msg = [magic.clone(), evm_address.clone()].concat();
        let script = generate_opreturn_script(msg);
        assert!(check_pegin_opreturn(&network, &script));

        let fork_network = Network::Testnet;
        let misspelled_magic = get_magic_bytes(&fork_network);
        let msg_misspelled_magic = [misspelled_magic, evm_address].concat();
        let script_misspelled_magic = generate_opreturn_script(msg_misspelled_magic);
        assert!(!check_pegin_opreturn(&network, &script_misspelled_magic));

        let suspicious_evm_address = "8943545177806ED17B9F23F0a21ee5948eCaa7";
        let suspicious_evm_address = hex::decode(suspicious_evm_address).unwrap();
        let msg_invalid_evm_address = [magic, suspicious_evm_address].concat();
        let script_invalid_evm_address = generate_opreturn_script(msg_invalid_evm_address);
        assert!(!check_pegin_opreturn(&network, &script_invalid_evm_address));
    }
}
