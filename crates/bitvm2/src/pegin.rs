use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::{Script, script};

// TODO: check magic bytes
pub fn check_pegin_opreturn(script: &Script) -> bool {
    if !script.is_op_return() {
        return false;
    }
    // Display decoded pushes
    let mut instructions = script.instructions();
    while let Some(instr) = instructions.next() {
        match instr {
            Ok(script::Instruction::PushBytes(bytes)) => {
                println!("Data pushed: {}", hex::encode(bytes));
                // TODO: use crate::types::get_magic_bytes;
                if bytes.len() != 20 {
                    return false;
                }
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
    use crate::pegin::check_pegin_opreturn;
    use goat::scripts::generate_opreturn_script;

    #[test]
    fn test_peg_opreturn_script() {
        let evm_address = "8943545177806ED17B9F23F0a21ee5948eCaa776";
        let msg = hex::decode(evm_address).unwrap();

        let script = generate_opreturn_script(msg);
        assert!(check_pegin_opreturn(&script));
    }
}
