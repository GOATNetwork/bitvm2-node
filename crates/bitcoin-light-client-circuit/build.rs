fn main() {
    prost_build::compile_protos(&["proto/tx.proto"], &["proto"]).unwrap();
}
