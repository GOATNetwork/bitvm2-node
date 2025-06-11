use zkm_build::build_program;

fn main() {
    build_program("../guest-aggregation");
    build_program("../guest-groth16");
}
