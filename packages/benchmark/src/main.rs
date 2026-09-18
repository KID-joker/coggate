#![forbid(unsafe_code)]

fn main() {
    let code = coggate_benchmark::cli::run_with_io(
        std::env::args().skip(1),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    std::process::exit(i32::from(code));
}
