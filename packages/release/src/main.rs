#![forbid(unsafe_code)]

fn main() {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let code = agentgate_release::cli::run_with_io(
        std::env::args().skip(1),
        &mut stdout.lock(),
        &mut stderr.lock(),
    );
    std::process::exit(i32::from(code));
}
