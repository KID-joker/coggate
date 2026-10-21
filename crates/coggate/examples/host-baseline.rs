fn main() {
    // Baseline application has no verification dependency at runtime.
    let source = std::env::args().nth(1).unwrap_or_default();
    println!("{} bytes received", source.len());
}
