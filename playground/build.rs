use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() {
    println!("cargo:rerun-if-changed=static");
    let root = PathBuf::from("static");
    let mut files = Vec::new();
    collect_files(&root, &mut files);
    files.sort();

    let mut generated = String::from(
        "pub(crate) fn embedded_asset(path: &str) -> Option<(&'static [u8], &'static str)> {\n    match path {\n",
    );
    for file in files {
        let relative = file
            .strip_prefix(&root)
            .expect("static file must be below static root")
            .to_string_lossy()
            .replace('\\', "/");
        let absolute = fs::canonicalize(&file).expect("static asset must be readable");
        generated.push_str(&format!(
            "        {relative:?} => Some((include_bytes!({absolute:?}), {:?})),\n",
            content_type(&file),
        ));
    }
    generated.push_str("        _ => None,\n    }\n}\n");

    let destination = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("static_assets.rs");
    fs::write(destination, generated).expect("generated asset table must be writable");
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("static directory must exist") {
        let path = entry.expect("static entry must be readable").path();
        if path.is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("woff2") => "font/woff2",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        _ => "application/octet-stream",
    }
}
