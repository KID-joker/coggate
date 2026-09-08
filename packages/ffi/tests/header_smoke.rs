use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn target_directory(manifest: &Path) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(path) if Path::new(&path).is_absolute() => PathBuf::from(path),
        Some(path) => manifest.join(path),
        None => manifest.join("../..").join("target"),
    }
}

#[test]
fn public_header_compiles_as_strict_c11() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = manifest.join("tests/header_smoke.c");
    let include = manifest.join("include");
    let output_dir = target_directory(&manifest).join("agentgate-header-smoke");
    fs::create_dir_all(&output_dir).expect("create header smoke output directory");

    let msvc = cfg!(target_env = "msvc");
    let compiler =
        env::var_os("CC").unwrap_or_else(|| if msvc { "cl".into() } else { "cc".into() });
    let mut command = Command::new(&compiler);
    if msvc {
        command
            .arg("/nologo")
            .arg("/std:c11")
            .arg("/W4")
            .arg("/WX")
            .arg("/c")
            .arg(&source)
            .arg(format!("/I{}", include.display()))
            .arg(format!(
                "/Fo{}",
                output_dir.join("header_smoke.obj").display()
            ));
    } else {
        command
            .arg("-std=c11")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg("-I")
            .arg(&include)
            .arg("-c")
            .arg(&source)
            .arg("-o")
            .arg(output_dir.join("header_smoke.o"));
    }

    let output = command.output().unwrap_or_else(|error| {
        panic!("failed to run C compiler {compiler:?}: {error}");
    });
    assert!(
        output.status.success(),
        "C11 header smoke failed with {compiler:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
