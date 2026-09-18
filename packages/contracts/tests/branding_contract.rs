use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(not(windows))]
use std::{fs, time::SystemTime};

fn repository_root(manifest_dir: &Path) -> PathBuf {
    manifest_dir
        .ancestors()
        .find(|candidate| {
            candidate.join("scripts").is_dir() && candidate.join("Cargo.toml").is_file()
        })
        .expect("contracts package must be inside the repository")
        .to_path_buf()
}

fn python_program() -> (PathBuf, bool) {
    let search_path = std::env::var_os("PATH").expect("PATH must locate Python");
    #[cfg(windows)]
    let candidates = [
        ("python3.exe", false),
        ("python.exe", false),
        ("py.exe", true),
    ];
    #[cfg(not(windows))]
    let candidates = [("python3", false)];

    for directory in std::env::split_paths(&search_path) {
        for (name, is_launcher) in candidates {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return (candidate, is_launcher);
            }
        }
    }
    panic!("Python 3 executable must be available on PATH");
}

fn isolated_python_command() -> Command {
    let (program, is_launcher) = python_program();
    let mut command = Command::new(program);
    if is_launcher {
        command.arg("-3");
    }
    command.args(["-I", "-S"]);
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("PYTHON")
        {
            command.env_remove(name);
        }
    }
    command
}

#[cfg(not(windows))]
#[test]
fn scanner_self_test_passes() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let scanner = root.join("scripts").join("test-branding.py");
    assert!(scanner.is_file(), "branding scanner is missing");

    let output = isolated_python_command()
        .arg(&scanner)
        .arg("--self-test")
        .current_dir(&root)
        .output()
        .expect("python3 must be available to run the branding contract");

    assert!(
        output.status.success(),
        "branding scanner self-test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(windows)]
#[test]
fn scanner_refuses_platforms_without_safe_descriptor_support() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let scanner = root.join("scripts").join("test-branding.py");
    let output = isolated_python_command()
        .arg(&scanner)
        .args(["--paths", "scripts/test-branding.py"])
        .current_dir(&root)
        .output()
        .expect("Python 3 must launch the branding scanner");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(output.stdout.is_empty(), "stdout must be empty");
    assert_eq!(
        stderr.lines().collect::<Vec<_>>(),
        ["error: safe descriptor operations are unavailable"]
    );
    assert!(!stderr.contains("Traceback"), "stderr:\n{stderr}");
}

#[test]
fn scanner_maps_process_launch_errors_to_operational_exit() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let scanner = root.join("scripts").join("test-branding.py");
    let output = isolated_python_command()
        .arg(&scanner)
        .args(["--paths", "scripts/test-branding.py"])
        .env("PATH", "/nonexistent")
        .current_dir(&root)
        .output()
        .expect("python3 must launch the branding scanner");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr:\n{stderr}");
    assert!(!stderr.contains("Traceback"), "stderr:\n{stderr}");
}

#[cfg(not(windows))]
#[test]
fn scanner_ignores_python_startup_pollution() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let scanner = root.join("scripts").join("test-branding.py");
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock must follow the Unix epoch")
        .as_nanos();
    let pollution =
        std::env::temp_dir().join(format!("coggate-branding-{}-{unique}", std::process::id()));
    fs::create_dir(&pollution).expect("pollution fixture directory must be created");
    fs::write(
        pollution.join("sitecustomize.py"),
        "print('startup pollution')\n",
    )
    .expect("pollution fixture must be written");

    let output = isolated_python_command()
        .arg(&scanner)
        .arg("--self-test")
        .env("PYTHONPATH", &pollution)
        .current_dir(&root)
        .output()
        .expect("python3 must launch the branding scanner");
    fs::remove_dir_all(&pollution).expect("pollution fixture must be removed");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"self-test: ok\n");
}
