use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(not(windows))]
use std::{
    io::Write,
    process::{Output, Stdio},
    time::SystemTime,
};

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
fn run_scanner_with_nul_paths(root: &Path, paths: &[u8]) -> Output {
    let scanner = root.join("scripts").join("test-branding.py");
    let mut child = isolated_python_command()
        .arg(scanner)
        .arg("--paths-from-stdin")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Python 3 must launch the branding scanner");
    child
        .stdin
        .take()
        .expect("scanner stdin must be piped")
        .write_all(paths)
        .expect("scanner path list must be writable");
    child.wait_with_output().expect("scanner must terminate")
}

#[cfg(not(windows))]
fn tracked_non_docs(root: &Path) -> Vec<u8> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .expect("git must enumerate tracked files");
    assert!(output.status.success(), "git ls-files failed");

    let mut filtered = Vec::with_capacity(output.stdout.len());
    for path in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let first_component = path
            .split(|byte| *byte == b'/')
            .next()
            .expect("tracked path must have a first component");
        if first_component == b"docs" {
            continue;
        }
        filtered.extend_from_slice(path);
        filtered.push(0);
    }
    filtered
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

#[cfg(not(windows))]
#[test]
fn all_tracked_non_docs_paths_and_contents_are_brand_clean() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let paths = tracked_non_docs(&root);
    assert!(
        !paths.is_empty(),
        "tracked non-docs path list must not be empty"
    );
    let output = run_scanner_with_nul_paths(&root, &paths);
    assert!(
        output.status.success(),
        "real repository branding scan failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[cfg(not(windows))]
#[test]
fn scanner_rejects_contiguous_and_separated_content_path_and_binary_mutations() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let fixture = tempfile::tempdir_in(&root).expect("fixture must be inside repository");
    let retired = ["AgEnT", "GaTe"].concat();
    let mut mutations = vec![
        (
            fixture.path().join("mixed-case.txt"),
            format!("prefix {retired} suffix").into_bytes(),
        ),
        (
            fixture.path().join(format!("{retired}.txt")),
            b"safe content\n".to_vec(),
        ),
        (
            fixture.path().join("ordinary-binary.bin"),
            [vec![0x80, 0x81, 0x82], retired.as_bytes().to_vec()].concat(),
        ),
    ];
    for (index, separator) in [" ", "-", "_", ".", "/"].into_iter().enumerate() {
        let separated = ["AgEnT", separator, "GaTe"].concat();
        mutations.push((
            fixture
                .path()
                .join(format!("separated-content-{index}.txt")),
            format!("prefix {separated} suffix").into_bytes(),
        ));
        mutations.push((
            fixture
                .path()
                .join(format!("separated-path-{index}"))
                .join(&separated),
            b"safe content\n".to_vec(),
        ));
        mutations.push((
            fixture.path().join(format!("separated-binary-{index}.bin")),
            [vec![0x80, 0x81, 0x82], separated.into_bytes()].concat(),
        ));
    }

    for (path, bytes) in mutations {
        fs::create_dir_all(path.parent().expect("mutation fixture parent"))
            .expect("mutation fixture parent must be writable");
        fs::write(&path, bytes).expect("mutation fixture must be writable");
        let mut encoded = path.as_os_str().as_encoded_bytes().to_vec();
        encoded.push(0);
        let output = run_scanner_with_nul_paths(&root, &encoded);
        assert_eq!(
            output.status.code(),
            Some(1),
            "scanner accepted mutation at {}\nstdout:\n{}\nstderr:\n{}",
            path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
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

#[test]
fn repository_metadata_and_readme_use_canonical_coggate_urls() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let repository = "https://github.com/KID-joker/coggate";
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    assert!(readme.starts_with("# CogGate\n"));
    assert!(readme.contains(&format!("[repository]: {repository}")));
    assert!(readme.contains(&format!("git clone {repository}.git")));

    let cargo = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(cargo.contains(&format!("repository = \"{repository}\"")));
    for manifest in [
        "packages/benchmark/Cargo.toml",
        "packages/contracts/Cargo.toml",
        "packages/core/Cargo.toml",
        "packages/ffi/Cargo.toml",
        "packages/release/Cargo.toml",
    ] {
        let source = fs::read_to_string(root.join(manifest)).unwrap();
        assert!(source.contains("repository.workspace = true"), "{manifest}");
    }

    let node = fs::read_to_string(root.join("bindings/node/package.json")).unwrap();
    assert!(node.contains(&format!("\"url\": \"{repository}.git\"")));
    let python = fs::read_to_string(root.join("bindings/python/pyproject.toml")).unwrap();
    assert!(python.contains(&format!("Repository = \"{repository}\"")));
    let java = fs::read_to_string(root.join("bindings/java/pom.xml")).unwrap();
    assert!(java.contains(&format!("<url>{repository}</url>")));
}
