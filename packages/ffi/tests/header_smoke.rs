#[cfg(unix)]
use std::collections::BTreeSet;
use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(unix)]
const EXPORTED_SYMBOLS: [&str; 7] = [
    "ag_abi_version",
    "ag_core_version",
    "ag_service_create",
    "ag_service_destroy",
    "ag_service_issue",
    "ag_service_verify",
    "ag_buffer_free",
];

fn target_directory(manifest: &Path, current_dir: &Path) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(path) if Path::new(&path).is_absolute() => PathBuf::from(path),
        Some(path) => current_dir.join(path),
        None => manifest.join("../..").join("target"),
    }
}

fn rustc_host() -> Option<String> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc).arg("-vV").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
}

fn target_triple(host: Option<&str>) -> Option<String> {
    env::var("TARGET")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            env::var("CARGO_BUILD_TARGET")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .or_else(|| host.map(str::to_owned))
}

fn compiler(host: Option<&str>, target: Option<&str>, msvc: bool) -> OsString {
    let mut variables = Vec::new();
    if let Some(target) = target {
        variables.push(format!("CC_{target}"));
        variables.push(format!("CC_{}", target.replace('-', "_")));
        variables.push(if Some(target) == host {
            "HOST_CC".to_owned()
        } else {
            "TARGET_CC".to_owned()
        });
    }
    variables.push("CC".to_owned());

    variables
        .into_iter()
        .find_map(|name| env::var_os(name).filter(|value| !value.is_empty()))
        .unwrap_or_else(|| if msvc { "cl".into() } else { "cc".into() })
}

#[cfg(unix)]
fn assert_undefined_exports(object: &Path) {
    let nm = env::var_os("NM").unwrap_or_else(|| "nm".into());
    let output = Command::new(&nm)
        .arg("-u")
        .arg(object)
        .output()
        .unwrap_or_else(|error| panic!("failed to run nm executable {nm:?}: {error}"));
    assert!(
        output.status.success(),
        "nm failed for {}\nstdout:\n{}\nstderr:\n{}",
        object.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let nm_stdout = String::from_utf8_lossy(&output.stdout);
    let undefined = nm_stdout
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .map(|symbol| symbol.strip_prefix('_').unwrap_or(symbol))
        .collect::<BTreeSet<_>>();
    for symbol in EXPORTED_SYMBOLS {
        assert!(
            undefined.contains(symbol),
            "C smoke object does not retain an undefined reference to {symbol}; nm output:\n{}",
            String::from_utf8_lossy(&output.stdout),
        );
    }
}

#[test]
fn public_header_compiles_as_strict_c11() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = manifest.join("tests/header_smoke.c");
    let include = manifest.join("include");
    let current_dir = env::current_dir().expect("read current directory");
    let output_dir = target_directory(&manifest, &current_dir).join("coggate-header-smoke");
    fs::create_dir_all(&output_dir).expect("create header smoke output directory");

    let msvc = cfg!(target_env = "msvc");
    let host = rustc_host();
    let target = target_triple(host.as_deref());
    let compiler = compiler(host.as_deref(), target.as_deref(), msvc);
    let object = output_dir.join(if msvc {
        "header_smoke.obj"
    } else {
        "header_smoke.o"
    });
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
            .arg(format!("/Fo{}", object.display()));
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
            .arg(&object);
    }

    let output = command.output().unwrap_or_else(|error| {
        panic!(
            "failed to run C compiler {compiler:?}: {error}; CC variables must name an executable without embedded arguments"
        );
    });
    assert!(
        output.status.success(),
        "C11 header smoke failed with {compiler:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    #[cfg(unix)]
    assert_undefined_exports(&object);
}

#[test]
fn public_header_uses_coggate_macro_namespace() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let header =
        fs::read_to_string(manifest.join("include/coggate.h")).expect("read public C header");

    for expected in ["COGGATE_API", "COGGATE_CALL", "COGGATE_STATIC"] {
        assert!(header.contains(expected), "missing public macro {expected}");
    }
    for legacy in ["AG_API", "AG_CALL"] {
        assert!(
            !header.contains(legacy),
            "legacy public macro remains: {legacy}"
        );
    }
}
