use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn run(command: &mut Command) {
    let status = command
        .status()
        .expect("failed to start C compiler or generator");
    assert!(status.success(), "native worker build failed: {command:?}");
}

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let vendor = manifest.join("../../third_party/mquickjs");
    let native = manifest.join("native");
    let host = env::var("HOST").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let pointer_width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap();
    assert!(
        pointer_width == "32" || pointer_width == "64",
        "unsupported pointer width"
    );
    println!("cargo:rerun-if-changed={}", native.display());
    println!("cargo:rerun-if-changed={}", vendor.display());
    println!("cargo:rerun-if-env-changed=HOST_CC");

    let mut host_build = cc::Build::new();
    host_build.target(&host).host(&host).cargo_metadata(false);
    if let Some(compiler) = env::var_os("HOST_CC") {
        host_build.compiler(compiler);
    }
    let generator = out.join("coggate-stdlib-generator");
    let mut command = host_build.get_compiler().to_command();
    command
        .arg("-std=c11")
        .arg("-D_GNU_SOURCE")
        .arg("-O2")
        .arg("-I")
        .arg(&vendor)
        .arg(native.join("stdlib.c"))
        .arg(vendor.join("mquickjs_build.c"))
        .arg("-o")
        .arg(&generator);
    run(&mut command);
    for (filename, atoms) in [("coggate_stdlib.h", false), ("mquickjs_atom.h", true)] {
        let file = File::create(out.join(filename)).expect("generated header");
        let mut command = Command::new(&generator);
        command.arg(format!("-m{pointer_width}"));
        if atoms {
            command.arg("-a");
        }
        command.stdout(Stdio::from(file));
        run(&mut command);
    }
    let worker = out.join("coggate-worker");
    build_worker(&vendor, &native, &out, &worker, &target_os, false);
    println!("cargo:rustc-env=COGGATE_WORKER_PATH={}", worker.display());
    if env::var_os("CARGO_FEATURE_ENGINE_TESTS").is_some() {
        let engine_test = out.join("coggate-engine-test-UNSANDBOXED");
        build_worker(&vendor, &native, &out, &engine_test, &target_os, true);
        println!(
            "cargo:rustc-env=COGGATE_ENGINE_TEST_PATH={}",
            engine_test.display()
        );
    }
}

fn build_worker(
    vendor: &Path,
    native: &Path,
    out: &Path,
    executable: &Path,
    target_os: &str,
    engine_test: bool,
) {
    let mut build = cc::Build::new();
    build.cargo_metadata(false);
    let mut command = build.get_compiler().to_command();
    command.args([
        "-std=c11",
        "-D_GNU_SOURCE",
        "-DNDEBUG",
        "-Os",
        "-fno-math-errno",
        "-fno-trapping-math",
        "-ffunction-sections",
        "-fdata-sections",
        "-fstack-protector-strong",
    ]);
    if engine_test {
        command.arg("-DCOGGATE_ENGINE_TEST_ONLY=1");
    }
    command
        .arg("-I")
        .arg(vendor)
        .arg("-I")
        .arg(out)
        .arg(native.join("worker.c"));
    for source in ["mquickjs.c", "dtoa.c", "libm.c", "cutils.c"] {
        command.arg(vendor.join(source));
    }
    if target_os == "linux" {
        command.args(["-Wl,--gc-sections", "-Wl,-z,relro,-z,now", "-Wl,-s"]);
    } else if target_os == "macos" {
        command.args(["-Wl,-dead_strip"]);
    }
    command.arg("-lm").arg("-o").arg(executable);
    run(&mut command);
}
