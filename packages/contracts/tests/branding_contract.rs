use std::fs;
use std::io::Read;
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

#[derive(Debug, Eq, PartialEq)]
struct MavenLicense {
    name: String,
    url: String,
    distribution: String,
}

fn unique_xml_child<'a, 'input>(
    parent: roxmltree::Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    let mut matches = parent.children().filter(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(namespace)
            && child.tag_name().name() == name
    });
    let child = matches.next()?;
    matches.next().is_none().then_some(child)
}

fn java_license(source: &str) -> Result<Option<MavenLicense>, roxmltree::Error> {
    const MAVEN_NAMESPACE: &str = "http://maven.apache.org/POM/4.0.0";
    let document = roxmltree::Document::parse(source)?;
    let project = document.root_element();
    if project.tag_name().namespace() != Some(MAVEN_NAMESPACE)
        || project.tag_name().name() != "project"
    {
        return Ok(None);
    }

    let Some(licenses) = unique_xml_child(project, MAVEN_NAMESPACE, "licenses") else {
        return Ok(None);
    };
    let Some(license) = unique_xml_child(licenses, MAVEN_NAMESPACE, "license") else {
        return Ok(None);
    };
    let field = |name| {
        unique_xml_child(license, MAVEN_NAMESPACE, name)
            .and_then(|element| element.text())
            .map(str::trim)
            .map(str::to_owned)
    };
    Ok(Some(MavenLicense {
        name: field("name").unwrap_or_default(),
        url: field("url").unwrap_or_default(),
        distribution: field("distribution").unwrap_or_default(),
    }))
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("must create {}: {error}", destination.display()));
    for entry in fs::read_dir(source)
        .unwrap_or_else(|error| panic!("must read {}: {error}", source.display()))
    {
        let entry = entry.expect("directory entry must be readable");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("entry type must be readable");
        if file_type.is_dir() {
            copy_directory(&source_path, &destination_path);
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "must copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        } else {
            panic!("unsupported Java source entry: {}", source_path.display());
        }
    }
}

fn zip_entry(archive: &mut zip::ZipArchive<fs::File>, path: &str) -> Vec<u8> {
    let mut entry = archive
        .by_name(path)
        .unwrap_or_else(|error| panic!("JAR must contain {path}: {error}"));
    let mut contents = Vec::new();
    entry
        .read_to_end(&mut contents)
        .unwrap_or_else(|error| panic!("JAR entry {path} must be readable: {error}"));
    contents
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

#[test]
fn publishing_metadata_uses_the_root_mit_license() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let license = fs::read_to_string(root.join("LICENSE")).expect("LICENSE must be readable");
    assert!(
        license.starts_with("MIT License\n"),
        "LICENSE must start with the MIT License heading"
    );
    for required_notice_text in [
        "Copyright (c) 2026 Sergio",
        "Permission is hereby granted, free of charge, to any person obtaining a copy",
        "The above copyright notice and this permission notice shall be included in all",
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND",
    ] {
        assert!(
            license.contains(required_notice_text),
            "LICENSE is missing required MIT notice text: {required_notice_text}"
        );
    }

    let cargo_output = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .expect("cargo metadata must launch");
    assert!(
        cargo_output.status.success(),
        "cargo metadata failed for Cargo.toml: {}",
        String::from_utf8_lossy(&cargo_output.stderr)
    );
    let cargo: serde_json::Value =
        serde_json::from_slice(&cargo_output.stdout).expect("cargo metadata must return JSON");
    let workspace_members = cargo["workspace_members"]
        .as_array()
        .expect("cargo metadata must list workspace members");
    let packages = cargo["packages"]
        .as_array()
        .expect("cargo metadata must list packages");
    assert_eq!(
        workspace_members.len(),
        5,
        "Cargo.toml workspace member count"
    );
    for member in workspace_members {
        let package = packages
            .iter()
            .find(|package| package["id"] == *member)
            .expect("each Cargo workspace member must have package metadata");
        assert_eq!(
            package["license"].as_str(),
            Some("MIT"),
            "{} must inherit the Cargo.toml workspace MIT license",
            package["manifest_path"]
                .as_str()
                .unwrap_or("Cargo manifest")
        );
    }

    let python = fs::read_to_string(root.join("bindings/python/pyproject.toml"))
        .expect("bindings/python/pyproject.toml must be readable");
    let python: toml::Value =
        toml::from_str(&python).expect("bindings/python/pyproject.toml must be valid TOML");
    assert_eq!(
        python["project"]["license"].as_str(),
        Some("MIT"),
        "bindings/python/pyproject.toml [project].license must be MIT"
    );

    let node: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("bindings/node/package.json"))
            .expect("bindings/node/package.json must be readable"),
    )
    .expect("bindings/node/package.json must be valid JSON");
    assert_eq!(
        node.get("license").and_then(serde_json::Value::as_str),
        Some("MIT"),
        "bindings/node/package.json top-level license must be MIT"
    );

    let node_lock: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("bindings/node/package-lock.json"))
            .expect("bindings/node/package-lock.json must be readable"),
    )
    .expect("bindings/node/package-lock.json must be valid JSON");
    assert_eq!(
        node_lock
            .pointer("/packages/")
            .and_then(|package| package.get("license"))
            .and_then(serde_json::Value::as_str),
        Some("MIT"),
        "bindings/node/package-lock.json packages[\"\"].license must be MIT"
    );

    let java = fs::read_to_string(root.join("bindings/java/pom.xml"))
        .expect("bindings/java/pom.xml must be readable");
    assert_eq!(
        java_license(&java).expect("bindings/java/pom.xml must be valid XML"),
        Some(MavenLicense {
            name: "MIT License".to_owned(),
            url: "https://opensource.org/license/mit".to_owned(),
            distribution: "repo".to_owned(),
        }),
        "bindings/java/pom.xml must declare the standard MIT license name, URL, and distribution"
    );
}

#[test]
fn python_packaging_requires_pep639_license_configuration() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let python = fs::read_to_string(root.join("bindings/python/pyproject.toml"))
        .expect("bindings/python/pyproject.toml must be readable");
    let python: toml::Value =
        toml::from_str(&python).expect("bindings/python/pyproject.toml must be valid TOML");

    let build_requirements = python["build-system"]["requires"]
        .as_array()
        .expect("bindings/python/pyproject.toml build-system.requires must be an array");
    assert!(
        build_requirements
            .iter()
            .any(|requirement| requirement.as_str() == Some("setuptools>=77")),
        "bindings/python/pyproject.toml must require setuptools>=77 for PEP 639"
    );
    assert_eq!(
        python["project"]["license-files"]
            .as_array()
            .map(|files| files.as_slice()),
        Some([toml::Value::String("LICENSE".to_owned())].as_slice()),
        "bindings/python/pyproject.toml must include LICENSE via PEP 639 license-files"
    );
}

#[test]
fn distribution_license_copies_match_the_complete_root_notice() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let expected = fs::read(root.join("LICENSE")).expect("LICENSE must be readable");

    for distribution_license in [
        "packages/benchmark/LICENSE",
        "packages/contracts/LICENSE",
        "packages/core/LICENSE",
        "packages/ffi/LICENSE",
        "packages/release/LICENSE",
        "bindings/python/LICENSE",
        "bindings/node/LICENSE",
        "bindings/java/src/main/resources/META-INF/licenses/CogGate-LICENSE",
    ] {
        let actual = fs::read(root.join(distribution_license))
            .unwrap_or_else(|error| panic!("{distribution_license} must be readable: {error}"));
        assert_eq!(
            actual, expected,
            "{distribution_license} must exactly match the root LICENSE"
        );
    }
}

#[test]
fn java_shaded_jar_preserves_project_and_dependency_license_notices() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let java_source = root.join("bindings/java");
    let fixture = tempfile::tempdir().expect("Java package fixture must be created");
    let java_fixture = fixture.path().join("java");
    fs::create_dir(&java_fixture).expect("Java fixture root must be created");
    fs::copy(java_source.join("pom.xml"), java_fixture.join("pom.xml"))
        .expect("Java pom.xml must be copied");
    copy_directory(&java_source.join("src"), &java_fixture.join("src"));

    let maven = if cfg!(windows) { "mvn.cmd" } else { "mvn" };
    let mut command = Command::new(maven);
    command
        .args(["-DskipTests", "package"])
        .current_dir(&java_fixture);
    if let Some(repository) = std::env::var_os("COGGATE_MAVEN_REPO_LOCAL") {
        command.arg(format!(
            "-Dmaven.repo.local={}",
            PathBuf::from(repository).display()
        ));
    }
    let output = command.output().expect("Maven must launch");
    let build_log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "Maven package failed:\n{build_log}"
    );
    assert!(
        !(build_log.contains("overlapping resource") && build_log.contains("META-INF/LICENSE")),
        "Maven shade reported a LICENSE overlap:\n{build_log}"
    );

    let jar_path = java_fixture
        .join("target")
        .join("coggate-java-0.1.0-SNAPSHOT.jar");
    let jar = fs::File::open(&jar_path)
        .unwrap_or_else(|error| panic!("must open {}: {error}", jar_path.display()));
    let mut archive = zip::ZipArchive::new(jar).expect("shaded JAR must be valid ZIP");
    assert_eq!(
        zip_entry(&mut archive, "META-INF/licenses/CogGate-LICENSE"),
        fs::read(root.join("LICENSE")).expect("root LICENSE must be readable"),
        "shaded JAR must preserve the complete CogGate MIT license"
    );

    let jackson_license = String::from_utf8(zip_entry(&mut archive, "META-INF/LICENSE"))
        .expect("Jackson LICENSE must be UTF-8");
    for required_text in [
        "Apache License",
        "Version 2.0, January 2004",
        "http://www.apache.org/licenses/",
        "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
    ] {
        assert!(
            jackson_license.contains(required_text),
            "Jackson LICENSE is missing: {required_text}"
        );
    }
    let jackson_notice = String::from_utf8(zip_entry(&mut archive, "META-INF/NOTICE"))
        .expect("Jackson NOTICE must be UTF-8");
    assert!(
        jackson_notice.contains("Jackson JSON processor")
            && jackson_notice.contains("Apache License 2.0"),
        "shaded JAR must preserve the Jackson NOTICE"
    );
}

#[test]
fn rust_packages_build_archives_with_the_complete_license_notice() {
    let root = repository_root(Path::new(env!("CARGO_MANIFEST_DIR")));
    let expected_license = fs::read(root.join("LICENSE")).expect("LICENSE must be readable");
    let package_output = tempfile::tempdir().expect("package output directory must be created");
    let target_dir = package_output.path().join("target");
    for package in [
        "coggate-benchmark",
        "coggate-contracts",
        "coggate-core",
        "coggate-ffi",
        "coggate-release",
    ] {
        let output = Command::new("cargo")
            .args([
                "package",
                "--locked",
                "--allow-dirty",
                "--offline",
                "--no-verify",
                "--target-dir",
            ])
            .arg(&target_dir)
            .args([
                "--config",
                "patch.crates-io.coggate-contracts.path=\"packages/contracts\"",
                "--config",
                "patch.crates-io.coggate-core.path=\"packages/core\"",
                "-p",
                package,
            ])
            .current_dir(&root)
            .output()
            .unwrap_or_else(|error| panic!("cargo package must launch for {package}: {error}"));
        assert!(
            output.status.success(),
            "cargo package failed for {package}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let archive_path = target_dir
            .join("package")
            .join(format!("{package}-0.1.0.crate"));
        let archive_file = fs::File::open(&archive_path)
            .unwrap_or_else(|error| panic!("must open {}: {error}", archive_path.display()));
        let decoder = flate2::read::GzDecoder::new(archive_file);
        let mut archive = tar::Archive::new(decoder);
        let expected_path = format!("{package}-0.1.0/LICENSE");
        let mut packaged_license = None;
        for entry in archive.entries().expect("crate entries must be readable") {
            let mut entry = entry.expect("crate entry must be readable");
            if entry.path().expect("crate path must be readable") == Path::new(&expected_path) {
                let mut contents = Vec::new();
                entry
                    .read_to_end(&mut contents)
                    .expect("packaged LICENSE must be readable");
                packaged_license = Some(contents);
                break;
            }
        }
        assert_eq!(
            packaged_license.as_deref(),
            Some(expected_license.as_slice()),
            "{archive_path:?} must contain a byte-exact LICENSE"
        );
    }
}

#[test]
fn metadata_parsers_reject_invalid_toml_and_commented_license() {
    let commented: toml::Value = toml::from_str("[project]\n# license = \"MIT\"\n")
        .expect("comment-only fixture must be valid TOML");
    assert_eq!(
        commented["project"].get("license"),
        None,
        "a commented license must not be metadata"
    );
    assert!(
        toml::from_str::<toml::Value>(
            "[project]\nlicense = \"MIT\"\n[project]\nname = \"invalid duplicate table\"\n"
        )
        .is_err(),
        "invalid TOML must not be accepted"
    );
}

#[test]
fn java_license_parser_rejects_wrongly_nested_license_metadata() {
    let wrongly_nested = r#"
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <profiles><profile><licenses><license>
            <name>MIT License</name>
            <url>https://opensource.org/license/mit</url>
            <distribution>repo</distribution>
          </license></licenses></profile></profiles>
        </project>
    "#;
    assert_eq!(
        java_license(wrongly_nested).expect("wrongly nested fixture must be valid XML"),
        None,
        "only /project/licenses/license is valid Maven license metadata"
    );

    let duplicate = r#"
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <licenses>
            <license><name>MIT License</name></license>
            <license><name>MIT License</name></license>
          </licenses>
        </project>
    "#;
    assert_eq!(
        java_license(duplicate).expect("duplicate fixture must be valid XML"),
        None,
        "Maven license metadata must contain exactly one direct license"
    );
}
