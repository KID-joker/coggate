use std::{
    collections::HashMap,
    io::Write,
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use base64::Engine;
use coggate_playground::{
    model::Language,
    runner::{
        BrokerRequest, BrokerResponse, CompileResult, MAX_FRAME_BYTES, PROTOCOL_VERSION, RunResult,
        RunStatus,
    },
    util::random_id,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::{Mutex, mpsc},
};

const OUTPUT_LIMIT: usize = 16 * 1024;

#[derive(Clone)]
struct Broker {
    artifacts: Arc<Mutex<HashMap<String, Artifact>>>,
    images: Arc<HashMap<Language, String>>,
    expected_uid: u32,
}

#[derive(Clone)]
struct Artifact {
    container: String,
    language: Language,
    image: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let socket = PathBuf::from(
        std::env::var("ARENA_RUNNER_SOCKET")
            .unwrap_or_else(|_| "/run/coggate-playground/runner.sock".into()),
    );
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }
    let images = load_images()?;
    cleanup_orphans().await;
    let expected_uid = std::env::var("ARENA_WEB_UID")?.parse()?;
    let listener = UnixListener::bind(&socket)?;
    set_socket_permissions(&socket)?;
    let broker = Broker {
        artifacts: Arc::new(Mutex::new(HashMap::new())),
        images: Arc::new(images),
        expected_uid,
    };
    tracing::info!(path=%socket.display(), "runner broker listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let broker = broker.clone();
        tokio::spawn(async move {
            if let Err(error) = broker.handle(stream).await {
                tracing::warn!(error=%error, "runner request rejected");
            }
        });
    }
}

async fn cleanup_orphans() {
    let output = Command::new("docker")
        .args(["ps", "-aq", "--filter", "label=coggate.submission"])
        .output()
        .await;
    let Ok(output) = output else {
        return;
    };
    for container in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|value| !value.is_empty())
    {
        let _ = remove_container(container).await;
    }
}

fn set_socket_permissions(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn load_images() -> Result<HashMap<Language, String>, Box<dyn std::error::Error>> {
    let entries = [
        (Language::C, "C"),
        (Language::Cpp, "CPP"),
        (Language::Rust, "RUST"),
        (Language::Go, "GO"),
        (Language::Java, "JAVA"),
        (Language::Python, "PYTHON"),
        (Language::Node, "NODE"),
    ];
    let mut images = HashMap::new();
    for (language, suffix) in entries {
        let value = std::env::var(format!("ARENA_RUNNER_IMAGE_{suffix}"))?;
        if !value.contains("@sha256:") {
            return Err(format!(
                "runner image for {} must be pinned by digest",
                language.as_str()
            )
            .into());
        }
        images.insert(language, value);
    }
    Ok(images)
}

impl Broker {
    async fn handle(&self, mut stream: UnixStream) -> Result<(), Box<dyn std::error::Error>> {
        let credential = stream
            .peer_cred()
            .map_err(|_| "peer credentials unavailable")?;
        if credential.uid() != self.expected_uid {
            return Err("peer uid rejected".into());
        }
        let length = stream.read_u32().await? as usize;
        if length > MAX_FRAME_BYTES {
            return Err("frame too large".into());
        }
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        let request: BrokerRequest = serde_json::from_slice(&payload)?;
        let response = self.dispatch(request).await;
        let payload = serde_json::to_vec(&response)?;
        stream.write_u32(payload.len() as u32).await?;
        stream.write_all(&payload).await?;
        Ok(())
    }

    async fn dispatch(&self, request: BrokerRequest) -> BrokerResponse {
        let result = match request {
            BrokerRequest::Prepare {
                version,
                submission_id,
                lease_id,
                language,
                source,
                compile_timeout_ms,
                ..
            } => {
                if version != PROTOCOL_VERSION || compile_timeout_ms > 15_000 {
                    return BrokerResponse::Error {
                        code: "invalid_request".into(),
                    };
                }
                self.prepare(
                    &submission_id,
                    &lease_id,
                    language,
                    &source,
                    compile_timeout_ms,
                )
                .await
                .map(BrokerResponse::Prepared)
            }
            BrokerRequest::Execute {
                version,
                artifact_id,
                question,
                timeout_ms,
                ..
            } => {
                if version != PROTOCOL_VERSION || timeout_ms > 5_000 {
                    return BrokerResponse::Error {
                        code: "invalid_request".into(),
                    };
                }
                self.execute(&artifact_id, &question, timeout_ms)
                    .await
                    .map(BrokerResponse::Executed)
            }
            BrokerRequest::Destroy {
                version,
                artifact_id,
                ..
            } => {
                if version != PROTOCOL_VERSION {
                    return BrokerResponse::Error {
                        code: "invalid_request".into(),
                    };
                }
                self.destroy(&artifact_id)
                    .await
                    .map(|_| BrokerResponse::Destroyed)
            }
        };
        result.unwrap_or_else(|code| BrokerResponse::Error { code })
    }

    async fn prepare(
        &self,
        submission_id: &str,
        lease_id: &str,
        language: Language,
        source: &str,
        timeout_ms: u64,
    ) -> Result<CompileResult, String> {
        if source.len() > 32 * 1024 {
            return Err("source_too_large".into());
        }
        let image = self
            .images
            .get(&language)
            .ok_or("language_not_configured")?
            .clone();
        let artifact_id = random_id("artifact").map_err(|_| "random_failed")?;
        let container = format!("coggate-{}", artifact_id.replace('_', "-"));
        let start = Instant::now();
        let created = Command::new("docker")
            .args([
                "create",
                "--name",
                &container,
                "--runtime=runsc",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=64",
                "--memory=384m",
                "--cpus=0.75",
                "--user=65532:65532",
                "--env=HOME=/work",
                "--env=GOCACHE=/work/.cache/go-build",
                "--env=GOPATH=/work/go",
                "--env=GOPROXY=off",
                "--env=GOSUMDB=off",
                "--workdir=/work",
                "--tmpfs=/work:rw,exec,nosuid,nodev,size=64m",
                "--label",
                &format!("coggate.submission={submission_id}"),
                "--label",
                &format!("coggate.lease={lease_id}"),
                &image,
                "sleep",
                "120",
            ])
            .output()
            .await
            .map_err(|_| "docker_unavailable")?;
        if !created.status.success() {
            return Err("container_create_failed".into());
        }
        let started = Command::new("docker")
            .args(["start", &container])
            .output()
            .await
            .map_err(|_| "docker_unavailable")?;
        if !started.status.success() {
            let _ = remove_container(&container).await;
            return Err("container_start_failed".into());
        }

        let mut source_file = tempfile::NamedTempFile::new().map_err(|_| "tempfile_failed")?;
        source_file
            .write_all(source.as_bytes())
            .map_err(|_| "tempfile_failed")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            source_file
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o644))
                .map_err(|_| "tempfile_failed")?;
        }
        let filename = source_filename(language);
        let copied = Command::new("docker")
            .arg("cp")
            .arg(source_file.path())
            .arg(format!("{container}:/work/{filename}"))
            .output()
            .await
            .map_err(|_| "docker_unavailable")?;
        if !copied.status.success() {
            let _ = remove_container(&container).await;
            return Err("source_copy_failed".into());
        }

        let args = compile_command(language);
        let output = run_bounded(
            Command::new("docker")
                .arg("exec")
                .arg(&container)
                .args(args),
            None,
            timeout_ms,
            OUTPUT_LIMIT,
        )
        .await;
        let (status, stdout, stderr, stdout_truncated, stderr_truncated, timed_out) = match output {
            Ok(value) => value,
            Err(code) => {
                let _ = remove_container(&container).await;
                return Err(code);
            }
        };
        let truncated = stdout_truncated || stderr_truncated;
        let success = status == Some(0) && !timed_out && !truncated;
        let diagnostic = String::from_utf8_lossy(&[stdout, stderr].concat()).into_owned();
        if success {
            self.artifacts.lock().await.insert(
                artifact_id.clone(),
                Artifact {
                    container,
                    language,
                    image: image.clone(),
                },
            );
        } else {
            let _ = remove_container(&container).await;
        }
        Ok(CompileResult {
            success,
            artifact_id: success.then_some(artifact_id),
            duration_ms: start.elapsed().as_millis() as i64,
            output: diagnostic,
            output_truncated: truncated,
            image_digest: image,
        })
    }

    async fn execute(
        &self,
        artifact_id: &str,
        question: &str,
        timeout_ms: u64,
    ) -> Result<RunResult, String> {
        let artifact = self
            .artifacts
            .lock()
            .await
            .get(artifact_id)
            .cloned()
            .ok_or("artifact_not_found")?;
        let start = Instant::now();
        let command = run_command(artifact.language);
        let output = run_bounded(
            Command::new("docker")
                .arg("exec")
                .arg("-i")
                .arg(&artifact.container)
                .args(command),
            Some(format!("{question}\n").into_bytes()),
            timeout_ms,
            OUTPUT_LIMIT,
        )
        .await;
        let (exit_code, stdout, stderr, stdout_truncated, stderr_truncated, timed_out) = output?;
        let stdout_valid = String::from_utf8(stdout.clone());
        let (stdout, output_encoding) = match stdout_valid {
            Ok(value) => (value, "utf8".to_owned()),
            Err(_) => (
                base64::engine::general_purpose::STANDARD.encode(stdout),
                "base64".to_owned(),
            ),
        };
        let status = if timed_out {
            RunStatus::TimedOut
        } else if stdout_truncated || stderr_truncated {
            RunStatus::OutputLimitExceeded
        } else {
            RunStatus::Exited
        };
        Ok(RunResult {
            status,
            duration_ms: start.elapsed().as_millis() as i64,
            exit_code,
            stdout,
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            output_encoding,
            stdout_truncated,
            stderr_truncated,
        })
    }

    async fn destroy(&self, artifact_id: &str) -> Result<(), String> {
        if let Some(artifact) = self.artifacts.lock().await.remove(artifact_id) {
            let _ = &artifact.image;
            remove_container(&artifact.container).await?;
        }
        Ok(())
    }
}

fn source_filename(language: Language) -> &'static str {
    match language {
        Language::C => "main.c",
        Language::Cpp => "main.cpp",
        Language::Rust => "main.rs",
        Language::Go => "main.go",
        Language::Java => "Main.java",
        Language::Python => "main.py",
        Language::Node => "main.js",
    }
}

fn compile_command(language: Language) -> &'static [&'static str] {
    match language {
        Language::C => &[
            "cc",
            "-std=c11",
            "-O2",
            "-o",
            "/work/solver",
            "/work/main.c",
        ],
        Language::Cpp => &[
            "c++",
            "-std=c++20",
            "-O2",
            "-o",
            "/work/solver",
            "/work/main.cpp",
        ],
        Language::Rust => &["rustc", "-O", "-o", "/work/solver", "/work/main.rs"],
        Language::Go => &["go", "build", "-o", "/work/solver", "/work/main.go"],
        Language::Java => &["javac", "-d", "/work", "/work/Main.java"],
        Language::Python => &["python3", "-I", "-m", "py_compile", "/work/main.py"],
        Language::Node => &["node", "--check", "/work/main.js"],
    }
}

fn run_command(language: Language) -> &'static [&'static str] {
    match language {
        Language::C | Language::Cpp | Language::Rust | Language::Go => &["/work/solver"],
        Language::Java => &["java", "-Xms16m", "-Xmx128m", "-cp", "/work", "Main"],
        Language::Python => &["python3", "-I", "/work/main.py"],
        Language::Node => &["node", "--no-addons", "/work/main.js"],
    }
}

async fn remove_container(container: &str) -> Result<(), String> {
    Command::new("docker")
        .args(["rm", "-f", container])
        .output()
        .await
        .map(|_| ())
        .map_err(|_| "container_cleanup_failed".into())
}

async fn read_limited(
    mut reader: impl AsyncRead + Unpin,
    limit: usize,
    total: Arc<AtomicUsize>,
    exceeded: mpsc::UnboundedSender<()>,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut stored = Vec::with_capacity(limit.min(4096));
    let mut buffer = [0_u8; 4096];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let before = total.fetch_add(read, Ordering::Relaxed);
        let remaining = limit.saturating_sub(before);
        stored.extend_from_slice(&buffer[..read.min(remaining)]);
        if read > remaining && !truncated {
            truncated = true;
            let _ = exceeded.send(());
        }
    }
    Ok((stored, truncated))
}

async fn run_bounded(
    command: &mut Command,
    input: Option<Vec<u8>>,
    timeout_ms: u64,
    limit: usize,
) -> Result<(Option<i32>, Vec<u8>, Vec<u8>, bool, bool, bool), String> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| "process_spawn_failed")?;
    if let (Some(mut stdin), Some(input)) = (child.stdin.take(), input) {
        tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
        });
    }
    let stdout = child.stdout.take().ok_or("pipe_failed")?;
    let stderr = child.stderr.take().ok_or("pipe_failed")?;
    let (exceeded_tx, mut exceeded_rx) = mpsc::unbounded_channel();
    let total = Arc::new(AtomicUsize::new(0));
    let stdout_task = tokio::spawn(read_limited(
        stdout,
        limit,
        total.clone(),
        exceeded_tx.clone(),
    ));
    let stderr_task = tokio::spawn(read_limited(stderr, limit, total, exceeded_tx));
    enum Completion {
        Exited(std::io::Result<std::process::ExitStatus>),
        TimedOut,
        OutputLimit,
    }
    let completion = tokio::select! {
        status = child.wait() => Completion::Exited(status),
        _ = tokio::time::sleep(std::time::Duration::from_millis(timeout_ms)) => Completion::TimedOut,
        _ = exceeded_rx.recv() => Completion::OutputLimit,
    };
    let (exit_code, timed_out) = match completion {
        Completion::Exited(Ok(status)) => (status.code(), false),
        Completion::Exited(Err(_)) => return Err("process_wait_failed".into()),
        Completion::TimedOut => {
            let _ = child.kill().await;
            (None, true)
        }
        Completion::OutputLimit => {
            let _ = child.kill().await;
            (None, false)
        }
    };
    let (stdout, stdout_truncated) = stdout_task
        .await
        .map_err(|_| "pipe_failed")?
        .map_err(|_| "pipe_failed")?;
    let (stderr, stderr_truncated) = stderr_task
        .await
        .map_err(|_| "pipe_failed")?
        .map_err(|_| "pipe_failed")?;
    Ok((
        exit_code,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        timed_out,
    ))
}
