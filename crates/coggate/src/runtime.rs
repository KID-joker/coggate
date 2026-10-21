//! Bounded subprocess execution. The production path only runs on Linux.
use coggate_core::PrivateChallenge;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_SOURCE: usize = 65_536;
const MAX_INPUT: usize = 4096;
const MAX_CASES: usize = 32;
const MAX_OUTPUT: usize = 65_536;
const MAX_RESPONSE: usize = 8 + MAX_CASES * (5 + MAX_OUTPUT);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Passed,
    WrongAnswer,
    InvalidSubmission,
    ResourceLimit,
    /// Worker started but crashed, broke its protocol, or failed isolation.
    /// The attempt is spent; only failures before execution are refunded.
    WorkerFailure,
    InternalError,
    Unsupported,
    Busy,
}

pub struct Runtime {
    worker: PathBuf,
    active: Arc<AtomicUsize>,
    max_parallel: usize,
}

pub(crate) struct Permit(Arc<AtomicUsize>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Runtime {
    /// The file is part of the trusted application installation. Package it
    /// alongside the application; the build-directory path is not deployable.
    pub fn new(worker: impl AsRef<Path>, max_parallel: usize) -> Self {
        Self {
            worker: worker.as_ref().to_owned(),
            active: Arc::new(AtomicUsize::new(0)),
            max_parallel,
        }
    }

    pub(crate) fn reserve(&self) -> Option<Permit> {
        let mut active = self.active.load(Ordering::Acquire);
        while active < self.max_parallel {
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Permit(Arc::clone(&self.active))),
                Err(current) => active = current,
            }
        }
        None
    }

    pub fn execute(&self, challenge: &PrivateChallenge, source: &str) -> Verdict {
        let Some(permit) = self.reserve() else {
            return Verdict::Busy;
        };
        self.execute_reserved(challenge, source, permit)
    }

    pub(crate) fn execute_reserved(
        &self,
        challenge: &PrivateChallenge,
        source: &str,
        _permit: Permit,
    ) -> Verdict {
        if !cfg!(target_os = "linux") {
            return Verdict::Unsupported;
        }
        if source.len() > MAX_SOURCE || source.is_empty() || source.as_bytes().contains(&0) {
            return Verdict::InvalidSubmission;
        }
        let Some(request) = encode_request(challenge, source) else {
            return Verdict::InternalError;
        };
        let start = Instant::now();
        let Ok(mut child) = Command::new(&self.worker)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return Verdict::InternalError;
        };
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let writer = std::thread::Builder::new()
            .name("coggate-input".into())
            .spawn(move || {
                let mut stdin = stdin;
                stdin.write_all(&request)
            });
        let Ok(writer) = writer else {
            let _ = child.kill();
            let _ = child.wait();
            return Verdict::WorkerFailure;
        };
        let reader = std::thread::Builder::new()
            .name("coggate-output".into())
            .spawn(move || {
                let mut bytes = Vec::new();
                let result = stdout
                    .take((MAX_RESPONSE + 1) as u64)
                    .read_to_end(&mut bytes);
                (result, bytes)
            });
        let Ok(reader) = reader else {
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            return Verdict::WorkerFailure;
        };
        let (status, timeout) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (Some(status), false),
                Ok(None) if start.elapsed() < Duration::from_millis(500) => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (None, true);
                }
            }
        };
        let written = writer.join().ok().and_then(Result::ok).is_some();
        let output = reader.join().ok();
        if timeout {
            return Verdict::ResourceLimit;
        }
        let Some((Ok(_), bytes)) = output else {
            return Verdict::WorkerFailure;
        };
        if bytes.len() > MAX_RESPONSE {
            return Verdict::ResourceLimit;
        }
        // Seccomp violations, native crashes and broken IPC cannot pass.
        if !status.is_some_and(|s| s.success()) {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                // Linux signal numbers. Production execution is Linux-only.
                if status
                    .and_then(|s| s.signal())
                    .is_some_and(|s| matches!(s, 9 | 14 | 24 | 27))
                {
                    return Verdict::ResourceLimit;
                }
            }
            return Verdict::WorkerFailure;
        }
        if !written {
            return Verdict::WorkerFailure;
        }
        decode_response(challenge, &bytes)
    }
}

fn push_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_be_bytes());
}

fn encode_request(challenge: &PrivateChallenge, source: &str) -> Option<Vec<u8>> {
    let cases = challenge.cases();
    if cases.is_empty() || cases.len() > MAX_CASES {
        return None;
    }
    let mut out = b"CGW1".to_vec();
    push_u32(&mut out, source.len());
    out.extend_from_slice(source.as_bytes());
    push_u32(&mut out, cases.len());
    for case in cases {
        let json = serde_json::to_vec(case.input()).ok()?;
        if json.len() > MAX_INPUT {
            return None;
        }
        push_u32(&mut out, json.len());
        out.extend_from_slice(&json);
    }
    Some(out)
}

fn read_u32(bytes: &mut &[u8]) -> Option<usize> {
    let value = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    *bytes = &bytes[4..];
    Some(value)
}

fn decode_response(challenge: &PrivateChallenge, mut bytes: &[u8]) -> Verdict {
    if !bytes.starts_with(b"CGR1") {
        return Verdict::WorkerFailure;
    }
    bytes = &bytes[4..];
    let Some(count) = read_u32(&mut bytes) else {
        return Verdict::WorkerFailure;
    };
    if count == 0 || count > MAX_CASES {
        return Verdict::WorkerFailure;
    }
    let mut verdict = Verdict::Passed;
    for i in 0..count {
        let Some((&status, rest)) = bytes.split_first() else {
            return Verdict::WorkerFailure;
        };
        bytes = rest;
        let Some(len) = read_u32(&mut bytes) else {
            return Verdict::WorkerFailure;
        };
        if len > MAX_OUTPUT {
            return Verdict::ResourceLimit;
        }
        let Some(payload) = bytes.get(..len) else {
            return Verdict::WorkerFailure;
        };
        bytes = &bytes[len..];
        match status {
            0 => {
                let Some(case) = challenge.cases().get(i) else {
                    return Verdict::WorkerFailure;
                };
                let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) else {
                    return Verdict::InvalidSubmission;
                };
                if &value != case.expected() {
                    verdict = Verdict::WrongAnswer;
                }
            }
            1 => verdict = Verdict::InvalidSubmission,
            2 => verdict = Verdict::ResourceLimit,
            3 => return Verdict::WorkerFailure,
            _ => return Verdict::WorkerFailure,
        }
    }
    if !bytes.is_empty() {
        return Verdict::WorkerFailure;
    }
    if count != challenge.cases().len() && verdict == Verdict::Passed {
        return Verdict::WorkerFailure;
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use coggate_core::Engine;

    #[test]
    fn response_cannot_claim_pass_without_all_expected_outputs() {
        let c = Engine::new([3; 32]).issue("tenant", b"", 10).unwrap().1;
        assert_eq!(decode_response(&c, b"CGR1\0\0\0\0"), Verdict::WorkerFailure);
        let mut response = b"CGR1".to_vec();
        push_u32(&mut response, c.cases().len());
        for case in c.cases() {
            response.push(0);
            let value = serde_json::to_vec(case.expected()).unwrap();
            push_u32(&mut response, value.len());
            response.extend(value);
        }
        assert_eq!(decode_response(&c, &response), Verdict::Passed);
        response.push(0);
        assert_eq!(decode_response(&c, &response), Verdict::WorkerFailure);
    }

    #[test]
    fn capacity_is_released_by_drop() {
        let runtime = Runtime::new("does-not-run", 1);
        let permit = runtime.reserve().unwrap();
        assert!(runtime.reserve().is_none());
        drop(permit);
        assert!(runtime.reserve().is_some());
    }

    #[test]
    fn concurrent_reservations_never_exceed_capacity() {
        let runtime = Arc::new(Runtime::new("does-not-run", 4));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let runtime = Arc::clone(&runtime);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let permit = runtime.reserve();
                    // Keep every acquired permit alive until all contenders try.
                    barrier.wait();
                    permit.is_some()
                })
            })
            .collect();
        let acquired = handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>();
        assert_eq!(acquired, 4);
        assert_eq!(runtime.active.load(Ordering::Acquire), 0);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn unsupported_platform_does_not_spawn_any_command() {
        let runtime = Runtime::new("/this/must/not/run", 1);
        let c = Engine::new([3; 32]).issue("tenant", b"", 10).unwrap().1;
        assert_eq!(
            runtime.execute(&c, "function solve(x) { return x; }"),
            Verdict::Unsupported
        );
    }
}
