use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

use crate::{
    error::{ArenaError, ArenaResult},
    model::Language,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum BrokerRequest {
    Prepare {
        version: u16,
        request_id: String,
        submission_id: String,
        lease_id: String,
        language: Language,
        source: String,
        compile_timeout_ms: u64,
    },
    Execute {
        version: u16,
        request_id: String,
        artifact_id: String,
        question: String,
        timeout_ms: u64,
    },
    Destroy {
        version: u16,
        request_id: String,
        artifact_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompileResult {
    pub success: bool,
    pub artifact_id: Option<String>,
    pub duration_ms: i64,
    pub output: String,
    pub output_truncated: bool,
    pub image_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunResult {
    pub status: RunStatus,
    pub duration_ms: i64,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_encoding: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Exited,
    TimedOut,
    OutputLimitExceeded,
    SandboxError,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum BrokerResponse {
    Prepared(CompileResult),
    Executed(RunResult),
    Destroyed,
    Error { code: String },
}

#[derive(Clone, Debug)]
pub struct RunnerClient {
    socket: std::path::PathBuf,
}

impl RunnerClient {
    pub fn new(socket: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    async fn call(&self, request: &BrokerRequest) -> ArenaResult<BrokerResponse> {
        let mut stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|_| ArenaError::Upstream)?;
        let payload = serde_json::to_vec(request).map_err(|_| ArenaError::Internal)?;
        if payload.len() > MAX_FRAME_BYTES {
            return Err(ArenaError::PayloadTooLarge);
        }
        stream
            .write_u32(payload.len() as u32)
            .await
            .map_err(|_| ArenaError::Upstream)?;
        stream
            .write_all(&payload)
            .await
            .map_err(|_| ArenaError::Upstream)?;
        let length = stream.read_u32().await.map_err(|_| ArenaError::Upstream)? as usize;
        if length > MAX_FRAME_BYTES {
            return Err(ArenaError::Upstream);
        }
        let mut response = vec![0; length];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|_| ArenaError::Upstream)?;
        serde_json::from_slice(&response).map_err(|_| ArenaError::Upstream)
    }

    pub async fn prepare(
        &self,
        submission_id: &str,
        lease_id: &str,
        language: Language,
        source: &str,
    ) -> ArenaResult<CompileResult> {
        let request = BrokerRequest::Prepare {
            version: PROTOCOL_VERSION,
            request_id: crate::util::random_id("req")?,
            submission_id: submission_id.into(),
            lease_id: lease_id.into(),
            language,
            source: source.into(),
            compile_timeout_ms: 10_000,
        };
        match self.call(&request).await? {
            BrokerResponse::Prepared(result) => Ok(result),
            _ => Err(ArenaError::Upstream),
        }
    }

    pub async fn execute(
        &self,
        artifact_id: &str,
        question: &str,
        timeout_ms: u64,
    ) -> ArenaResult<RunResult> {
        let request = BrokerRequest::Execute {
            version: PROTOCOL_VERSION,
            request_id: crate::util::random_id("req")?,
            artifact_id: artifact_id.into(),
            question: question.into(),
            timeout_ms,
        };
        match self.call(&request).await? {
            BrokerResponse::Executed(result) => Ok(result),
            _ => Err(ArenaError::Upstream),
        }
    }

    pub async fn destroy(&self, artifact_id: &str) {
        let request = BrokerRequest::Destroy {
            version: PROTOCOL_VERSION,
            request_id: crate::util::random_id("req").unwrap_or_else(|_| "cleanup".into()),
            artifact_id: artifact_id.into(),
        };
        let _ = self.call(&request).await;
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }
}
