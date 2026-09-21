use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{
        Html, IntoResponse, Redirect, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use coggate_core::{ChallengeService, IssueRequest};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use tokio_stream::{StreamExt, wrappers::BroadcastStream};

use crate::{
    auth::{OAUTH_COOKIE, SESSION_COOKIE, clear_cookie, cookie, set_cookie},
    config::Config,
    db::Database,
    error::{ArenaError, ArenaResult},
    github::{GitHubClient, GitHubClientConfig},
    lifecycle::{SqliteLifecycle, StaticKeyring},
    model::{Language, PreviewView},
    runner::RunnerClient,
    util::now_unix,
    worker::{SubmissionWorker, WorkerEvent},
};

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub database: Database,
    pub github: GitHubClient,
    pub keys: StaticKeyring,
    pub runner: RunnerClient,
    pub preview: Arc<RwLock<Option<PreviewView>>>,
    pub worker_events: broadcast::Sender<WorkerEvent>,
    pub arena_events: broadcast::Sender<String>,
}

impl AppState {
    pub fn new(config: Config, database: Database) -> ArenaResult<Self> {
        let github = GitHubClient::new(GitHubClientConfig {
            client_id: config.github_client_id.clone(),
            client_secret: config.github_client_secret.clone(),
            callback_url: config.github_callback_url(),
            owner: config.github_owner.clone(),
            repo: config.github_repo.clone(),
            app_id: config.github_app_id,
            installation_id: config.github_installation_id,
            app_private_key_pem: config.github_app_private_key_pem.as_bytes().to_vec(),
        })?;
        let keys = StaticKeyring::from_keys(config.mac_key_id.clone(), config.mac_keys.clone())
            .map_err(|_| ArenaError::Configuration("invalid MAC keyring".into()))?;
        let runner = RunnerClient::new(config.runner_socket.clone());
        let (worker_events, _) = broadcast::channel(128);
        let (arena_events, _) = broadcast::channel(32);
        Ok(Self {
            config: Arc::new(config),
            database,
            github,
            keys,
            runner,
            preview: Arc::new(RwLock::new(None)),
            worker_events,
            arena_events,
        })
    }

    pub fn start_background_tasks(&self) -> ArenaResult<()> {
        let worker = Arc::new(SubmissionWorker::new(
            self.database.clone(),
            self.runner.clone(),
            self.keys.clone(),
            self.worker_events.clone(),
            self.arena_events.clone(),
        )?);
        tokio::spawn(worker.run());
        tokio::spawn(crate::worker::run_issue_worker(
            self.database.clone(),
            self.github.clone(),
        ));

        let preview_state = self.clone();
        tokio::spawn(async move {
            let mut revision = 0_i64;
            loop {
                if let Ok(round) = preview_state.database.current_round() {
                    if round.status == "OPEN" {
                        revision += 1;
                        let binding = format!("preview:{}:{revision}", round.id);
                        let mut service = ChallengeService::new(
                            SqliteLifecycle::new(preview_state.database.clone()),
                            preview_state.keys.clone(),
                        );
                        match IssueRequest::v1(binding.as_bytes())
                            .map_err(|_| ())
                            .and_then(|request| service.issue_challenge(request).map_err(|_| ()))
                        {
                            Ok(challenge) => {
                                *preview_state.preview.write().await = Some(PreviewView {
                                    round_id: round.id,
                                    epoch: round.epoch,
                                    revision,
                                    refresh_at: now_unix() + 10,
                                    challenge,
                                });
                                let _ = preview_state.arena_events.send("preview_refreshed".into());
                            }
                            Err(()) => tracing::warn!("preview generation failed"),
                        }
                    } else {
                        *preview_state.preview.write().await = None;
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let cleanup_database = self.database.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                if let Err(error) = cleanup_database.cleanup_expired_payloads() {
                    tracing::warn!(error=%error, "retention cleanup failed");
                }
            }
        });
        Ok(())
    }
}

pub fn router(state: AppState) -> Router {
    let body_limit = state.config.source_limit_bytes * 6 + 4096;
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/app.js", get(app_js))
        .route("/api/v1/arena", get(arena))
        .route("/api/v1/arena/preview", get(preview))
        .route("/api/v1/arena/events", get(arena_events))
        .route("/auth/github/start", get(github_start))
        .route("/auth/github/callback", get(github_callback))
        .route("/api/v1/me", get(me))
        .route("/api/v1/logout", post(logout))
        .route(
            "/api/v1/submissions",
            get(list_submissions).post(create_submission),
        )
        .route("/api/v1/submissions/{id}", get(get_submission))
        .route("/api/v1/submissions/{id}/events", get(submission_events))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
    );
    response
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn healthz(State(state): State<AppState>) -> StatusCode {
    if state.database.current_round().is_ok() && state.runner.socket_path().exists() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn app_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        APP_JS,
    )
}

async fn arena(State(state): State<AppState>) -> ArenaResult<impl IntoResponse> {
    let view = state.database.arena_view(state.config.source_limit_bytes)?;
    Ok((
        [(header::CACHE_CONTROL, "public, max-age=2, must-revalidate")],
        Json(view),
    ))
}

async fn preview(State(state): State<AppState>) -> ArenaResult<Response> {
    let preview = state
        .preview
        .read()
        .await
        .clone()
        .filter(|value| value.challenge.expires_at >= now_unix())
        .ok_or(ArenaError::NotFound)?;
    let etag = format!("\"{}:{}\"", preview.round_id, preview.revision);
    let mut response = Json(preview).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=2, must-revalidate"),
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(|_| ArenaError::Internal)?,
    );
    Ok(response)
}

async fn arena_events(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(state.arena_events.subscribe()).filter_map(|item| {
        item.ok()
            .map(|kind| Ok(Event::default().event(kind.clone()).data(kind)))
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

async fn github_start(State(state): State<AppState>) -> ArenaResult<Response> {
    let oauth_state = crate::util::random_token(32)?;
    state
        .database
        .store_oauth_state(&oauth_state, now_unix() + 600)?;
    let location = state.github.authorize_url(&oauth_state)?;
    let mut response = Redirect::temporary(&location).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_cookie(
            OAUTH_COOKIE,
            &oauth_state,
            600,
            state.config.secure_cookies,
        ))
        .map_err(|_| ArenaError::Internal)?,
    );
    Ok(response)
}

#[derive(Deserialize)]
struct OAuthCallback {
    code: String,
    state: String,
}

async fn github_callback(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OAuthCallback>,
) -> ArenaResult<Response> {
    let cookie_state = cookie(&headers, OAUTH_COOKIE).ok_or(ArenaError::Unauthorized)?;
    if cookie_state != query.state {
        return Err(ArenaError::Unauthorized);
    }
    app.database.consume_oauth_state(&query.state)?;
    let user = app.github.exchange_user(&query.code).await?;
    let session = app.database.create_login_session(
        user.github_id,
        &user.github_login,
        app.config.session_ttl_seconds,
    )?;
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_cookie(
            SESSION_COOKIE,
            &session,
            app.config.session_ttl_seconds,
            app.config.secure_cookies,
        ))
        .map_err(|_| ArenaError::Internal)?,
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(OAUTH_COOKIE, app.config.secure_cookies))
            .map_err(|_| ArenaError::Internal)?,
    );
    Ok(response)
}

fn authenticated(
    state: &AppState,
    headers: &HeaderMap,
) -> ArenaResult<(crate::model::User, String)> {
    let token = cookie(headers, SESSION_COOKIE).ok_or(ArenaError::Unauthorized)?;
    Ok((state.database.authenticate(&token)?, token))
}

#[derive(Serialize)]
struct MeResponse {
    github_id: i64,
    github_login: String,
    quota: crate::model::QuotaView,
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> ArenaResult<Json<MeResponse>> {
    let (user, _) = authenticated(&state, &headers)?;
    let quota = state.database.quota_for(user.github_id)?;
    Ok(Json(MeResponse {
        github_id: user.github_id,
        github_login: user.github_login,
        quota,
    }))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ArenaResult<Response> {
    let (_, token) = authenticated(&state, &headers)?;
    state.database.logout(&token)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(SESSION_COOKIE, state.config.secure_cookies))
            .map_err(|_| ArenaError::Internal)?,
    );
    Ok(response)
}

#[derive(Deserialize)]
struct CreateSubmission {
    epoch: i64,
    language: Language,
    source: String,
    idempotency_key: String,
    publication_agreed: bool,
}

#[derive(Serialize)]
struct AcceptedResponse {
    submission_id: String,
    created: bool,
    quota: crate::model::QuotaView,
}

async fn create_submission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSubmission>,
) -> ArenaResult<impl IntoResponse> {
    let (user, _) = authenticated(&state, &headers)?;
    if !request.publication_agreed {
        return Err(ArenaError::InvalidRequest("publication_consent_required"));
    }
    if request.source.is_empty() {
        return Err(ArenaError::InvalidRequest("source_empty"));
    }
    if request.source.len() > state.config.source_limit_bytes {
        return Err(ArenaError::PayloadTooLarge);
    }
    if !(8..=128).contains(&request.idempotency_key.len())
        || !request
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ArenaError::InvalidRequest("invalid_idempotency_key"));
    }
    let accepted = state.database.accept_submission(
        &user,
        request.epoch,
        request.language,
        &request.source,
        &request.idempotency_key,
        state.config.queue_limit,
        "broker-configured",
        "arena-policy-v1",
    )?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedResponse {
            submission_id: accepted.id,
            created: accepted.created,
            quota: accepted.quota,
        }),
    ))
}

async fn get_submission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ArenaResult<Json<crate::model::SubmissionView>> {
    let (user, _) = authenticated(&state, &headers)?;
    Ok(Json(state.database.submission_view(&id, user.github_id)?))
}

async fn list_submissions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ArenaResult<Json<Vec<crate::model::SubmissionView>>> {
    let (user, _) = authenticated(&state, &headers)?;
    let mut submissions = Vec::new();
    for id in state.database.recent_submission_ids(user.github_id)? {
        submissions.push(state.database.submission_view(&id, user.github_id)?);
    }
    Ok(Json(submissions))
}

async fn submission_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ArenaResult<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>> {
    let (user, _) = authenticated(&state, &headers)?;
    state.database.submission_view(&id, user.github_id)?;
    let selected_id = id.clone();
    let stream =
        BroadcastStream::new(state.worker_events.subscribe()).filter_map(move |item| match item {
            Ok(event) if event.submission_id == selected_id => Some(Ok(Event::default()
                .event(event.kind)
                .data(event.submission_id))),
            _ => None,
        });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parser_uses_exact_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("xarena_session=no; arena_session=yes"),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("yes"));
    }
}
