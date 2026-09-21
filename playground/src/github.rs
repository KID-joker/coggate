use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ArenaError, ArenaResult},
    model::User,
};

#[derive(Clone)]
pub struct GitHubClient {
    http: reqwest::Client,
    client_id: String,
    client_secret: String,
    callback_url: String,
    owner: String,
    repo: String,
    app_id: u64,
    installation_id: u64,
    app_key: jsonwebtoken::EncodingKey,
}

pub struct GitHubClientConfig {
    pub client_id: String,
    pub client_secret: String,
    pub callback_url: String,
    pub owner: String,
    pub repo: String,
    pub app_id: u64,
    pub installation_id: u64,
    pub app_private_key_pem: Vec<u8>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
}

#[derive(Serialize)]
struct IssueRequest<'a> {
    title: &'a str,
    body: &'a str,
}

#[derive(Deserialize)]
pub struct CreatedIssue {
    pub number: i64,
    pub html_url: String,
}

#[derive(Serialize)]
struct AppClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Deserialize)]
struct InstallationToken {
    token: String,
}

#[derive(Deserialize)]
struct IssueListItem {
    number: i64,
    html_url: String,
    body: Option<String>,
}

impl GitHubClient {
    pub fn new(config: GitHubClientConfig) -> ArenaResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|_| ArenaError::Configuration("cannot build HTTP client".into()))?;
        let app_key = jsonwebtoken::EncodingKey::from_rsa_pem(&config.app_private_key_pem)
            .map_err(|_| ArenaError::Configuration("invalid GitHub App private key".into()))?;
        Ok(Self {
            http,
            client_id: config.client_id,
            client_secret: config.client_secret,
            callback_url: config.callback_url,
            owner: config.owner,
            repo: config.repo,
            app_id: config.app_id,
            installation_id: config.installation_id,
            app_key,
        })
    }

    pub fn authorize_url(&self, state: &str) -> ArenaResult<String> {
        let mut url = url::Url::parse("https://github.com/login/oauth/authorize")
            .map_err(|_| ArenaError::Internal)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.callback_url)
            .append_pair("state", state)
            .append_pair("scope", "read:user");
        Ok(url.into())
    }

    pub async fn exchange_user(&self, code: &str) -> ArenaResult<User> {
        let token: TokenResponse = self
            .http
            .post("https://github.com/login/oauth/access_token")
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, "coggate-playground")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", self.callback_url.as_str()),
            ])
            .send()
            .await
            .map_err(|_| ArenaError::Upstream)?
            .error_for_status()
            .map_err(|_| ArenaError::Upstream)?
            .json()
            .await
            .map_err(|_| ArenaError::Upstream)?;
        let access_token = token.access_token.ok_or(ArenaError::Unauthorized)?;
        let github: GitHubUser = self
            .http
            .get("https://api.github.com/user")
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "coggate-playground")
            .header(AUTHORIZATION, format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|_| ArenaError::Upstream)?
            .error_for_status()
            .map_err(|_| ArenaError::Unauthorized)?
            .json()
            .await
            .map_err(|_| ArenaError::Upstream)?;
        if github.id <= 0
            || github.login.is_empty()
            || github.login.len() > 39
            || !github
                .login
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || value == b'-')
        {
            return Err(ArenaError::Upstream);
        }
        Ok(User {
            github_id: github.id,
            github_login: github.login,
        })
    }

    pub async fn create_issue_with_token(
        &self,
        installation_token: &str,
        title: &str,
        body: &str,
    ) -> ArenaResult<CreatedIssue> {
        let url = format!(
            "https://api.github.com/repos/{}/{}/issues",
            self.owner, self.repo
        );
        self.http
            .post(url)
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "coggate-playground")
            .header(AUTHORIZATION, format!("Bearer {installation_token}"))
            .json(&IssueRequest { title, body })
            .send()
            .await
            .map_err(|_| ArenaError::Upstream)?
            .error_for_status()
            .map_err(|_| ArenaError::Upstream)?
            .json()
            .await
            .map_err(|_| ArenaError::Upstream)
    }

    async fn installation_token(&self) -> ArenaResult<String> {
        let now = crate::util::now_unix();
        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &AppClaims {
                iat: now - 60,
                exp: now + 540,
                iss: self.app_id.to_string(),
            },
            &self.app_key,
        )
        .map_err(|_| ArenaError::Internal)?;
        let url = format!(
            "https://api.github.com/app/installations/{}/access_tokens",
            self.installation_id
        );
        let token: InstallationToken = self
            .http
            .post(url)
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "coggate-playground")
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .send()
            .await
            .map_err(|_| ArenaError::Upstream)?
            .error_for_status()
            .map_err(|_| ArenaError::Upstream)?
            .json()
            .await
            .map_err(|_| ArenaError::Upstream)?;
        Ok(token.token)
    }

    pub async fn find_or_create_issue(
        &self,
        marker: &str,
        title: &str,
        body: &str,
    ) -> ArenaResult<CreatedIssue> {
        let token = self.installation_token().await?;
        let url = format!(
            "https://api.github.com/repos/{}/{}/issues",
            self.owner, self.repo
        );
        let issues: Vec<IssueListItem> = self
            .http
            .get(&url)
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "coggate-playground")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .query(&[
                ("state", "all"),
                ("per_page", "100"),
                ("sort", "created"),
                ("direction", "desc"),
            ])
            .send()
            .await
            .map_err(|_| ArenaError::Upstream)?
            .error_for_status()
            .map_err(|_| ArenaError::Upstream)?
            .json()
            .await
            .map_err(|_| ArenaError::Upstream)?;
        if let Some(issue) = issues.into_iter().find(|issue| {
            issue
                .body
                .as_deref()
                .is_some_and(|value| value.contains(marker))
        }) {
            return Ok(CreatedIssue {
                number: issue.number,
                html_url: issue.html_url,
            });
        }
        self.create_issue_with_token(&token, title, body).await
    }
}
