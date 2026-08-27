use super::json::{Json, jcs, object_get, object_string, object_u64};
use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};

const COMMENTS_PER_PAGE: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GithubCredential {
    AppInstallation {
        token: String,
        installation_id: u64,
        app_id: u64,
    },
    #[allow(dead_code)]
    // Deliberate negative credential class for the App-only authorship boundary.
    UserToken(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedReceiptAuth {
    token: String,
    pub installation_id: u64,
    pub app_id: u64,
}

impl TrustedReceiptAuth {
    pub(super) fn try_from_credential(
        credential: GithubCredential,
    ) -> Result<Self, PublicationError> {
        match credential {
            GithubCredential::UserToken(_) => Err(PublicationError(
                "trusted receipt production requires GitHub App installation identity; user/PAT credentials are forbidden".into(),
            )),
            GithubCredential::AppInstallation {
                token,
                installation_id,
                app_id,
            } => {
                if !token.starts_with("ghs_")
                    || token.len() < 16
                    || token.chars().any(char::is_whitespace)
                    || installation_id == 0
                    || app_id == 0
                {
                    return Err(PublicationError(
                        "invalid GitHub App installation credential configuration".into(),
                    ));
                }
                Ok(Self {
                    token,
                    installation_id,
                    app_id,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicationError(pub String);

impl fmt::Display for PublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PublicationError {}

pub(crate) trait ReceiptPublisher: Send + Sync {
    fn publish_terminal(
        &self,
        auth: &TrustedReceiptAuth,
        issue_number: u64,
        receipt: &str,
    ) -> Result<i64, PublicationError>;

    fn reconcile_terminal(
        &self,
        auth: &TrustedReceiptAuth,
        issue_number: u64,
        receipt: &str,
    ) -> Result<Option<i64>, PublicationError>;
}

#[derive(Debug, Clone)]
pub(super) struct GithubAppReceiptPublisher {
    repository: String,
}

impl GithubAppReceiptPublisher {
    pub(super) fn new(repository: String) -> Result<Self, PublicationError> {
        if !valid_repository(&repository) {
            return Err(PublicationError(
                "trusted GitHub repository must be configured as owner/name".into(),
            ));
        }
        Ok(Self { repository })
    }

    fn comments_page(
        &self,
        auth: &TrustedReceiptAuth,
        issue_number: u64,
        page: u64,
    ) -> Result<Json, PublicationError> {
        self.request_json(
            auth,
            "GET",
            &format!(
                "/repos/{}/issues/{issue_number}/comments?per_page={COMMENTS_PER_PAGE}&page={page}",
                self.repository
            ),
            None,
        )
    }

    fn ensure_closed(
        &self,
        auth: &TrustedReceiptAuth,
        issue_number: u64,
    ) -> Result<(), PublicationError> {
        let body = jcs(&Json::Object(vec![(
            "state".into(),
            Json::String("closed".into()),
        )]))
        .map_err(|error| PublicationError(error.to_string()))?;
        let response = self.request_json(
            auth,
            "PATCH",
            &format!("/repos/{}/issues/{issue_number}", self.repository),
            Some(&body),
        )?;
        if response.get("state").and_then(Json::as_str) != Some("closed") {
            return Err(PublicationError(
                "GitHub did not confirm terminal Issue closure".into(),
            ));
        }
        Ok(())
    }

    fn request_json(
        &self,
        auth: &TrustedReceiptAuth,
        method: &str,
        endpoint: &str,
        body: Option<&str>,
    ) -> Result<Json, PublicationError> {
        let url = format!("https://api.github.com{endpoint}");
        let mut command = Command::new("curl");
        command
            .args([
                "--silent",
                "--show-error",
                "--location",
                "--request",
                method,
            ])
            .arg("--header")
            .arg("X-GitHub-Api-Version: 2022-11-28")
            .arg("--header")
            .arg("Accept: application/vnd.github+json")
            .arg("--header")
            .arg(format!("Authorization: Bearer {}", auth.token))
            .args(["--write-out", "\n%{http_code}"]);
        if body.is_some() {
            command
                .arg("--header")
                .arg("Content-Type: application/json")
                .args(["--data-binary", "@-"])
                .stdin(Stdio::piped());
        }
        command
            .arg(url)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            PublicationError(format!(
                "could not execute bounded GitHub HTTP client: {error}"
            ))
        })?;
        if let Some(body) = body {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| PublicationError("GitHub HTTP client stdin unavailable".into()))?;
            stdin.write_all(body.as_bytes()).map_err(|error| {
                PublicationError(format!("could not send GitHub request body: {error}"))
            })?;
        }
        let output = child.wait_with_output().map_err(|error| {
            PublicationError(format!("bounded GitHub HTTP client failed: {error}"))
        })?;
        if !output.status.success() {
            return Err(PublicationError(
                "bounded GitHub HTTP client exited unsuccessfully".into(),
            ));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| PublicationError("GitHub response is not UTF-8".into()))?;
        let (body, status) = stdout
            .rsplit_once('\n')
            .ok_or_else(|| PublicationError("GitHub response lacks HTTP status trailer".into()))?;
        let status = status
            .parse::<u16>()
            .map_err(|_| PublicationError("GitHub HTTP status trailer is invalid".into()))?;
        if !(200..300).contains(&status) {
            return Err(PublicationError(format!(
                "GitHub transaction request returned HTTP {status}"
            )));
        }
        Json::parse(body).map_err(|error| PublicationError(error.to_string()))
    }
}

impl ReceiptPublisher for GithubAppReceiptPublisher {
    fn publish_terminal(
        &self,
        auth: &TrustedReceiptAuth,
        issue_number: u64,
        receipt: &str,
    ) -> Result<i64, PublicationError> {
        let body = jcs(&Json::Object(vec![(
            "body".into(),
            Json::String(receipt.to_owned()),
        )]))
        .map_err(|error| PublicationError(error.to_string()))?;
        let response = self.request_json(
            auth,
            "POST",
            &format!("/repos/{}/issues/{issue_number}/comments", self.repository),
            Some(&body),
        )?;
        let object = response
            .as_object()
            .ok_or_else(|| PublicationError("GitHub comment response is not an object".into()))?;
        let id = trusted_comment_id(object, auth, receipt)?.ok_or_else(|| {
            PublicationError(
                "terminal comment author/body metadata does not match configured GitHub App".into(),
            )
        })?;
        self.ensure_closed(auth, issue_number)?;
        i64::try_from(id).map_err(|_| PublicationError("GitHub comment id exceeds i64".into()))
    }

    fn reconcile_terminal(
        &self,
        auth: &TrustedReceiptAuth,
        issue_number: u64,
        receipt: &str,
    ) -> Result<Option<i64>, PublicationError> {
        let comment_id = reconcile_paginated_comments(auth, receipt, |page| {
            self.comments_page(auth, issue_number, page)
        })?;
        if comment_id.is_some() {
            self.ensure_closed(auth, issue_number)?;
        }
        Ok(comment_id)
    }
}

fn reconcile_paginated_comments(
    auth: &TrustedReceiptAuth,
    receipt: &str,
    mut fetch_page: impl FnMut(u64) -> Result<Json, PublicationError>,
) -> Result<Option<i64>, PublicationError> {
    let mut page = 1_u64;
    let mut matching_id = None::<u64>;
    loop {
        let comments = fetch_page(page)?;
        let array = comments
            .as_array()
            .ok_or_else(|| PublicationError("GitHub comments response is not an array".into()))?;
        if array.len() > COMMENTS_PER_PAGE {
            return Err(PublicationError(
                "GitHub comments page exceeds requested page size".into(),
            ));
        }
        for comment in array {
            let Some(object) = comment.as_object() else {
                continue;
            };
            let Some(id) = trusted_comment_id(object, auth, receipt)? else {
                continue;
            };
            if matching_id.replace(id).is_some() {
                return Err(PublicationError(
                    "multiple trusted terminal comments match one transaction".into(),
                ));
            }
        }
        if array.len() < COMMENTS_PER_PAGE {
            break;
        }
        page = page
            .checked_add(1)
            .ok_or_else(|| PublicationError("GitHub comments pagination overflow".into()))?;
    }
    matching_id
        .map(i64::try_from)
        .transpose()
        .map_err(|_| PublicationError("GitHub comment id exceeds i64".into()))
}

fn trusted_comment_id(
    object: &[(String, Json)],
    auth: &TrustedReceiptAuth,
    receipt: &str,
) -> Result<Option<u64>, PublicationError> {
    if object_string(object, "body") != Some(receipt) {
        return Ok(None);
    }
    let user = object_get(object, "user").and_then(Json::as_object);
    let app = object_get(object, "performed_via_github_app").and_then(Json::as_object);
    let trusted = user
        .and_then(|value| object_string(value, "type"))
        .is_some_and(|value| value == "Bot")
        && app
            .and_then(|value| object_u64(value, "id"))
            .is_some_and(|value| value == auth.app_id);
    if !trusted {
        return Ok(None);
    }
    object_u64(object, "id")
        .map(Some)
        .ok_or_else(|| PublicationError("trusted matching GitHub comment has no numeric id".into()))
}

fn valid_repository(repository: &str) -> bool {
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    !owner.is_empty()
        && !name.is_empty()
        && parts.next().is_none()
        && owner
            .bytes()
            .chain(name.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> TrustedReceiptAuth {
        TrustedReceiptAuth::try_from_credential(GithubCredential::AppInstallation {
            token: "ghs_12345678901234567890".into(),
            installation_id: 7,
            app_id: 9,
        })
        .unwrap()
    }

    fn comment(id: u64, body: &str, trusted: bool) -> Json {
        Json::Object(vec![
            ("id".into(), Json::Number(id.to_string())),
            ("body".into(), Json::String(body.into())),
            (
                "user".into(),
                Json::Object(vec![(
                    "type".into(),
                    Json::String(if trusted { "Bot" } else { "User" }.into()),
                )]),
            ),
            (
                "performed_via_github_app".into(),
                if trusted {
                    Json::Object(vec![("id".into(), Json::Number("9".into()))])
                } else {
                    Json::Null
                },
            ),
        ])
    }

    #[test]
    fn receipt_authorship_requires_app_installation_identity() {
        let user = TrustedReceiptAuth::try_from_credential(GithubCredential::UserToken(
            "github_pat_not_trusted".into(),
        ));
        assert!(user.is_err());
        let app = auth();
        assert_eq!(app.installation_id, 7);
        assert_eq!(app.app_id, 9);
    }

    #[test]
    fn copied_receipt_body_without_app_metadata_is_not_trusted() {
        let comments = Json::Array(vec![comment(1, "receipt", false)]);
        assert_eq!(
            reconcile_paginated_comments(&auth(), "receipt", |_| Ok(comments.clone())).unwrap(),
            None
        );
    }

    #[test]
    fn reconciliation_finds_trusted_receipt_after_first_hundred_comments() {
        let mut first = (0..COMMENTS_PER_PAGE)
            .map(|index| comment(index as u64 + 1, "decoy", false))
            .collect::<Vec<_>>();
        assert_eq!(first.len(), COMMENTS_PER_PAGE);
        let second = vec![comment(777, "receipt", true)];
        let mut calls = 0_u64;
        let found = reconcile_paginated_comments(&auth(), "receipt", |page| {
            calls += 1;
            match page {
                1 => Ok(Json::Array(std::mem::take(&mut first))),
                2 => Ok(Json::Array(second.clone())),
                _ => panic!("unexpected page {page}"),
            }
        })
        .unwrap();
        assert_eq!(found, Some(777));
        assert_eq!(calls, 2);
    }

    #[test]
    fn reconciliation_exhausts_pagination_when_no_receipt_matches() {
        let first = (0..COMMENTS_PER_PAGE)
            .map(|index| comment(index as u64 + 1, "decoy", false))
            .collect::<Vec<_>>();
        let second = vec![comment(501, "receipt", false)];
        let mut calls = 0_u64;
        let found = reconcile_paginated_comments(&auth(), "receipt", |page| {
            calls += 1;
            match page {
                1 => Ok(Json::Array(first.clone())),
                2 => Ok(Json::Array(second.clone())),
                _ => panic!("unexpected page {page}"),
            }
        })
        .unwrap();
        assert_eq!(found, None);
        assert_eq!(calls, 2);
    }

    #[test]
    fn multiple_trusted_matching_receipts_fail_closed_across_pages() {
        let mut first = (0..COMMENTS_PER_PAGE - 1)
            .map(|index| comment(index as u64 + 1, "decoy", false))
            .collect::<Vec<_>>();
        first.push(comment(600, "receipt", true));
        let second = vec![comment(601, "receipt", true)];
        let error = reconcile_paginated_comments(&auth(), "receipt", |page| match page {
            1 => Ok(Json::Array(first.clone())),
            2 => Ok(Json::Array(second.clone())),
            _ => panic!("unexpected page {page}"),
        })
        .unwrap_err();
        assert!(error.0.contains("multiple trusted"));
    }

    #[test]
    fn pagination_http_error_is_not_treated_as_exhaustion() {
        let first = (0..COMMENTS_PER_PAGE)
            .map(|index| comment(index as u64 + 1, "decoy", false))
            .collect::<Vec<_>>();
        let error = reconcile_paginated_comments(&auth(), "receipt", |page| match page {
            1 => Ok(Json::Array(first.clone())),
            2 => Err(PublicationError("HTTP 503".into())),
            _ => panic!("unexpected page {page}"),
        })
        .unwrap_err();
        assert_eq!(error.0, "HTTP 503");
    }
}
