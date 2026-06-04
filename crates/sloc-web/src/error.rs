// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Typed HTTP error responses for JSON API endpoints.
//!
//! Every function returns an Axum [`Response`] with a consistent JSON body
//! `{"error": "<message>"}` and the appropriate status code.  Use these in
//! handlers that speak JSON; HTML page handlers should keep using
//! `ErrorTemplate` so the browser gets a styled error page.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn not_found(message: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(ErrorBody { error: message }),
    )
        .into_response()
}

pub fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(ErrorBody { error: message }),
    )
        .into_response()
}

pub fn internal(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(ErrorBody { error: message }),
    )
        .into_response()
}

pub fn unprocessable_entity(message: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        axum::Json(ErrorBody { error: message }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use axum::body::Body;
    use http_body_util::BodyExt;

    async fn body_str(resp: Response) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn not_found_returns_404() {
        let (status, body) = body_str(not_found("thing not found")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("thing not found"));
        assert!(body.contains("\"error\""));
    }

    #[tokio::test]
    async fn bad_request_returns_400() {
        let (status, body) = body_str(bad_request("invalid input")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("invalid input"));
        assert!(body.contains("\"error\""));
    }

    #[tokio::test]
    async fn internal_returns_500() {
        let (status, body) = body_str(internal("server blew up")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("server blew up"));
        assert!(body.contains("\"error\""));
    }

    #[tokio::test]
    async fn unprocessable_entity_returns_422() {
        let (status, body) = body_str(unprocessable_entity("bad data")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("bad data"));
        assert!(body.contains("\"error\""));
    }

    #[tokio::test]
    async fn not_found_empty_message() {
        let (status, body) = body_str(not_found("")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("\"error\""));
    }

    #[tokio::test]
    async fn responses_are_json_content_type() {
        use axum::http::header;
        let fns: Vec<fn(&str) -> Response> =
            vec![not_found, bad_request, internal, unprocessable_entity];
        for f in fns {
            let resp = f("msg");
            let ct = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(ct.contains("json"), "expected JSON content-type, got: {ct}");
        }
    }
}
