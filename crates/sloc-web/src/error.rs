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
