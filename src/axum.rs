use std::{
    error::Error,
    fmt::{Display, Formatter},
};

use axum_core::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use http::{request::Parts, StatusCode};

use crate::csp::CspNonce;

#[derive(Debug)]
pub struct NonceNotFoundError;

impl Display for NonceNotFoundError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce not found in extensions!")
    }
}

impl Error for NonceNotFoundError {}

impl IntoResponse for NonceNotFoundError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for CspNonce {
    type Rejection = NonceNotFoundError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get().cloned().ok_or(NonceNotFoundError)
    }
}
