use std::{
    fmt::{Display, Formatter},
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
use http::{
    header::{CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY},
    Request, Response,
};
use tower_layer::Layer;
use tower_service::Service;

use crate::{headers::ContentSecurityPolicy, middleware_add_raw_header};

pub const BAD_CSP_MESSAGE: &str =
    "Failed to create CSP header. Did you pass an invalid header value into a custom string?";

#[derive(Clone, Debug)]
pub struct CspNonce(pub String);

impl Display for CspNonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[derive(Debug, Clone)]
pub struct CspLayer {
    report_only: bool,
    csp: Arc<ContentSecurityPolicy>,
}

impl CspLayer {
    pub fn new(csp: ContentSecurityPolicy) -> Self {
        Self::new_internal(Arc::new(csp), false)
    }

    pub fn new_report_only(csp: ContentSecurityPolicy) -> Self {
        Self::new_internal(Arc::new(csp), true)
    }

    pub fn new_arc(csp: Arc<ContentSecurityPolicy>) -> Self {
        Self::new_internal(csp, false)
    }

    pub fn new_arc_report_only(csp: Arc<ContentSecurityPolicy>) -> Self {
        Self::new_internal(csp, true)
    }

    fn new_internal(csp: Arc<ContentSecurityPolicy>, report_only: bool) -> Self {
        Self { report_only, csp }
    }
}

impl<S> Layer<S> for CspLayer {
    type Service = CspService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CspService {
            report_only: self.report_only,
            csp: self.csp.clone(),
            inner,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CspService<S> {
    report_only: bool,
    csp: Arc<ContentSecurityPolicy>,
    inner: S,
}

impl<S, Body> Service<Request<Body>> for CspService<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    Body: Send + 'static,
{
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    type Response = Response<Body>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let nonce_string = crate::random_string(32);
        request
            .extensions_mut()
            .insert(CspNonce(nonce_string.clone()));

        let future = self.inner.call(request);

        let csp = self.csp.value(&nonce_string).expect(BAD_CSP_MESSAGE);

        let name = if self.report_only {
            CONTENT_SECURITY_POLICY_REPORT_ONLY
        } else {
            CONTENT_SECURITY_POLICY
        };

        Box::pin(middleware_add_raw_header(name, csp, future))
    }
}
