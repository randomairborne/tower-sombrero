#![warn(clippy::all, clippy::nursery)]
//! # tower-sombrero`
//! ### Easily add basic security headers to your tower http services
//!
//! Documentation is a work on progress. [Contribute?]
//!
//! [Contribute?]: https://github.com/randomairborne/tower-sombrero`

#[cfg(feature = "axum")]
mod axum;
pub mod csp;
pub mod headers;

#[cfg(test)]
mod tests;

use std::{
    future::Future,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::BoxFuture;
use http::{
    header::{CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY},
    HeaderMap, HeaderName, HeaderValue, Request, Response,
};
use rand::{distributions::Alphanumeric, Rng};
use tower_layer::Layer;
use tower_service::Service;

use crate::{
    csp::{CspNonce, BAD_CSP_MESSAGE},
    headers::{
        ContentSecurityPolicy, CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy,
        CrossOriginResourcePolicy, Header, OriginAgentCluster, ReferrerPolicy,
        StrictTransportSecurity, XContentTypeOptions, XDnsPrefetchControl, XDownloadOptions,
        XFrameOptions, XPermittedCrossDomainPolicies, XXssProtection,
    },
};

#[derive(Debug, Clone)]
// would be Copy, if not for those meddling CSP strings
pub struct Sombrero {
    content_security_policy: Option<Arc<ContentSecurityPolicy>>,
    content_security_policy_report_only: Option<Arc<ContentSecurityPolicy>>,
    cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,
    origin_agent_cluster: Option<OriginAgentCluster>,
    referrer_policy: Option<ReferrerPolicy>,
    strict_transport_security: Option<StrictTransportSecurity>,
    x_content_type_options: Option<XContentTypeOptions>,
    /// Not set by default, as not using DNS prefetches can SUBSTANTIALLY slow a website and its navigation
    x_dns_prefetch_control: Option<XDnsPrefetchControl>,
    x_download_options: Option<XDownloadOptions>,
    x_frame_options: Option<XFrameOptions>,
    x_permitted_cross_domain_policies: Option<XPermittedCrossDomainPolicies>,
    /// Always use protection. Except X-XSS-Protection, which is buggy and can modify running scripts.
    x_xss_protection: Option<XXssProtection>,
}

macro_rules! builder_add {
    ($field:ident, $kind:ty) => {
        #[must_use]
        pub fn $field(self, k: $kind) -> Self {
            Self {
                $field: ::std::option::Option::Some(k),
                ..self
            }
        }
    };
}

macro_rules! builder_add_arc {
    ($field:ident, $kind:ty) => {
        #[must_use]
        pub fn $field(self, k: $kind) -> Self {
            Self {
                $field: ::std::option::Option::Some(::std::sync::Arc::new(k)),
                ..self
            }
        }
    };
}

macro_rules! builder_remove {
    ($field:ident, $name:ident) => {
        #[must_use]
        pub fn $name(self) -> Self {
            Self {
                $field: ::std::option::Option::None,
                ..self
            }
        }
    };
}

impl Sombrero {
    pub const fn new() -> Self {
        Self {
            content_security_policy: None,
            content_security_policy_report_only: None,
            cross_origin_embedder_policy: None,
            cross_origin_opener_policy: None,
            cross_origin_resource_policy: None,
            origin_agent_cluster: None,
            referrer_policy: None,
            strict_transport_security: None,
            x_content_type_options: None,
            x_dns_prefetch_control: None,
            x_download_options: None,
            x_frame_options: None,
            x_permitted_cross_domain_policies: None,
            x_xss_protection: None,
        }
    }
}

#[rustfmt::skip]
impl Sombrero {
    builder_remove!(content_security_policy, remove_content_security_policy);
    builder_remove!(content_security_policy_report_only, remove_content_security_policy_report_only);
    builder_remove!(cross_origin_embedder_policy, remove_cross_origin_embedder_policy);
    builder_remove!(cross_origin_opener_policy, remove_cross_origin_opener_policy);
    builder_remove!(cross_origin_resource_policy, remove_cross_origin_resource_policy);
    builder_remove!(origin_agent_cluster, remove_origin_agent_cluster);
    builder_remove!(referrer_policy, remove_referrer_policy);
    builder_remove!(strict_transport_security, remove_strict_transport_security);
    builder_remove!(x_content_type_options, remove_x_content_type_options);
    builder_remove!(x_dns_prefetch_control, remove_x_dns_prefetch_control);
    builder_remove!(x_download_options, remove_x_download_options);
    builder_remove!(x_frame_options, remove_x_frame_options);
    builder_remove!(x_permitted_cross_domain_policies, remove_x_permitted_cross_domain_policies);
    builder_remove!(x_xss_protection, remove_x_xss_protection);
    builder_add_arc!(content_security_policy, ContentSecurityPolicy);
    builder_add_arc!(content_security_policy_report_only, ContentSecurityPolicy);
    builder_add!(cross_origin_embedder_policy, CrossOriginEmbedderPolicy);
    builder_add!(cross_origin_opener_policy, CrossOriginOpenerPolicy);
    builder_add!(cross_origin_resource_policy, CrossOriginResourcePolicy);
    builder_add!(origin_agent_cluster, OriginAgentCluster);
    builder_add!(referrer_policy, ReferrerPolicy);
    builder_add!(strict_transport_security, StrictTransportSecurity);
    builder_add!(x_content_type_options, XContentTypeOptions);
    builder_add!(x_dns_prefetch_control, XDnsPrefetchControl);
    builder_add!(x_download_options, XDownloadOptions);
    builder_add!(x_frame_options, XFrameOptions);
    builder_add!(x_permitted_cross_domain_policies, XPermittedCrossDomainPolicies);
    builder_add!(x_xss_protection, XXssProtection);
}

impl Default for Sombrero {
    fn default() -> Self {
        Self {
            content_security_policy: Some(Arc::new(ContentSecurityPolicy::strict_default())),
            content_security_policy_report_only: None,
            cross_origin_embedder_policy: None,
            cross_origin_opener_policy: Some(CrossOriginOpenerPolicy::SameOrigin),
            cross_origin_resource_policy: Some(CrossOriginResourcePolicy::SameOrigin),
            origin_agent_cluster: Some(OriginAgentCluster),
            referrer_policy: Some(ReferrerPolicy::NoReferrer),
            strict_transport_security: Some(StrictTransportSecurity::DEFAULT),
            x_content_type_options: Some(XContentTypeOptions),
            x_dns_prefetch_control: None,
            x_download_options: Some(XDownloadOptions),
            x_frame_options: Some(XFrameOptions::Sameorigin),
            x_permitted_cross_domain_policies: Some(XPermittedCrossDomainPolicies::None),
            x_xss_protection: Some(XXssProtection::False),
        }
    }
}

impl<S> Layer<S> for Sombrero {
    type Service = SombreroService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SombreroService {
            sombrero: self.clone(),
            inner,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SombreroService<S> {
    sombrero: Sombrero,
    inner: S,
}

impl<S, Body> Service<Request<Body>> for SombreroService<S>
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
        let nonce = random_string(32);
        let csp = self
            .sombrero
            .content_security_policy
            .as_ref()
            .map(|csp| csp.value(&nonce).expect(BAD_CSP_MESSAGE));
        let csp_ro = self
            .sombrero
            .content_security_policy_report_only
            .as_ref()
            .map(|csp| csp.value(&nonce).expect(BAD_CSP_MESSAGE));
        request.extensions_mut().insert(CspNonce(nonce));

        let future = self.inner.call(request);
        Box::pin(sombrero_svc_middleware(
            self.sombrero.clone(),
            csp,
            csp_ro,
            future,
        ))
    }
}

fn add_opt_header(map: &mut HeaderMap, header: Option<impl Header>) {
    if let Some(header) = header {
        map.insert(header.name(), header.value());
    }
}

fn add_opt_header_raw(
    map: &mut HeaderMap,
    header_name: HeaderName,
    header_value: Option<HeaderValue>,
) {
    if let Some(header_value) = header_value {
        map.insert(header_name, header_value);
    }
}

async fn sombrero_svc_middleware<F, B, E>(
    h: Sombrero,
    content_security_policy: Option<HeaderValue>,
    content_security_policy_report_only: Option<HeaderValue>,
    response_fut: F,
) -> Result<Response<B>, E>
where
    F: Future<Output = Result<Response<B>, E>> + Send,
{
    let mut response = response_fut.await?;
    let m = response.headers_mut();
    add_opt_header_raw(m, CONTENT_SECURITY_POLICY, content_security_policy);
    add_opt_header_raw(
        m,
        CONTENT_SECURITY_POLICY_REPORT_ONLY,
        content_security_policy_report_only,
    );
    add_opt_header(m, h.cross_origin_embedder_policy);
    add_opt_header(m, h.cross_origin_opener_policy);
    add_opt_header(m, h.cross_origin_resource_policy);
    add_opt_header(m, h.origin_agent_cluster);
    add_opt_header(m, h.referrer_policy);
    add_opt_header(m, h.strict_transport_security);
    add_opt_header(m, h.x_content_type_options);
    add_opt_header(m, h.x_dns_prefetch_control);
    add_opt_header(m, h.x_download_options);
    add_opt_header(m, h.x_frame_options);
    add_opt_header(m, h.x_permitted_cross_domain_policies);
    add_opt_header(m, h.x_xss_protection);
    Ok(response)
}

pub async fn middleware_add_raw_header<F, B, E>(
    header_name: HeaderName,
    header_value: HeaderValue,
    response_fut: F,
) -> Result<Response<B>, E>
where
    F: Future<Output = Result<Response<B>, E>> + Send,
{
    let mut response = response_fut.await?;
    response.headers_mut().insert(header_name, header_value);
    Ok(response)
}

pub fn random_string(length: usize) -> String {
    let rng = rand::thread_rng();
    rng.sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(feature = "axum")]
    #[error("`Sombrero` middleware (required for `CspNonce` extractor) not enabled!")]
    NonceMiddlewareNotEnabled(#[from] axum::NonceNotFoundError),
}
