macro_rules! header {
    ($value:literal) => {{
        static GENERATED_HEADER_VALUE: ::http::HeaderValue =
            ::http::HeaderValue::from_static($value);
        GENERATED_HEADER_VALUE.clone()
    }};
}

/// You should probably be using a [`http::header`] constant here.
macro_rules! header_name {
    ($value:literal) => {{
        static GENERATED_HEADER_NAME: ::http::HeaderName = ::http::HeaderName::from_static($value);
        GENERATED_HEADER_NAME.clone()
    }};
}

mod csp;
mod sts;

pub use csp::{ContentSecurityPolicy, CspHashAlgorithm, CspSchemeSource, CspSource};
use http::{
    header::{
        REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_DNS_PREFETCH_CONTROL, X_FRAME_OPTIONS,
        X_XSS_PROTECTION,
    },
    HeaderName, HeaderValue,
};
pub use sts::StrictTransportSecurity;

pub trait Header {
    fn name(&self) -> HeaderName;
    fn value(&self) -> HeaderValue;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum CrossOriginEmbedderPolicy {
    #[default]
    RequireCorp,
    Credentialless,
    UnsafeNone,
}

impl Header for CrossOriginEmbedderPolicy {
    fn name(&self) -> HeaderName {
        header_name!("cross-origin-embedder-policy")
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::RequireCorp => header!("require-corp"),
            Self::Credentialless => header!("credentialless"),
            Self::UnsafeNone => header!("unsafe-none"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum CrossOriginOpenerPolicy {
    #[default]
    SameOrigin,
    SameOriginAllowPopups,
    UnsafeNone,
}

impl Header for CrossOriginOpenerPolicy {
    fn name(&self) -> HeaderName {
        header_name!("cross-origin-opener-policy")
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::SameOrigin => header!("same-origin"),
            Self::SameOriginAllowPopups => header!("same-origin-allow-popups"),
            Self::UnsafeNone => header!("unsafe-none"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum CrossOriginResourcePolicy {
    #[default]
    SameOrigin,
    SameSite,
    CrossOrigin,
}

impl Header for CrossOriginResourcePolicy {
    fn name(&self) -> HeaderName {
        header_name!("cross-origin-resource-policy")
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::SameOrigin => header!("same-origin"),
            Self::SameSite => header!("same-site"),
            Self::CrossOrigin => header!("cross-origin"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct OriginAgentCluster;

impl Header for OriginAgentCluster {
    fn name(&self) -> HeaderName {
        header_name!("origin-agent-cluster")
    }

    fn value(&self) -> HeaderValue {
        header!("?1")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum ReferrerPolicy {
    #[default]
    /// The Referer header will be omitted: sent requests do not include any referrer information.
    NoReferrer,
    /// Send the origin, path, and querystring in Referer when the protocol security level stays the same or improves (HTTP→HTTP, HTTP→HTTPS, HTTPS→HTTPS). Don't send the Referer header for requests to less secure destinations (HTTPS→HTTP, HTTPS→file).
    NoReferrerWhenDowngrade,
    /// Send only the origin in the Referer header. For example, a document at `https://example.com/page.html` will send the referee `https://example.com/`.
    Origin,
    /// When performing a same-origin request to the same protocol level (HTTP→HTTP, HTTPS→HTTPS), send the origin, path, and query string. Send only the origin for cross origin requests and requests to less secure destinations (HTTPS→HTTP).
    OriginWhenCrossOrigin,
    /// Send the origin, path, and query string for same-origin requests. Don't send the Referer header for cross-origin requests.
    SameOrigin,
    /// Send only the origin when the protocol security level stays the same (HTTPS→HTTPS). Don't send the Referer header to less secure destinations (HTTPS→HTTP)
    StrictOrigin,
    /// Send the origin, path, and querystring when performing a same-origin request. For cross-origin requests send the origin (only) when the protocol security level stays same (HTTPS→HTTPS). Don't send the Referer header to less secure destinations (HTTPS→HTTP).
    StrictOriginWhenCrossOrigin,
    /// Send the origin, path, and query string when performing any request, regardless of security.
    UnsafeUrl,
}

impl Header for ReferrerPolicy {
    fn name(&self) -> HeaderName {
        REFERRER_POLICY
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::NoReferrer => header!("no-referrer"),
            Self::NoReferrerWhenDowngrade => header!("no-referrer-when-downgrade"),
            Self::Origin => header!("origin"),
            Self::OriginWhenCrossOrigin => header!("origin-when-cross-origin"),
            Self::SameOrigin => header!("same-origin"),
            Self::StrictOrigin => header!("strict-origin"),
            Self::StrictOriginWhenCrossOrigin => header!("strict-origin-when-cross-origin"),

            Self::UnsafeUrl => header!("unsafe-url"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct XContentTypeOptions;

impl Header for XContentTypeOptions {
    fn name(&self) -> HeaderName {
        X_CONTENT_TYPE_OPTIONS
    }

    fn value(&self) -> HeaderValue {
        header!("nosniff")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum XDnsPrefetchControl {
    On,
    #[default]
    Off,
}

impl Header for XDnsPrefetchControl {
    fn name(&self) -> HeaderName {
        X_DNS_PREFETCH_CONTROL
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::Off => header!("off"),
            Self::On => header!("on"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct XDownloadOptions;

impl Header for XDownloadOptions {
    fn name(&self) -> HeaderName {
        header_name!("x-download-options")
    }

    fn value(&self) -> HeaderValue {
        header!("noopen")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum XFrameOptions {
    Deny,
    #[default]
    Sameorigin,
}

impl Header for XFrameOptions {
    fn name(&self) -> HeaderName {
        X_FRAME_OPTIONS
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::Deny => header!("DENY"),
            Self::Sameorigin => header!("SAMEORIGIN"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum XPermittedCrossDomainPolicies {
    #[default]
    None,
    MasterOnly,
    ByContentType,
    All,
}

impl Header for XPermittedCrossDomainPolicies {
    fn name(&self) -> HeaderName {
        header_name!("x-permitted-cross-domain-policies")
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::None => header!("none"),
            Self::MasterOnly => header!("master-only"),
            Self::ByContentType => header!("by-content-type"),
            Self::All => header!("all"),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum XXssProtection {
    #[default]
    False,
    TrueBlock,
    True,
}

impl Header for XXssProtection {
    fn name(&self) -> HeaderName {
        X_XSS_PROTECTION
    }

    fn value(&self) -> HeaderValue {
        match self {
            Self::TrueBlock => header!("1; mode=block"),
            Self::True => header!("1"),
            Self::False => header!("0"),
        }
    }
}
