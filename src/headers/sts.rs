use http::{header::STRICT_TRANSPORT_SECURITY, HeaderName, HeaderValue};

use crate::headers::Header;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct StrictTransportSecurity {
    pub include_sub_domains: bool,
    pub max_age: usize,
}

impl StrictTransportSecurity {
    pub const DEFAULT: Self = Self {
        include_sub_domains: true,
        max_age: Self::STS_MAX_AGE,
    };
    const STS_MAX_AGE: usize = 180 * 24 * 60 * 60;

    /// sets the TTL in seconds that this policy will be enforced
    pub const fn max_age(self, max_age: usize) -> Self {
        Self { max_age, ..self }
    }

    /// Enables or disables the includeSubDomains directive
    pub const fn include_sub_domains(self, include_sub_domains: bool) -> Self {
        Self {
            include_sub_domains,
            ..self
        }
    }
}

impl Default for StrictTransportSecurity {
    fn default() -> Self {
        Self::DEFAULT
    }
}

static DEFAULT_HEADERIZED: HeaderValue =
    HeaderValue::from_static("max-age=15552000;includeSubDomains");

impl StrictTransportSecurity {
    /// This function removes a minor optimization. It exists so it can be tested to be exactly
    /// equal to the optimized version.
    fn raw_value(&self) -> HeaderValue {
        let subdomain_flag = if self.include_sub_domains {
            ";includeSubDomains"
        } else {
            ""
        };
        let raw_header = format!("max-age={}{subdomain_flag}", self.max_age);
        match HeaderValue::from_str(&raw_header) {
            Ok(val) => val,
            Err(source) => {
                panic!(
                    "Failed to convert HTTP Strict Transport Security string `{raw_header}` to header: `{source:?}`",
                );
            }
        }
    }
}

impl Header for StrictTransportSecurity {
    fn name(&self) -> HeaderName {
        STRICT_TRANSPORT_SECURITY
    }

    fn value(&self) -> HeaderValue {
        if *self == Self::DEFAULT {
            return DEFAULT_HEADERIZED.clone();
        }
        self.raw_value()
    }
}

#[cfg(test)]
#[test]
fn sts_default_matches() {
    const DEFAULT: StrictTransportSecurity = StrictTransportSecurity::DEFAULT;
    assert_eq!(DEFAULT.raw_value(), DEFAULT.value());
}
