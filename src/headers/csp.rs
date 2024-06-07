use std::borrow::Cow;

use http::{header::InvalidHeaderValue, HeaderValue};

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentSecurityPolicy {
    // fetch directives
    pub default_src: Vec<CspSource>,
    pub child_src: Vec<CspSource>,
    pub connect_src: Vec<CspSource>,
    pub font_src: Vec<CspSource>,
    pub frame_src: Vec<CspSource>,
    pub img_src: Vec<CspSource>,
    pub manifest_src: Vec<CspSource>,
    pub media_src: Vec<CspSource>,
    pub object_src: Vec<CspSource>,
    pub script_src: Vec<CspSource>,
    pub script_src_elem: Vec<CspSource>,
    pub script_src_attr: Vec<CspSource>,
    pub style_src: Vec<CspSource>,
    pub style_src_elem: Vec<CspSource>,
    pub style_src_attr: Vec<CspSource>,
    pub worker_src: Vec<CspSource>,
    // Document directives
    pub base_uri: Vec<CspSource>,
    pub sandbox: Vec<CspSource>,
    // Navigation directives
    pub form_action: Vec<CspSource>,
    pub frame_ancestors: Vec<CspSource>,
    // Misc
    pub upgrade_insecure_requests: bool,
}

impl ContentSecurityPolicy {
    #[allow(clippy::new_without_default)] // i don't want any footguns around here
    pub fn new() -> Self {
        Self {
            default_src: vec![],
            child_src: vec![],
            connect_src: vec![],
            font_src: vec![],
            frame_src: vec![],
            img_src: vec![],
            manifest_src: vec![],
            media_src: vec![],
            object_src: vec![],
            script_src: vec![],
            script_src_elem: vec![],
            script_src_attr: vec![],
            style_src: vec![],
            style_src_elem: vec![],
            style_src_attr: vec![],
            worker_src: vec![],
            base_uri: vec![],
            sandbox: vec![],
            form_action: vec![],
            frame_ancestors: vec![],
            upgrade_insecure_requests: false,
        }
    }

    pub fn strict_default() -> Self {
        Self {
            default_src: vec![CspSource::SelfOrigin],
            base_uri: vec![CspSource::SelfOrigin],
            font_src: vec![
                CspSource::SelfOrigin,
                CspSource::Scheme(CspSchemeSource::Https),
                CspSource::Scheme(CspSchemeSource::Data),
            ],
            form_action: vec![CspSource::SelfOrigin],
            frame_ancestors: vec![CspSource::SelfOrigin],
            img_src: vec![
                CspSource::SelfOrigin,
                CspSource::Scheme(CspSchemeSource::Data),
            ],
            object_src: vec![CspSource::None],
            script_src: vec![CspSource::SelfOrigin],
            script_src_attr: vec![CspSource::None],
            style_src: vec![
                CspSource::SelfOrigin,
                CspSource::Scheme(CspSchemeSource::Https),
                CspSource::UnsafeInline,
            ],
            upgrade_insecure_requests: true,
            ..Self::new()
        }
    }
}

impl ContentSecurityPolicy {
    pub fn value(&self, nonce: &str) -> Result<HeaderValue, InvalidHeaderValue> {
        let mut output = String::with_capacity(256);
        serialize_header(&mut output, nonce, "default-src", &self.default_src);
        serialize_header(&mut output, nonce, "child-src", &self.child_src);
        serialize_header(&mut output, nonce, "connect-src", &self.connect_src);
        serialize_header(&mut output, nonce, "font-src", &self.font_src);
        serialize_header(&mut output, nonce, "frame-src", &self.frame_src);
        serialize_header(&mut output, nonce, "img-src", &self.img_src);
        serialize_header(&mut output, nonce, "manifest-src", &self.manifest_src);
        serialize_header(&mut output, nonce, "media-src", &self.media_src);
        serialize_header(&mut output, nonce, "object-src", &self.object_src);
        serialize_header(&mut output, nonce, "script-src", &self.script_src);
        serialize_header(&mut output, nonce, "script-src-elem", &self.script_src_elem);
        serialize_header(&mut output, nonce, "script-src-attr", &self.script_src_attr);
        serialize_header(&mut output, nonce, "style-src", &self.style_src);
        serialize_header(&mut output, nonce, "style-src-elem", &self.style_src_elem);
        serialize_header(&mut output, nonce, "style-src-attr", &self.style_src_attr);
        serialize_header(&mut output, nonce, "worker-src", &self.worker_src);
        serialize_header(&mut output, nonce, "base-uri", &self.base_uri);
        serialize_header(&mut output, nonce, "sandbox", &self.sandbox);
        serialize_header(&mut output, nonce, "form-action", &self.form_action);
        serialize_header(&mut output, nonce, "frame-ancestors", &self.frame_ancestors);
        HeaderValue::from_str(output.as_str())
    }
}

impl ContentSecurityPolicy {
    pub fn upgrade_insecure_requests(self, doit: bool) -> Self {
        Self {
            upgrade_insecure_requests: doit,
            ..self
        }
    }
}

macro_rules! csp_builder_add {
    ($id:ident) => {
        #[must_use]
        pub fn $id(
            self,
            new: impl ::std::convert::Into<::std::vec::Vec<$crate::headers::csp::CspSource>>,
        ) -> Self {
            Self {
                $id: ::std::convert::Into::into(new),
                ..self
            }
        }
    };
}

macro_rules! csp_builder_remove {
    ($id:ident, $func:ident) => {
        #[must_use]
        pub fn $func(mut self) -> Self {
            ::std::vec::Vec::clear(&mut self.$id);
            self
        }
    };
}

#[rustfmt::skip]
impl ContentSecurityPolicy { 
    csp_builder_add!(default_src);
    csp_builder_add!(child_src);
    csp_builder_add!(connect_src);
    csp_builder_add!(font_src);
    csp_builder_add!(frame_src);
    csp_builder_add!(img_src);
    csp_builder_add!(manifest_src);
    csp_builder_add!(media_src);
    csp_builder_add!(object_src);
    csp_builder_add!(script_src);
    csp_builder_add!(script_src_elem);
    csp_builder_add!(script_src_attr);
    csp_builder_add!(style_src);
    csp_builder_add!(style_src_elem);
    csp_builder_add!(style_src_attr);
    csp_builder_add!(worker_src);
    csp_builder_add!(base_uri);
    csp_builder_add!(sandbox);
    csp_builder_add!(form_action);
    csp_builder_add!(frame_ancestors);
    csp_builder_remove!(default_src, remove_default_src);
    csp_builder_remove!(child_src, remove_child_src);
    csp_builder_remove!(connect_src, remove_connect_src);
    csp_builder_remove!(font_src, remove_font_src);
    csp_builder_remove!(frame_src, remove_frame_src);
    csp_builder_remove!(img_src, remove_img_src);
    csp_builder_remove!(manifest_src, remove_manifest_src);
    csp_builder_remove!(media_src, remove_media_src);
    csp_builder_remove!(object_src, remove_object_src);
    csp_builder_remove!(script_src, remove_script_src);
    csp_builder_remove!(script_src_elem, remove_script_src_elem);
    csp_builder_remove!(script_src_attr, remove_script_src_attr);
    csp_builder_remove!(style_src, remove_style_src);
    csp_builder_remove!(style_src_elem, remove_style_src_elem);
    csp_builder_remove!(style_src_attr, remove_style_src_attr);
    csp_builder_remove!(worker_src, remove_worker_src);
    csp_builder_remove!(base_uri, remove_base_uri);
    csp_builder_remove!(sandbox, remove_sandbox);
    csp_builder_remove!(form_action, remove_form_action);
    csp_builder_remove!(frame_ancestors, remove_frame_ancestors);
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CspSchemeSource {
    Data,
    Mediastream,
    Blob,
    Filesystem,
    Http,
    Https,
}

impl AsRef<str> for CspSchemeSource {
    fn as_ref(&self) -> &str {
        match self {
            Self::Data => "data:",
            Self::Mediastream => "mediastream:",
            Self::Blob => "blob:",
            Self::Filesystem => "filesystem:",
            Self::Http => "http:",
            Self::Https => "https:",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CspHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Custom(String),
}

impl AsRef<str> for CspHashAlgorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Custom(s) => s.as_ref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CspSource {
    Host(String),
    Scheme(CspSchemeSource),
    /// Nonce has special handling by the library.
    Nonce,
    Hash(CspHashAlgorithm, String),
    /// Self is a keyword in rust, so [`SelfOrigin`] serializes to `'self'` in the header.
    SelfOrigin,
    UnsafeEval,
    WasmUnsafeEval,
    UnsafeHashes,
    UnsafeInline,
    StrictDynamic,
    ReportSample,
    InlineSpeculationRules,
    None,
}

impl CspSource {
    fn as_cow(&self, nonce: &str) -> Cow<'_, str> {
        let borrowed = match self {
            Self::Host(s) => s.as_str(),
            Self::Scheme(s) => s.as_ref(),
            Self::Nonce => return Cow::Owned(format!("'nonce-{nonce}'")),
            Self::Hash(algo, data) => return Cow::Owned(format!("'{}-{data}'", algo.as_ref())),
            Self::SelfOrigin => "'self'",
            Self::UnsafeEval => "'unsafe-eval'",
            Self::WasmUnsafeEval => "'wasm-unsafe-eval'",
            Self::UnsafeHashes => "'unsafe-hashes'",
            Self::UnsafeInline => "'unsafe-inline'",
            Self::StrictDynamic => "'strict-dynamic'",
            Self::ReportSample => "'report-sample'",
            Self::InlineSpeculationRules => "'inline-speculation-rules'",
            Self::None => "'none'",
        };
        Cow::Borrowed(borrowed)
    }
}

fn serialize_header(s: &mut String, nonce: &str, name: &str, sources: &[CspSource]) {
    if sources.is_empty() {
        return;
    }
    s.push_str(name);
    for source in sources {
        s.push(' ');
        s.push_str(source.as_cow(nonce).as_ref());
    }
    s.push(';');
}
