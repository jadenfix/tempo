//! iOS static-library boundary for Tempo's portable core.
//!
//! This crate deliberately excludes process-host and desktop engine crates. The
//! Swift shell owns WKWebView and calls into Rust for schema contracts,
//! observation compilation, policy-facing provenance, and WebView T2 adapter
//! types.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ffi::{c_char, CString};
use tempo_observe::{CompileOptions, ObservationCompiler, ObservationInput};
use tempo_schema::CompiledObservation;
use thiserror::Error;

pub use tempo_engine_webview::{
    WebViewDriver, WebViewElement, WebViewHost, WebViewHostError, WebViewLocator, WebViewSnapshot,
    WEBVIEW_OBSERVATION_SCRIPT,
};

/// Engine lane exposed by the iOS shell.
pub const IOS_ENGINE_LANE: &str = "wkwebview_t2";

/// Static capability summary consumed by Swift at startup and by CI smoke tests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IosCoreCapabilities {
    pub schema_version: String,
    pub engine_lane: String,
    pub static_library: bool,
    pub native_fork: bool,
    pub observation_script_bytes: usize,
    pub desktop_engines_excluded: Vec<String>,
}

impl Default for IosCoreCapabilities {
    fn default() -> Self {
        Self {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            engine_lane: IOS_ENGINE_LANE.into(),
            static_library: true,
            native_fork: false,
            observation_script_bytes: WEBVIEW_OBSERVATION_SCRIPT.len(),
            desktop_engines_excluded: vec![
                "tempo-engine-host".into(),
                "tempo-engine-cdp".into(),
                "tempo-engine-servo".into(),
            ],
        }
    }
}

/// Errors returned by the safe Rust API boundary.
#[derive(Debug, Error)]
pub enum IosCoreError {
    #[error("invalid observation input JSON: {0}")]
    InvalidObservationInput(serde_json::Error),
    #[error("failed to serialize observation JSON: {0}")]
    SerializeObservation(serde_json::Error),
}

/// Stateful observation session for one WKWebView tab.
#[derive(Debug)]
pub struct IosObservationSession {
    compiler: ObservationCompiler,
}

impl IosObservationSession {
    pub fn new() -> Self {
        Self {
            compiler: ObservationCompiler::new(),
        }
    }

    pub fn with_options(options: CompileOptions) -> Self {
        Self {
            compiler: ObservationCompiler::with_options(options),
        }
    }

    pub fn compile(&mut self, input: ObservationInput) -> CompiledObservation {
        self.compiler.compile(input)
    }

    pub fn compile_json(&mut self, input_json: &str) -> Result<String, IosCoreError> {
        let input: ObservationInput =
            serde_json::from_str(input_json).map_err(IosCoreError::InvalidObservationInput)?;
        let observation = self.compile(input);
        serde_json::to_string(&observation).map_err(IosCoreError::SerializeObservation)
    }
}

impl Default for IosObservationSession {
    fn default() -> Self {
        Self::new()
    }
}

pub fn capabilities() -> IosCoreCapabilities {
    IosCoreCapabilities::default()
}

pub fn capabilities_json() -> Result<String, IosCoreError> {
    serde_json::to_string(&capabilities()).map_err(IosCoreError::SerializeObservation)
}

pub fn observation_script() -> &'static str {
    WEBVIEW_OBSERVATION_SCRIPT
}

pub fn compile_observation_json(input_json: &str) -> Result<String, IosCoreError> {
    IosObservationSession::new().compile_json(input_json)
}

pub fn describe() -> &'static str {
    "iOS staticlib core for WKWebView T2: schema, observation compiler, policy-safe provenance, and WebView adapter types"
}

/// Parse a JSON value emitted by the Swift bridge without losing the safe Rust
/// error boundary. This is intentionally small until the C/Swift ABI layer is
/// generated in a dedicated FFI slice.
pub fn parse_bridge_json(value: &str) -> Result<Value, IosCoreError> {
    serde_json::from_str(value).map_err(IosCoreError::InvalidObservationInput)
}

#[unsafe(no_mangle)]
pub extern "C" fn tempo_ios_core_capabilities_json() -> *mut c_char {
    match capabilities_json()
        .ok()
        .and_then(|json| CString::new(json).ok())
    {
        Some(json) => json.into_raw(),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn tempo_ios_core_observation_script() -> *mut c_char {
    match CString::new(observation_script()) {
        Ok(script) => script.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// `value` must be either null or a pointer previously returned by a
/// Rust-to-NSString bridge allocation in this crate, and must not have been freed
/// before this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tempo_ios_core_string_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_observe::RawElement;
    use tempo_schema::Provenance;

    #[test]
    fn capabilities_name_wkwebview_lane_and_exclusions() {
        let capabilities = capabilities();

        assert_eq!(capabilities.schema_version, tempo_schema::SCHEMA_VERSION);
        assert_eq!(capabilities.engine_lane, IOS_ENGINE_LANE);
        assert!(capabilities.static_library);
        assert!(!capabilities.native_fork);
        assert!(capabilities.observation_script_bytes > 0);
        assert!(capabilities
            .desktop_engines_excluded
            .contains(&"tempo-engine-host".to_string()));
    }

    #[test]
    fn compile_observation_json_uses_page_taint() -> Result<(), Box<dyn std::error::Error>> {
        let input = ObservationInput::new(
            "https://example.com",
            vec![RawElement::new("button", "Continue").stable_hint("continue")],
        );
        let input_json = serde_json::to_string(&input)?;

        let output = compile_observation_json(&input_json)?;
        let observation: CompiledObservation = serde_json::from_str(&output)?;

        assert_eq!(observation.schema_version, tempo_schema::SCHEMA_VERSION);
        assert_eq!(observation.elements.len(), 1);
        assert_eq!(observation.elements[0].name[0].provenance, Provenance::Page);
        Ok(())
    }

    #[test]
    fn manifest_does_not_directly_reference_desktop_engine_crates() {
        let manifest = include_str!("../Cargo.toml");

        for blocked in [
            "tempo-engine-host",
            "tempo-engine-cdp",
            "tempo-engine-servo",
            "tempo-headless",
            "tempo-shell",
            "tempo-cli",
        ] {
            assert!(
                !manifest.contains(blocked),
                "iOS core manifest must not depend on {blocked}"
            );
        }
    }

    #[test]
    fn bundled_observation_script_has_collector_entrypoint() {
        assert!(observation_script().contains("__tempoCollectObservation"));
    }

    #[test]
    fn c_abi_exports_capabilities_json_string() -> Result<(), Box<dyn std::error::Error>> {
        let ptr = tempo_ios_core_capabilities_json();
        assert!(!ptr.is_null());
        let text = unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()?
            .to_string();
        unsafe { tempo_ios_core_string_free(ptr) };

        let value: serde_json::Value = serde_json::from_str(&text)?;
        assert_eq!(value["engine_lane"], IOS_ENGINE_LANE);
        Ok(())
    }

    #[test]
    fn c_abi_exports_observation_script_string() -> Result<(), Box<dyn std::error::Error>> {
        let ptr = tempo_ios_core_observation_script();
        assert!(!ptr.is_null());
        let text = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str()?;
        assert!(text.contains("__tempoCollectObservation"));
        unsafe { tempo_ios_core_string_free(ptr) };
        Ok(())
    }
}
