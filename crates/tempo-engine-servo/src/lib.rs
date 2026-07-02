//! tempo-engine-servo — typed boundary for the Servo-backed engine lane.
//!
//! This crate keeps embedding details private to the engine lane. Public APIs use
//! tempo contracts only: semantic actions, stable node ids, network interception
//! records, screenshot requests, and capability flags.

use serde::{Deserialize, Serialize};
use tempo_driver::Unsupported;
use tempo_schema::{Action, NodeId};
use thiserror::Error;

/// Which Servo build is backing this engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServoBuildFlavor {
    Vanilla,
    TempoFork,
}

/// Engine-side viewport in CSS pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 720,
        }
    }
}

/// Configuration required before spawning a Servo-backed page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoEngineConfig {
    pub build_flavor: ServoBuildFlavor,
    pub viewport: Viewport,
    pub user_agent: String,
    pub access_tree: bool,
    pub intercept_network: bool,
}

impl ServoEngineConfig {
    pub fn vanilla() -> Self {
        Self {
            build_flavor: ServoBuildFlavor::Vanilla,
            viewport: Viewport::default(),
            user_agent: "tempo-servo/0.1".into(),
            access_tree: true,
            intercept_network: true,
        }
    }

    pub fn tempo_fork() -> Self {
        Self {
            build_flavor: ServoBuildFlavor::TempoFork,
            ..Self::vanilla()
        }
    }

    pub fn native_fork(&self) -> Result<(), Unsupported> {
        match self.build_flavor {
            ServoBuildFlavor::TempoFork => Ok(()),
            ServoBuildFlavor::Vanilla => Err(Unsupported("native servo fork requires tempo fork")),
        }
    }
}

/// Engine command sent to the private Servo embedder.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServoEmbedderCommand {
    LoadUrl {
        url: String,
    },
    ActivateNode {
        node: NodeId,
    },
    TypeText {
        node: NodeId,
        text: String,
    },
    SelectValue {
        node: NodeId,
        value: String,
    },
    Scroll {
        x: f32,
        y: f32,
    },
    ExtractNode {
        node: NodeId,
    },
    InvokeSkill {
        name: String,
        input: serde_json::Value,
    },
    CaptureScreenshot {
        format: ScreenshotFormat,
    },
    Close,
}

impl ServoEmbedderCommand {
    pub fn from_action(action: Action) -> Self {
        match action {
            Action::Goto { url } => Self::LoadUrl { url },
            Action::Click { node } => Self::ActivateNode { node },
            Action::Type { node, text } => Self::TypeText { node, text },
            Action::Select { node, value } => Self::SelectValue { node, value },
            Action::Scroll { x, y } => Self::Scroll { x, y },
            Action::Extract { node } => Self::ExtractNode { node },
            Action::Skill { name, input } => Self::InvokeSkill { name, input },
        }
    }
}

/// Screenshot format requested from the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotFormat {
    Png,
}

/// Request intercepted at the engine boundary before it reaches the network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoNetworkRequest {
    pub request_id: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body_len: u64,
}

/// Response returned to the engine after tempo-net policy/signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoNetworkResponse {
    pub request_id: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Engine readiness gates that must be satisfied before a page is agent-drivable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServoReadiness {
    pub loaded: bool,
    pub access_tree_ready: bool,
    pub network_idle: bool,
}

impl ServoReadiness {
    pub fn agent_drivable(&self) -> bool {
        self.loaded && self.access_tree_ready && self.network_idle
    }
}

/// Guard used by CI to prove public signatures stay free of private embedder type names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicApiGuard {
    denied_fragments: Vec<&'static str>,
}

impl PublicApiGuard {
    pub fn servo_private_type_guard() -> Self {
        Self {
            denied_fragments: vec![
                "WebView",
                "WebViewDelegate",
                "RenderingContext",
                "Constellation",
            ],
        }
    }

    pub fn check_symbols<'a>(
        &self,
        symbols: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), ServoEngineError> {
        for symbol in symbols {
            if symbol.starts_with("servo::") || symbol.contains("::servo::") {
                return Err(ServoEngineError::PrivateTypeLeaked {
                    symbol: symbol.into(),
                    fragment: "servo::",
                });
            }
            if let Some(fragment) = self
                .denied_fragments
                .iter()
                .find(|fragment| symbol.contains(**fragment))
            {
                return Err(ServoEngineError::PrivateTypeLeaked {
                    symbol: symbol.into(),
                    fragment,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ServoEngineError {
    #[error("private Servo type leaked through public API: {symbol} contains {fragment}")]
    PrivateTypeLeaked {
        symbol: String,
        fragment: &'static str,
    },
}

/// Human-readable crate summary.
pub fn describe() -> &'static str {
    "Servo engine boundary types, action translation, network interception records, and capability gates"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vanilla_config_enables_access_tree_and_network_interception() {
        let config = ServoEngineConfig::vanilla();

        assert_eq!(config.build_flavor, ServoBuildFlavor::Vanilla);
        assert_eq!(config.viewport, Viewport::default());
        assert!(config.access_tree);
        assert!(config.intercept_network);
    }

    #[test]
    fn native_fork_requires_tempo_fork_build() {
        let vanilla = ServoEngineConfig::vanilla();
        let fork = ServoEngineConfig::tempo_fork();

        assert!(vanilla.native_fork().is_err());
        assert!(fork.native_fork().is_ok());
    }

    #[test]
    fn semantic_actions_translate_to_embedder_commands() {
        let commands = vec![
            ServoEmbedderCommand::from_action(Action::Goto {
                url: "https://example.test".into(),
            }),
            ServoEmbedderCommand::from_action(Action::Click {
                node: NodeId("button".into()),
            }),
            ServoEmbedderCommand::from_action(Action::Type {
                node: NodeId("input".into()),
                text: "hello".into(),
            }),
            ServoEmbedderCommand::from_action(Action::Scroll { x: 0.0, y: 12.0 }),
        ];

        assert_eq!(
            commands,
            vec![
                ServoEmbedderCommand::LoadUrl {
                    url: "https://example.test".into(),
                },
                ServoEmbedderCommand::ActivateNode {
                    node: NodeId("button".into()),
                },
                ServoEmbedderCommand::TypeText {
                    node: NodeId("input".into()),
                    text: "hello".into(),
                },
                ServoEmbedderCommand::Scroll { x: 0.0, y: 12.0 },
            ]
        );
    }

    #[test]
    fn readiness_requires_load_access_tree_and_network_idle() {
        assert!(ServoReadiness {
            loaded: true,
            access_tree_ready: true,
            network_idle: true,
        }
        .agent_drivable());

        assert!(!ServoReadiness {
            loaded: true,
            access_tree_ready: false,
            network_idle: true,
        }
        .agent_drivable());
    }

    #[test]
    fn public_api_guard_rejects_private_embedder_types() {
        let guard = PublicApiGuard::servo_private_type_guard();

        assert!(guard
            .check_symbols([
                "tempo_engine_servo::ServoEngineConfig",
                "tempo_engine_servo::ServoEmbedderCommand",
            ])
            .is_ok());
        assert!(matches!(
            guard.check_symbols(["tempo_engine_servo::WebViewDelegateHandle"]),
            Err(ServoEngineError::PrivateTypeLeaked { .. })
        ));
    }

    #[test]
    fn network_interception_records_request_and_response_bytes() {
        let request = ServoNetworkRequest {
            request_id: "req-1".into(),
            method: "GET".into(),
            url: "https://example.test/data".into(),
            headers: vec![("accept".into(), "application/json".into())],
            body_len: 0,
        };
        let response = ServoNetworkResponse {
            request_id: request.request_id.clone(),
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: br#"{"ok":true}"#.to_vec(),
        };

        assert_eq!(request.request_id, response.request_id);
        assert_eq!(response.body, br#"{"ok":true}"#.to_vec());
    }
}
