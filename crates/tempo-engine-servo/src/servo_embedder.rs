use std::any::type_name;

use servo::{
    RenderingContext, Servo, ServoBuilder, ServoUrl, WebResourceLoad, WebView, WebViewBuilder,
    WebViewDelegate,
};
use tempo_driver::Unsupported;

use crate::{
    ServoBuildFlavor, ServoEngineConfig, ServoSourcePin, ServoVanillaBuildPlan, Viewport,
    PINNED_VANILLA_SERVO_VERSION,
};

pub(crate) struct VanillaServoEmbedderPlan {
    build_flavor: ServoBuildFlavor,
    source: ServoSourcePin,
    viewport: Viewport,
    user_agent: String,
    access_tree: bool,
    intercept_network: bool,
}

impl VanillaServoEmbedderPlan {
    pub(crate) fn from_config(config: &ServoEngineConfig) -> Result<Self, Unsupported> {
        if config.build_flavor != ServoBuildFlavor::Vanilla {
            return Err(Unsupported(
                "servo-vanilla only accepts a vanilla ServoEngineConfig",
            ));
        }
        Ok(Self {
            build_flavor: config.build_flavor,
            source: ServoSourcePin::vanilla(),
            viewport: config.viewport,
            user_agent: config.user_agent.clone(),
            access_tree: config.access_tree,
            intercept_network: config.intercept_network,
        })
    }

    pub(crate) fn from_tempo_fork_config(config: &ServoEngineConfig) -> Result<Self, Unsupported> {
        if config.build_flavor != ServoBuildFlavor::TempoFork {
            return Err(Unsupported(
                "servo-tempo only accepts a tempo-fork ServoEngineConfig",
            ));
        }
        Ok(Self {
            build_flavor: config.build_flavor,
            source: ServoSourcePin::tempo_fork(),
            viewport: config.viewport,
            user_agent: config.user_agent.clone(),
            access_tree: config.access_tree,
            intercept_network: config.intercept_network,
        })
    }

    fn assert_linked_to_vanilla_embedder_api(&self) {
        let _ = type_name::<Servo>();
        let _ = type_name::<ServoBuilder>();
        let _ = type_name::<ServoUrl>();
        let _ = type_name::<WebResourceLoad>();
        let _ = type_name::<WebView>();
        let _ = type_name::<WebViewBuilder>();
        let _ = type_name::<dyn RenderingContext>();
        let _ = type_name::<dyn WebViewDelegate>();
    }
}

impl From<VanillaServoEmbedderPlan> for ServoVanillaBuildPlan {
    fn from(plan: VanillaServoEmbedderPlan) -> Self {
        plan.assert_linked_to_vanilla_embedder_api();
        Self {
            servo_crate_version: PINNED_VANILLA_SERVO_VERSION.into(),
            build_flavor: plan.build_flavor,
            source: plan.source,
            viewport: plan.viewport,
            user_agent: plan.user_agent,
            access_tree: plan.access_tree,
            intercept_network: plan.intercept_network,
        }
    }
}
