//! Challenge / auth-wall detection — **DETECT, never SOLVE** (#244).
//!
//! # Ethical stance (load-bearing, not a comment to delete)
//!
//! CAPTCHA vendors design their challenges for humans, and the good-citizen
//! pattern (OpenAI Operator, Cloudflare Turnstile, hCaptcha's agent rules) is to
//! **pause and hand the wheel to a person** — never to answer the challenge
//! automatically. tempo therefore NEVER integrates a CAPTCHA-solving service, a
//! third-party solving API, or any automated challenge-answering. This module is
//! the *opposite* of a solver: it only *recognises* that a human is required so
//! the act loop can hard-pause. It performs no network I/O, clicks nothing, and
//! answers nothing.
//!
//! # Structure over prose (false-positive discipline)
//!
//! A trigger-happy detector is a bug: every false positive hard-pauses normal
//! automation and demands a human for nothing. So detection keys on **page
//! structure**, not on a word appearing somewhere in body text. Concretely:
//!
//! * **CAPTCHA** requires a *widget*: a vendor name (recaptcha / hcaptcha /
//!   turnstile / cloudflare) on an **embedding** element (iframe / frame / embed
//!   / widget container), or the challenge checkbox itself (`role=checkbox`
//!   named for a vendor or "I'm not a robot"), or a Cloudflare challenge **URL**.
//!   A settings toggle labeled "Enable CAPTCHA protection" or a help link
//!   mentioning reCAPTCHA is *not* a widget and does not fire.
//! * **Auth wall** requires **two corroborating signals**: an access-denial
//!   statement in a *prominent* role (heading / alert / status / banner) **and**
//!   an authenticate path (a sign-in control or a login URL). A help link
//!   "Access Denied — Troubleshooting" or an article that mentions "session
//!   expired" in body text lacks the prominent-role statement and does not fire.
//! * **Login** requires a real credential **input** (password or one-time code)
//!   **and** an authenticate path. A lone "Sign in" nav link (no credential
//!   field) and a change-password settings form (no sign-in path) do not fire.
//!
//! HTTP status (401/403) and script/iframe *origins* would strengthen the auth
//! wall and CAPTCHA signals respectively, but the [`CompiledObservation`] does
//! not carry them today; wiring those in is a follow-up. The classifier stays
//! deliberately conservative (under-fire rather than over-fire) until then.

use tempo_schema::{CompiledObservation, HumanTakeover, InteractiveElement, TakeoverKind};

/// Vendor tokens that name a CAPTCHA widget, most-specific first. Matched only on
/// an embedding element or the challenge checkbox — never on arbitrary prose.
const CAPTCHA_VENDORS: &[(&str, &str)] = &[
    ("recaptcha", "reCAPTCHA challenge widget"),
    ("hcaptcha", "hCaptcha challenge widget"),
    ("turnstile", "Cloudflare Turnstile challenge widget"),
    ("cloudflare", "Cloudflare challenge widget"),
];

/// The reCAPTCHA challenge-checkbox label. Only meaningful on `role=checkbox`.
const ROBOT_PHRASES: &[&str] = &[
    "i'm not a robot",
    "im not a robot",
    "i am not a robot",
    "not a robot",
];

/// URL fragments that are, by themselves, a bot-challenge page.
const CAPTCHA_URL_MARKERS: &[&str] = &[
    "cdn-cgi/challenge",
    "challenges.cloudflare.com",
    "/recaptcha/api",
    "/hcaptcha",
];

/// Access-denial statements. Only fire on a prominent role (see [`is_wall_role`]).
const WALL_PHRASES: &[(&str, &str)] = &[
    ("403 forbidden", "HTTP 403 Forbidden"),
    ("401 unauthorized", "HTTP 401 Unauthorized"),
    ("you are not authorized", "not authorized"),
    ("you do not have permission", "permission denied"),
    ("you don't have permission", "permission denied"),
    ("session has expired", "session expired"),
    ("session expired", "session expired"),
    ("you must be logged in", "login required"),
    ("authentication required", "authentication required"),
    ("access denied", "access denied"),
];

/// URL path fragments that identify a login / SSO endpoint.
const LOGIN_URL_MARKERS: &[&str] = &[
    "/login",
    "/log-in",
    "/signin",
    "/sign-in",
    "/sso",
    "/oauth",
    "/authorize",
    "/session/new",
    "/account/login",
    "/accounts/login",
    "/u/login",
];

/// Credential-input name/value cues.
const PASSWORD_MARKERS: &[&str] = &["password", "passcode"];

/// One-time-code / MFA input name/value cues.
const OTP_MARKERS: &[&str] = &[
    "one-time",
    "one time code",
    "verification code",
    "authentication code",
    "security code",
    "two-factor",
    "2-step",
    " otp",
    "otp ",
    "2fa",
];

/// Sign-in affordance name cues on a button / link. None of these are substrings
/// of "sign out" / "log out" / "sign up", so an authenticated page's sign-out
/// control cannot trigger login detection.
const AFFORDANCE_MARKERS: &[&str] = &[
    "sign in", "signin", "sign-in", "log in", "login", "log-in", "log on", "logon",
];

/// Classify the current observation. Returns the typed hard-pause signal when the
/// page requires a human (CAPTCHA / auth wall / login), else `None`.
///
/// Pure and total: no I/O, no mutation, no panics. A single pass gathers the
/// structural signals; precedence is CAPTCHA > auth wall > login.
pub fn detect_human_takeover(observation: &CompiledObservation) -> Option<HumanTakeover> {
    let url_lc = observation.url.to_lowercase();

    let mut captcha_reason: Option<&'static str> = None;
    let mut wall_reason: Option<&'static str> = None;
    let mut authenticate = false;
    let mut credential: Option<&'static str> = None;

    for element in &observation.elements {
        let role = element.role.to_lowercase();
        let text = element_text_lc(element);

        // CAPTCHA widget: a vendor name on an embedding element, or the challenge
        // checkbox itself. Never on a plain button/link/label.
        if is_embedding_role(&role)
            && let Some(reason) = first_vendor(&text)
        {
            captcha_reason.get_or_insert(reason);
        }
        if is_checkbox_role(&role) {
            if let Some(reason) = first_vendor(&text) {
                captcha_reason.get_or_insert(reason);
            } else if contains_any(&text, ROBOT_PHRASES) {
                captcha_reason.get_or_insert("\"I'm not a robot\" challenge checkbox");
            }
        }

        // Auth-wall statement: only when it sits in a prominent role.
        if is_wall_role(&role)
            && let Some(reason) = first_wall(&text)
        {
            wall_reason.get_or_insert(reason);
        }

        // Authenticate affordance (shared corroborating signal).
        if !authenticate && is_affordance_role(&role) && contains_any(&text, AFFORDANCE_MARKERS) {
            authenticate = true;
        }

        // Credential input.
        if is_input_role(&role) {
            if credential != Some("password") && contains_any(&text, PASSWORD_MARKERS) {
                credential = Some("password");
            } else if credential.is_none() && contains_any(&text, OTP_MARKERS) {
                credential = Some("one-time-code");
            }
        }
    }

    let login_url = contains_any(&url_lc, LOGIN_URL_MARKERS);

    // CAPTCHA (widget structure or a challenge URL).
    if let Some(reason) = captcha_reason {
        return Some(takeover(TakeoverKind::Captcha, reason, observation));
    }
    if contains_any(&url_lc, CAPTCHA_URL_MARKERS) {
        return Some(takeover(
            TakeoverKind::Captcha,
            "Cloudflare challenge page",
            observation,
        ));
    }

    // Auth wall: a prominent access-denial statement AND an authenticate path.
    if let Some(reason) = wall_reason
        && (authenticate || login_url)
    {
        return Some(takeover(
            TakeoverKind::AuthWall,
            format!("{reason} with a sign-in path"),
            observation,
        ));
    }

    // Login: a credential input AND an authenticate path.
    if let Some(cred) = credential
        && (authenticate || login_url)
    {
        let via = match (authenticate, login_url) {
            (true, true) => "sign-in control and login URL",
            (true, false) => "sign-in control",
            (false, true) => "login URL",
            (false, false) => "",
        };
        return Some(takeover(
            TakeoverKind::LoginRequired,
            format!("{cred} field with {via}"),
            observation,
        ));
    }

    None
}

fn takeover(
    kind: TakeoverKind,
    reason: impl Into<String>,
    obs: &CompiledObservation,
) -> HumanTakeover {
    HumanTakeover {
        kind,
        reason: reason.into(),
        url: obs.url.clone(),
    }
}

/// Append an element's lowercased name and value text to `corpus`.
fn push_element_text(corpus: &mut String, element: &InteractiveElement) {
    for span in element.name.iter().chain(element.value.iter()) {
        corpus.push(' ');
        for ch in span.text.chars() {
            corpus.extend(ch.to_lowercase());
        }
    }
}

/// Lowercased name+value text of a single element.
fn element_text_lc(element: &InteractiveElement) -> String {
    let mut text = String::new();
    push_element_text(&mut text, element);
    text
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn first_vendor(text: &str) -> Option<&'static str> {
    CAPTCHA_VENDORS
        .iter()
        .find(|(needle, _)| text.contains(needle))
        .map(|(_, reason)| *reason)
}

fn first_wall(text: &str) -> Option<&'static str> {
    WALL_PHRASES
        .iter()
        .find(|(needle, _)| text.contains(needle))
        .map(|(_, reason)| *reason)
}

/// True for roles that embed a foreign widget (where a CAPTCHA renders).
fn is_embedding_role(role_lc: &str) -> bool {
    ["iframe", "frame", "embed", "group", "region", "widget"]
        .iter()
        .any(|r| role_lc.contains(r))
}

fn is_checkbox_role(role_lc: &str) -> bool {
    role_lc.contains("checkbox")
}

/// True for prominent roles a page-blocking statement would occupy — deliberately
/// NOT link/button/paragraph, so a help link or an article body cannot fire.
fn is_wall_role(role_lc: &str) -> bool {
    ["heading", "alert", "status", "banner", "alertdialog"]
        .iter()
        .any(|r| role_lc.contains(r))
}

/// True for roles that accept text entry (where a password/OTP would live).
fn is_input_role(role_lc: &str) -> bool {
    [
        "textbox",
        "textfield",
        "text field",
        "password",
        "searchbox",
        "combobox",
        "input",
    ]
    .iter()
    .any(|r| role_lc.contains(r))
}

/// True for roles a human would activate to submit credentials.
fn is_affordance_role(role_lc: &str) -> bool {
    ["button", "link", "menuitem"]
        .iter()
        .any(|r| role_lc.contains(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_schema::{NodeId, Provenance, TaintSpan};

    fn obs(url: &str, elements: Vec<InteractiveElement>) -> CompiledObservation {
        CompiledObservation {
            schema_version: tempo_schema::SCHEMA_VERSION.into(),
            url: url.into(),
            seq: 1,
            elements,
            marks: vec![],
        }
    }

    fn element(role: &str, name: &str) -> InteractiveElement {
        InteractiveElement {
            node_id: NodeId(format!("{role}:{name}")),
            role: role.into(),
            name: vec![TaintSpan {
                provenance: Provenance::Page,
                text: name.into(),
            }],
            value: Vec::new(),
            bounds: None,
            rank: 1.0,
        }
    }

    fn detect_kind(o: &CompiledObservation) -> Result<TakeoverKind, String> {
        detect_human_takeover(o)
            .map(|takeover| takeover.kind)
            .ok_or_else(|| "expected a human-takeover detection".to_string())
    }

    // ---- CAPTCHA (widget structure / challenge URL) ----

    #[test]
    fn recaptcha_iframe_is_captcha() -> Result<(), String> {
        let o = obs(
            "https://example.com/checkout",
            vec![
                element("iframe", "reCAPTCHA"),
                element("checkbox", "I'm not a robot"),
            ],
        );
        let t = detect_human_takeover(&o).ok_or("expected detection")?;
        assert_eq!(t.kind, TakeoverKind::Captcha);
        assert_eq!(t.url, "https://example.com/checkout");
        Ok(())
    }

    #[test]
    fn hcaptcha_checkbox_is_captcha() -> Result<(), String> {
        let o = obs(
            "https://example.com",
            vec![element(
                "checkbox",
                "Widget containing checkbox for hCaptcha security challenge",
            )],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::Captcha);
        Ok(())
    }

    #[test]
    fn turnstile_widget_container_is_captcha() -> Result<(), String> {
        let o = obs(
            "https://example.com",
            vec![element(
                "group",
                "Widget containing a Cloudflare Turnstile challenge",
            )],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::Captcha);
        Ok(())
    }

    #[test]
    fn cloudflare_challenge_url_is_captcha() -> Result<(), String> {
        let o = obs(
            "https://site.example/cdn-cgi/challenge-platform/h/b/orchestrate",
            vec![],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::Captcha);
        Ok(())
    }

    // ---- Auth wall (prominent statement + authenticate path) ----

    #[test]
    fn forbidden_heading_with_signin_is_auth_wall() -> Result<(), String> {
        let o = obs(
            "https://api.example/private",
            vec![
                element("heading", "403 Forbidden"),
                element("paragraph", "You do not have access."),
                element("link", "Sign in"),
            ],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::AuthWall);
        Ok(())
    }

    #[test]
    fn session_expired_alert_at_login_url_is_auth_wall() -> Result<(), String> {
        let o = obs(
            "https://app.example/login?returnTo=/dashboard",
            vec![element("alert", "Your session has expired")],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::AuthWall);
        Ok(())
    }

    // ---- Login (credential input + authenticate path) ----

    #[test]
    fn login_form_with_password_and_signin_is_login_required() -> Result<(), String> {
        let o = obs(
            "https://app.example/account/login",
            vec![
                element("textbox", "Email"),
                element("textbox", "Password"),
                element("button", "Sign in"),
            ],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::LoginRequired);
        Ok(())
    }

    #[test]
    fn otp_form_at_login_url_is_login_required() -> Result<(), String> {
        let o = obs(
            "https://app.example/login/challenge",
            vec![
                element("textbox", "Enter the 6-digit verification code"),
                element("button", "Verify"),
            ],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::LoginRequired);
        Ok(())
    }

    #[test]
    fn captcha_takes_precedence_over_login() -> Result<(), String> {
        let o = obs(
            "https://app.example/login",
            vec![
                element("textbox", "Password"),
                element("button", "Sign in"),
                element("iframe", "reCAPTCHA"),
            ],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::Captcha);
        Ok(())
    }

    // ---- false-positive guard: benign pages must NOT flag ----

    #[test]
    fn benign_checkout_page_is_not_flagged() {
        let o = obs(
            "https://shop.example/checkout",
            vec![
                element("textbox", "Card number"),
                element("textbox", "Full name"),
                element("button", "Place order"),
                element("link", "Return to cart"),
            ],
        );
        assert_eq!(detect_human_takeover(&o), None);
    }

    #[test]
    fn lone_signin_nav_link_without_credential_is_not_flagged() {
        // A logged-out marketing homepage: a "Sign in" nav link but no password
        // field and a non-login URL. Must not stall automation.
        let o = obs(
            "https://shop.example/",
            vec![
                element("link", "Sign in"),
                element("link", "Products"),
                element("button", "Add to cart"),
            ],
        );
        assert_eq!(detect_human_takeover(&o), None);
    }

    #[test]
    fn change_password_settings_form_is_not_flagged() {
        // Password fields present, but the affordance is "Save changes" and the
        // URL is a settings page — a legitimate action the agent should perform.
        let o = obs(
            "https://app.example/settings/security",
            vec![
                element("textbox", "Current password"),
                element("textbox", "New password"),
                element("button", "Save changes"),
            ],
        );
        assert_eq!(detect_human_takeover(&o), None);
    }

    #[test]
    fn sign_out_control_does_not_trigger_login() {
        // An authenticated app page with a "Sign out" control and no credential
        // field: the sign-out affordance must not read as a login wall.
        let o = obs(
            "https://app.example/inbox",
            vec![
                element("button", "Sign out"),
                element("link", "Compose"),
                element("textbox", "Search mail"),
            ],
        );
        assert_eq!(detect_human_takeover(&o), None);
    }

    #[test]
    fn enable_captcha_settings_toggle_is_not_flagged() {
        // An admin settings toggle that merely mentions "CAPTCHA": not a widget,
        // not a vendor name, not the challenge checkbox. Must not hard-pause.
        let o = obs(
            "https://app.example/settings/security",
            vec![
                element("checkbox", "Enable CAPTCHA protection"),
                element("switch", "Enable CAPTCHA on signup"),
                element("button", "Save"),
            ],
        );
        assert_eq!(detect_human_takeover(&o), None);
    }

    #[test]
    fn access_denied_help_link_is_not_flagged() {
        // A docs page with a help link whose label contains "Access Denied":
        // a link is not a prominent wall statement, so no auth wall fires.
        let o = obs(
            "https://docs.example/guides",
            vec![
                element("link", "Access Denied — Troubleshooting Guide"),
                element("link", "Sign in"),
                element("heading", "Troubleshooting"),
            ],
        );
        assert_eq!(detect_human_takeover(&o), None);
    }

    #[test]
    fn article_mentioning_session_expired_is_not_flagged() {
        // A blog article whose body text mentions "session expired", with a
        // "Sign in" nav link. Neither the body role nor the nav link is a
        // prominent access-denial statement, so nothing fires.
        let o = obs(
            "https://blog.example/posts/auth-pitfalls",
            vec![
                element("heading", "Common auth pitfalls"),
                element(
                    "paragraph",
                    "Last week my session expired mid-request and I lost data.",
                ),
                element("link", "Sign in"),
                element("link", "Subscribe"),
            ],
        );
        assert_eq!(detect_human_takeover(&o), None);
    }

    #[test]
    fn recaptcha_help_link_is_not_flagged() {
        // A support page linking to reCAPTCHA docs: the vendor name is on a link,
        // not an embedding widget or challenge checkbox, so no CAPTCHA fires.
        let o = obs(
            "https://support.example/articles",
            vec![
                element("link", "How reCAPTCHA protects your account"),
                element("button", "Contact support"),
            ],
        );
        assert_eq!(detect_human_takeover(&o), None);
    }
}
