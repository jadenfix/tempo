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
//! # What this is
//!
//! A pure, total classifier over a [`CompiledObservation`]. Given the current
//! page's taint-labeled interactive elements and URL, it returns
//! `Some(HumanTakeover)` when the page is a CAPTCHA / bot challenge, an access
//! wall (401/403/session-expired), or a login / one-time-code form — otherwise
//! `None`. The false-positive guard is critical: a trigger-happy detector would
//! stall normal automation, so login detection requires an actual credential
//! field plus a sign-in affordance (a lone "Sign in" nav link or a
//! change-password settings form does not fire).

use tempo_schema::{CompiledObservation, HumanTakeover, InteractiveElement, TakeoverKind};

/// Well-known CAPTCHA / bot-challenge markers, matched as lowercase substrings of
/// the page URL or any interactive element's name/value. Ordered most-specific
/// first so the reason names the vendor before the generic `captcha` fallback.
const CAPTCHA_MARKERS: &[(&str, &str)] = &[
    ("recaptcha", "reCAPTCHA challenge widget"),
    ("hcaptcha", "hCaptcha challenge widget"),
    ("turnstile", "Cloudflare Turnstile challenge widget"),
    ("cdn-cgi/challenge", "Cloudflare challenge page"),
    (
        "cloudflare security challenge",
        "Cloudflare security challenge",
    ),
    ("checking your browser", "Cloudflare interstitial challenge"),
    ("i'm not a robot", "\"I'm not a robot\" challenge checkbox"),
    ("im not a robot", "\"I'm not a robot\" challenge checkbox"),
    ("i am not a robot", "\"I'm not a robot\" challenge checkbox"),
    ("verify you are human", "\"verify you are human\" challenge"),
    ("captcha", "CAPTCHA challenge widget"),
];

/// Access-wall text cues, matched as lowercase substrings of the URL or any
/// element's name/value. Ordered most-specific first.
const AUTH_WALL_MARKERS: &[(&str, &str)] = &[
    ("403 forbidden", "HTTP 403 Forbidden"),
    ("401 unauthorized", "HTTP 401 Unauthorized"),
    ("session has expired", "session expired"),
    ("session expired", "session expired"),
    ("access denied", "access denied"),
    ("you are not authorized", "not authorized"),
    ("you do not have permission", "permission denied"),
    ("you don't have permission", "permission denied"),
    ("authentication required", "authentication required"),
    ("you must be logged in", "login-required auth wall"),
    ("please log in to continue", "login-required auth wall"),
    ("please sign in to continue", "login-required auth wall"),
    ("unauthorized", "unauthorized"),
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
/// Pure and total: no I/O, no mutation, no panics.
pub fn detect_human_takeover(observation: &CompiledObservation) -> Option<HumanTakeover> {
    // Substring corpus for the CAPTCHA and auth-wall markers: the URL plus every
    // interactive element's taint-labeled name/value text, lowercased once.
    let mut corpus = observation.url.to_lowercase();
    for element in &observation.elements {
        corpus.push(' ');
        push_element_text(&mut corpus, element);
    }

    if let Some(reason) = first_marker(&corpus, CAPTCHA_MARKERS) {
        return Some(takeover(TakeoverKind::Captcha, reason, observation));
    }
    if let Some(reason) = first_marker(&corpus, AUTH_WALL_MARKERS) {
        return Some(takeover(TakeoverKind::AuthWall, reason, observation));
    }
    if let Some(reason) = login_reason(&observation.url.to_lowercase(), &observation.elements) {
        return Some(takeover(TakeoverKind::LoginRequired, reason, observation));
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

fn first_marker(corpus: &str, markers: &[(&str, &'static str)]) -> Option<&'static str> {
    markers
        .iter()
        .find(|(needle, _)| corpus.contains(needle))
        .map(|(_, reason)| *reason)
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
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

/// Detect a login / OTP credential wall.
///
/// Requires a credential *input* (password or one-time-code) **and** a sign-in
/// affordance or a login URL. This two-signal rule is the false-positive guard:
/// a change-password settings form (password field, but a "Save" button and a
/// non-login URL) and a marketing page with a lone "Sign in" link (affordance,
/// but no credential field) both fail it.
fn login_reason(url_lc: &str, elements: &[InteractiveElement]) -> Option<String> {
    let mut credential: Option<&'static str> = None;
    let mut has_affordance = false;

    for element in elements {
        let role = element.role.to_lowercase();
        if is_input_role(&role) {
            let text = element_text_lc(element);
            if credential != Some("password") && contains_any(&text, PASSWORD_MARKERS) {
                credential = Some("password");
            } else if credential.is_none() && contains_any(&text, OTP_MARKERS) {
                credential = Some("one-time-code");
            }
        }
        if !has_affordance && is_affordance_role(&role) {
            let text = element_text_lc(element);
            if contains_any(&text, AFFORDANCE_MARKERS) {
                has_affordance = true;
            }
        }
    }

    let login_url = contains_any(url_lc, LOGIN_URL_MARKERS);
    let credential = credential?;
    if !(has_affordance || login_url) {
        return None;
    }
    let via = match (has_affordance, login_url) {
        (true, true) => "sign-in control and login URL",
        (true, false) => "sign-in control",
        (false, true) => "login URL",
        (false, false) => unreachable!(),
    };
    Some(format!("{credential} field with {via}"))
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
    fn hcaptcha_widget_is_captcha() -> Result<(), String> {
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
    fn turnstile_widget_is_captcha() -> Result<(), String> {
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

    #[test]
    fn forbidden_text_is_auth_wall() -> Result<(), String> {
        let o = obs(
            "https://api.example/private",
            vec![
                element("heading", "403 Forbidden"),
                element("paragraph", "Access denied"),
            ],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::AuthWall);
        Ok(())
    }

    #[test]
    fn session_expired_is_auth_wall() -> Result<(), String> {
        let o = obs(
            "https://app.example/dashboard",
            vec![element("heading", "Your session has expired")],
        );
        assert_eq!(detect_kind(&o)?, TakeoverKind::AuthWall);
        Ok(())
    }

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
    fn captcha_takes_precedence_over_login() -> Result<(), String> {
        // A login page that also presents a CAPTCHA: the CAPTCHA is the blocking
        // challenge, so it wins.
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
}
