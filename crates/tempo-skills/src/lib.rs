//! tempo-skills — persisted macro-actions and deterministic skill expansion.
//!
//! Skills are parameterized procedures stored as JSON files. Runtime callers load a
//! definition from the store, provide input values, and receive a concrete `ActionBatch`
//! that can be handed to `tempo-act` or a driver.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempo_schema::{Action, ActionBatch, NodeId, QuiescencePolicy, SideEffect};
use tempo_telemetry::{logger, Level};
use thiserror::Error;

/// Stored skill definition. The `(name, version)` pair is the stable key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillDefinition {
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default = "default_skill_side_effect")]
    pub side_effect: SideEffect,
    #[serde(default)]
    pub inputs: Vec<SkillInput>,
    pub quiescence: QuiescencePolicy,
    pub steps: Vec<ActionTemplate>,
}

const fn default_skill_side_effect() -> SideEffect {
    SideEffect::Write
}

impl SkillDefinition {
    pub fn key(&self) -> SkillKey {
        SkillKey {
            name: self.name.clone(),
            version: self.version.clone(),
        }
    }

    pub fn metadata(&self) -> Result<SkillMetadata, SkillError> {
        validate_definition(self)?;
        let required_inputs = self.inputs.iter().filter(|input| input.required).count();
        Ok(SkillMetadata {
            key: self.key(),
            description: self.description.clone(),
            side_effect: self.side_effect,
            inputs: self.inputs.clone(),
            quiescence: self.quiescence,
            step_count: self.steps.len(),
            required_inputs,
            optional_inputs: self.inputs.len().saturating_sub(required_inputs),
        })
    }

    pub fn compile(&self, input: &Value) -> Result<ActionBatch, SkillError> {
        validate_definition(self)?;
        let bindings = InputBindings::new(&self.inputs, input)?;
        let mut actions = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            actions.push(step.render(&bindings)?);
        }
        Ok(ActionBatch {
            actions,
            quiescence: self.quiescence,
        })
    }
}

/// Stable skill key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SkillKey {
    pub name: String,
    pub version: String,
}

/// Catalog metadata exposed to runtime/policy surfaces without expanding a skill.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SkillMetadata {
    pub key: SkillKey,
    pub description: String,
    pub side_effect: SideEffect,
    pub inputs: Vec<SkillInput>,
    pub quiescence: QuiescencePolicy,
    pub step_count: usize,
    pub required_inputs: usize,
    pub optional_inputs: usize,
}

/// One named input a skill requires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillInput {
    pub name: String,
    pub required: bool,
}

impl SkillInput {
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: true,
        }
    }

    pub fn optional(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: false,
        }
    }
}

/// String interpolation surface. Only whole-field parameters are supported; this keeps
/// expansion deterministic and prevents accidental prompt-style substitution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TemplateString {
    Literal { value: String },
    Param { name: String },
}

impl TemplateString {
    pub fn literal(value: impl Into<String>) -> Self {
        Self::Literal {
            value: value.into(),
        }
    }

    pub fn param(name: impl Into<String>) -> Self {
        Self::Param { name: name.into() }
    }

    fn render(&self, bindings: &InputBindings) -> Result<String, SkillError> {
        match self {
            Self::Literal { value } => Ok(value.clone()),
            Self::Param { name } => bindings.string(name),
        }
    }

    fn referenced_params(&self, params: &mut BTreeSet<String>) {
        if let Self::Param { name } = self {
            params.insert(name.clone());
        }
    }
}

/// Parameterized action shape.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionTemplate {
    Goto {
        url: TemplateString,
    },
    Click {
        node: TemplateString,
    },
    Type {
        node: TemplateString,
        text: TemplateString,
    },
    Select {
        node: TemplateString,
        value: TemplateString,
    },
    Scroll {
        x: f32,
        y: f32,
    },
    Extract {
        node: TemplateString,
    },
    Skill {
        name: TemplateString,
        input: Value,
    },
}

impl ActionTemplate {
    fn render(&self, bindings: &InputBindings) -> Result<Action, SkillError> {
        match self {
            Self::Goto { url } => Ok(Action::Goto {
                url: url.render(bindings)?,
            }),
            Self::Click { node } => Ok(Action::Click {
                node: NodeId(node.render(bindings)?),
            }),
            Self::Type { node, text } => Ok(Action::Type {
                node: NodeId(node.render(bindings)?),
                text: text.render(bindings)?,
            }),
            Self::Select { node, value } => Ok(Action::Select {
                node: NodeId(node.render(bindings)?),
                value: value.render(bindings)?,
            }),
            Self::Scroll { x, y } => Ok(Action::Scroll { x: *x, y: *y }),
            Self::Extract { node } => Ok(Action::Extract {
                node: NodeId(node.render(bindings)?),
            }),
            Self::Skill { name, input } => Ok(Action::Skill {
                name: name.render(bindings)?,
                input: input.clone(),
            }),
        }
    }

    fn referenced_params(&self, params: &mut BTreeSet<String>) {
        match self {
            Self::Goto { url } => url.referenced_params(params),
            Self::Click { node } | Self::Extract { node } => node.referenced_params(params),
            Self::Type { node, text } => {
                node.referenced_params(params);
                text.referenced_params(params);
            }
            Self::Select { node, value } => {
                node.referenced_params(params);
                value.referenced_params(params);
            }
            Self::Scroll { .. } => {}
            Self::Skill { name, .. } => name.referenced_params(params),
        }
    }

    const fn minimum_side_effect(&self) -> SideEffect {
        match self {
            Self::Goto { .. } | Self::Scroll { .. } | Self::Extract { .. } => SideEffect::Read,
            Self::Click { .. } | Self::Type { .. } | Self::Select { .. } | Self::Skill { .. } => {
                SideEffect::Write
            }
        }
    }
}

/// Directory-backed skill store.
pub struct SkillStore {
    root: PathBuf,
}

impl SkillStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SkillError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn put(&self, definition: &SkillDefinition) -> Result<(), SkillError> {
        validate_definition(definition)?;
        let path = self.path_for(&definition.key())?;
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(definition)?;

        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.flush()?;
            file.sync_data()?;
        }

        std::fs::rename(&tmp, &path)?;
        sync_parent(&path)?;
        Ok(())
    }

    pub fn get(&self, key: &SkillKey) -> Result<SkillDefinition, SkillError> {
        let path = self.path_for(key)?;
        let mut file = File::open(&path).map_err(|source| SkillError::OpenSkill {
            path: path.clone(),
            source,
        })?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let definition = serde_json::from_slice(&bytes)?;
        validate_definition(&definition)?;
        Ok(definition)
    }

    pub fn compile(&self, key: &SkillKey, input: &Value) -> Result<ActionBatch, SkillError> {
        self.get(key)?.compile(input)
    }

    pub fn catalog(&self) -> Result<Vec<SkillMetadata>, SkillError> {
        let defs = self.all_definitions()?;
        let mut entries = Vec::with_capacity(defs.len());
        for (path, def) in defs {
            match def.metadata() {
                Ok(meta) => entries.push(meta),
                Err(err) => {
                    logger()
                        .event(Level::Warn, "tempo-skills", "skipping malformed skill file")
                        .field("path", path.display().to_string())
                        .field("error", err.to_string())
                        .emit();
                }
            }
        }
        entries.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(entries)
    }

    pub fn resolve(&self, name: &str) -> Result<SkillKey, SkillError> {
        safe_segment(name)?;
        self.list()?
            .into_iter()
            .filter(|key| key.name == name)
            .max_by(|a, b| compare_versions(&a.version, &b.version))
            .ok_or_else(|| SkillError::SkillNotFound(name.to_string()))
    }

    pub fn list(&self) -> Result<Vec<SkillKey>, SkillError> {
        let mut keys: Vec<SkillKey> = self
            .all_definitions()?
            .into_iter()
            .map(|(_, def)| def.key())
            .collect();
        keys.sort();
        Ok(keys)
    }

    /// Walk the skills directory once, parse every `*.json` file into a
    /// [`SkillDefinition`], and return the successful results.
    ///
    /// IO errors (e.g. permission denied on `File::open`) propagate immediately
    /// because they indicate an environmental problem rather than a bad skill
    /// file.  Parse and validation errors are logged as structured Warn events
    /// and the offending file is skipped so one malformed entry never prevents
    /// valid skills from being enumerated.
    fn all_definitions(&self) -> Result<Vec<(PathBuf, SkillDefinition)>, SkillError> {
        let mut defs = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let path = entry.path();
            if !is_skill_json_file(&entry, &path)? {
                continue;
            }
            match Self::load_definition(&path) {
                Ok(def) => defs.push((path, def)),
                Err(err @ (SkillError::Io(_) | SkillError::OpenSkill { .. })) => return Err(err),
                Err(err) => {
                    logger()
                        .event(Level::Warn, "tempo-skills", "skipping malformed skill file")
                        .field("path", path.display().to_string())
                        .field("error", err.to_string())
                        .emit();
                }
            }
        }
        Ok(defs)
    }

    fn load_definition(path: &Path) -> Result<SkillDefinition, SkillError> {
        let mut file = File::open(path).map_err(|source| SkillError::OpenSkill {
            path: path.to_path_buf(),
            source,
        })?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let definition: SkillDefinition = serde_json::from_slice(&bytes)?;
        validate_definition(&definition)?;
        Ok(definition)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, key: &SkillKey) -> Result<PathBuf, SkillError> {
        Ok(self.root.join(format!(
            "{}@{}.json",
            safe_segment(&key.name)?,
            safe_segment(&key.version)?
        )))
    }
}

fn is_skill_json_file(entry: &std::fs::DirEntry, path: &Path) -> Result<bool, SkillError> {
    Ok(entry.file_type()?.is_file()
        && path
            .extension()
            .is_some_and(|extension| extension == "json"))
}

#[derive(Debug, Error)]
pub enum SkillError {
    #[error("skill io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("skill serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("could not open skill file {path}: {source}")]
    OpenSkill {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid skill key segment: {0}")]
    InvalidKeySegment(String),
    #[error("duplicate input: {0}")]
    DuplicateInput(String),
    #[error("missing required input: {0}")]
    MissingInput(String),
    #[error("input {0} must be a string, number, boolean, or null")]
    UnsupportedInputValue(String),
    #[error("step references undeclared input: {0}")]
    UndeclaredInput(String),
    #[error("skill must contain at least one step")]
    EmptySkill,
    #[error("skill side effect {declared:?} does not cover direct step side effect {required:?}")]
    SkillSideEffectUndercovers {
        declared: SideEffect,
        required: SideEffect,
    },
    #[error("skill not found: {0}")]
    SkillNotFound(String),
}

fn validate_definition(definition: &SkillDefinition) -> Result<(), SkillError> {
    safe_segment(&definition.name)?;
    safe_segment(&definition.version)?;
    if definition.steps.is_empty() {
        return Err(SkillError::EmptySkill);
    }

    let mut declared = BTreeSet::new();
    for input in &definition.inputs {
        safe_segment(&input.name)?;
        if !declared.insert(input.name.clone()) {
            return Err(SkillError::DuplicateInput(input.name.clone()));
        }
    }

    let mut referenced = BTreeSet::new();
    let mut required_side_effect = SideEffect::Read;
    for step in &definition.steps {
        step.referenced_params(&mut referenced);
        required_side_effect = required_side_effect.max(step.minimum_side_effect());
    }

    if definition.side_effect < required_side_effect {
        return Err(SkillError::SkillSideEffectUndercovers {
            declared: definition.side_effect,
            required: required_side_effect,
        });
    }

    for param in referenced {
        if !declared.contains(&param) {
            return Err(SkillError::UndeclaredInput(param));
        }
    }

    Ok(())
}

fn safe_segment(segment: &str) -> Result<&str, SkillError> {
    let valid = !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(segment)
    } else {
        Err(SkillError::InvalidKeySegment(segment.to_string()))
    }
}

/// Compare two skill version strings by semantic precedence rather than lexically, so
/// that e.g. `"10"` ranks above `"9"`. A version is split into `.`/`_`-separated release
/// parts and an optional `-`-delimited pre-release; numeric parts compare numerically,
/// and a plain release outranks any pre-release sharing the same release parts.
fn compare_versions(a: &str, b: &str) -> Ordering {
    let (a_release, a_pre) = split_version(a);
    let (b_release, b_pre) = split_version(b);
    compare_version_parts(&a_release, &b_release).then_with(|| {
        match (a_pre.is_empty(), b_pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => compare_version_parts(&a_pre, &b_pre),
        }
    })
}

fn split_version(version: &str) -> (Vec<&str>, Vec<&str>) {
    let (release, pre) = version.split_once('-').unwrap_or((version, ""));
    (split_parts(release), split_parts(pre))
}

fn split_parts(segment: &str) -> Vec<&str> {
    if segment.is_empty() {
        Vec::new()
    } else {
        segment.split(['.', '_']).collect()
    }
}

fn compare_version_parts(a: &[&str], b: &[&str]) -> Ordering {
    let len = a.len().max(b.len());
    for index in 0..len {
        let ordering = match (a.get(index), b.get(index)) {
            (Some(a), Some(b)) => compare_part(a, b),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn compare_part(a: &str, b: &str) -> Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        // A numeric identifier has lower precedence than a textual one (semver rule).
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

fn sync_parent(path: &Path) -> Result<(), SkillError> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

struct InputBindings {
    values: BTreeMap<String, Value>,
}

impl InputBindings {
    fn new(inputs: &[SkillInput], input: &Value) -> Result<Self, SkillError> {
        let object = input.as_object();
        let mut values = BTreeMap::new();

        for spec in inputs {
            match object.and_then(|map| map.get(&spec.name)) {
                Some(value) => {
                    values.insert(spec.name.clone(), value.clone());
                }
                None if spec.required => return Err(SkillError::MissingInput(spec.name.clone())),
                None => {}
            }
        }

        Ok(Self { values })
    }

    fn string(&self, name: &str) -> Result<String, SkillError> {
        let value = self
            .values
            .get(name)
            .ok_or_else(|| SkillError::MissingInput(name.to_string()))?;
        match value {
            Value::String(value) => Ok(value.clone()),
            Value::Number(value) => Ok(value.to_string()),
            Value::Bool(value) => Ok(value.to_string()),
            Value::Null => Ok(String::new()),
            Value::Array(_) | Value::Object(_) => {
                Err(SkillError::UnsupportedInputValue(name.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    type TestResult = Result<(), Box<dyn Error>>;

    #[test]
    fn persisted_skill_replays_to_identical_action_batches() -> TestResult {
        let root = unique_dir("replay")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        let skill = checkout_skill();
        let key = skill.key();
        store.put(&skill)?;

        let input = serde_json::json!({
            "url": "https://shop.example/item",
            "buy_button": "node-buy",
            "note_box": "node-note",
            "note": "ship to side door"
        });

        let first = store.compile(&key, &input)?;
        let reopened = SkillStore::open(&root)?;
        let second = reopened.compile(&key, &input)?;

        assert_eq!(first, second);
        assert_eq!(
            first.actions,
            vec![
                Action::Goto {
                    url: "https://shop.example/item".into(),
                },
                Action::Type {
                    node: NodeId("node-note".into()),
                    text: "ship to side door".into(),
                },
                Action::Click {
                    node: NodeId("node-buy".into()),
                },
            ]
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn store_list_is_sorted_and_stable() -> TestResult {
        let root = unique_dir("list")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        let mut a = checkout_skill();
        a.name = "zeta".into();
        let mut b = checkout_skill();
        b.name = "alpha".into();

        store.put(&a)?;
        store.put(&b)?;

        assert_eq!(
            store.list()?,
            vec![
                SkillKey {
                    name: "alpha".into(),
                    version: "1".into(),
                },
                SkillKey {
                    name: "zeta".into(),
                    version: "1".into(),
                },
            ]
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn catalog_reports_runtime_metadata_without_expanding_actions() -> TestResult {
        let root = unique_dir("catalog")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        let mut checkout = checkout_skill();
        checkout.version = "2".into();
        let mut read_only = SkillDefinition {
            name: "extract-main".into(),
            version: "1".into(),
            description: "extract the main content node".into(),
            side_effect: SideEffect::Read,
            inputs: vec![SkillInput::required("main_node")],
            quiescence: QuiescencePolicy::FixedMillis(0),
            steps: vec![ActionTemplate::Extract {
                node: TemplateString::param("main_node"),
            }],
        };
        // Deliberately use an undeclared optional-looking input value at runtime
        // nowhere: metadata loading must not expand or validate caller input.
        read_only.inputs.push(SkillInput::optional("format"));

        store.put(&checkout)?;
        store.put(&read_only)?;

        let catalog = store.catalog()?;

        assert_eq!(catalog.len(), 2);
        assert_eq!(catalog[0].key.name, "checkout");
        assert_eq!(catalog[0].key.version, "2");
        assert_eq!(catalog[0].side_effect, SideEffect::Write);
        assert_eq!(catalog[0].step_count, 3);
        assert_eq!(catalog[0].required_inputs, 3);
        assert_eq!(catalog[0].optional_inputs, 1);
        assert_eq!(catalog[1].key.name, "extract-main");
        assert_eq!(catalog[1].side_effect, SideEffect::Read);
        assert_eq!(catalog[1].quiescence, QuiescencePolicy::FixedMillis(0));
        assert_eq!(catalog[1].step_count, 1);
        assert_eq!(catalog[1].required_inputs, 1);
        assert_eq!(catalog[1].optional_inputs, 1);

        let value = serde_json::to_value(&catalog)?;
        assert_eq!(value[0]["side_effect"], "write");
        assert_eq!(
            value[1]["quiescence"],
            serde_json::json!({"fixed_millis": 0})
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn resolve_selects_highest_stored_version_for_name() -> TestResult {
        let root = unique_dir("resolve")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        let mut first = checkout_skill();
        first.version = "1".into();
        let mut second = checkout_skill();
        second.version = "2".into();
        let mut other = checkout_skill();
        other.name = "other".into();

        store.put(&first)?;
        store.put(&second)?;
        store.put(&other)?;

        assert_eq!(
            store.resolve("checkout")?,
            SkillKey {
                name: "checkout".into(),
                version: "2".into(),
            }
        );
        assert!(matches!(
            store.resolve("missing"),
            Err(SkillError::SkillNotFound(name)) if name == "missing"
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn missing_required_input_is_rejected() {
        let skill = checkout_skill();
        let err = skill.compile(&serde_json::json!({"url": "https://example.com"}));
        assert!(matches!(err, Err(SkillError::MissingInput(name)) if name == "buy_button"));
    }

    #[test]
    fn undeclared_template_parameters_are_rejected() {
        let mut skill = checkout_skill();
        skill.steps.push(ActionTemplate::Click {
            node: TemplateString::param("not_declared"),
        });

        assert!(matches!(
            validate_definition(&skill),
            Err(SkillError::UndeclaredInput(name)) if name == "not_declared"
        ));
    }

    #[test]
    fn object_values_do_not_render_as_strings() {
        let skill = SkillDefinition {
            name: "object-value".into(),
            version: "1".into(),
            description: "reject object input".into(),
            side_effect: SideEffect::Write,
            inputs: vec![SkillInput::required("node")],
            quiescence: QuiescencePolicy::Composite,
            steps: vec![ActionTemplate::Click {
                node: TemplateString::param("node"),
            }],
        };

        let err = skill.compile(&serde_json::json!({"node": {"bad": true}}));
        assert!(matches!(
            err,
            Err(SkillError::UnsupportedInputValue(name)) if name == "node"
        ));
    }

    #[test]
    fn invalid_names_do_not_escape_store_root() -> TestResult {
        let root = unique_dir("invalid")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        let mut skill = checkout_skill();
        skill.name = "../escape".into();

        assert!(matches!(
            store.put(&skill),
            Err(SkillError::InvalidKeySegment(name)) if name == "../escape"
        ));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn persisted_file_has_no_host_local_paths_or_timestamps() -> TestResult {
        let root = unique_dir("portable")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        let skill = checkout_skill();
        store.put(&skill)?;

        let path = store.path_for(&skill.key())?;
        let content = fs::read_to_string(path)?;
        assert!(!content.contains(root.to_string_lossy().as_ref()));
        assert!(!content.contains("target/debug"));
        assert!(!content.contains("timestamp"));

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn skill_side_effect_is_persisted_and_defaults_to_write_for_old_files() -> TestResult {
        let skill = checkout_skill();
        let value = serde_json::to_value(&skill)?;
        assert_eq!(value["side_effect"], "write");

        let legacy_value = serde_json::json!({
            "name": "legacy_checkout",
            "version": "1",
            "description": "legacy file without side effect metadata",
            "inputs": [],
            "quiescence": "composite",
            "steps": [
                {
                    "kind": "click",
                    "node": {
                        "kind": "literal",
                        "value": "buy"
                    }
                }
            ]
        });
        let legacy: SkillDefinition = serde_json::from_value(legacy_value)?;
        assert_eq!(legacy.side_effect, SideEffect::Write);

        Ok(())
    }

    #[test]
    fn skill_side_effect_cannot_undercover_direct_steps() {
        let mut skill = checkout_skill();
        skill.side_effect = SideEffect::Read;

        assert!(matches!(
            validate_definition(&skill),
            Err(SkillError::SkillSideEffectUndercovers {
                declared: SideEffect::Read,
                required: SideEffect::Write,
            })
        ));
    }

    #[test]
    fn resolve_uses_semantic_version_ordering_not_lexical() -> TestResult {
        let root = unique_dir("semver")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        for version in ["2", "9", "10"] {
            let mut skill = checkout_skill();
            skill.version = version.into();
            store.put(&skill)?;
        }

        // Lexically "10" < "9" < "2"; semantically "10" is the highest.
        assert_eq!(
            store.resolve("checkout")?,
            SkillKey {
                name: "checkout".into(),
                version: "10".into(),
            }
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn compare_versions_orders_numeric_and_prerelease() {
        assert_eq!(compare_versions("10", "9"), Ordering::Greater);
        assert_eq!(compare_versions("2", "10"), Ordering::Less);
        assert_eq!(compare_versions("1_2_0", "1_10_0"), Ordering::Less);
        // A plain release outranks a pre-release of the same version.
        assert_eq!(compare_versions("1", "1-beta"), Ordering::Greater);
        assert_eq!(compare_versions("1-alpha", "1-beta"), Ordering::Less);
        assert_eq!(compare_versions("1", "1"), Ordering::Equal);
    }

    #[test]
    fn malformed_skill_file_is_skipped_and_valid_skills_still_resolve() -> TestResult {
        let root = unique_dir("malformed")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        store.put(&checkout_skill())?;

        // A single corrupt/unparseable .json file dropped into the store must not
        // abort resolution of the valid skills alongside it.
        fs::write(root.join("broken.json"), b"{ this is not valid json ")?;

        assert_eq!(
            store.list()?,
            vec![SkillKey {
                name: "checkout".into(),
                version: "1".into(),
            }]
        );
        assert_eq!(
            store.resolve("checkout")?,
            SkillKey {
                name: "checkout".into(),
                version: "1".into(),
            }
        );

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    #[test]
    fn catalog_skips_malformed_skill_files() -> TestResult {
        let root = unique_dir("catalog-malformed")?;
        remove_dir_if_exists(&root)?;
        let store = SkillStore::open(&root)?;
        store.put(&checkout_skill())?;
        fs::write(root.join("broken.json"), b"{ definitely not json ")?;

        let catalog = store.catalog()?;

        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].key.name, "checkout");

        remove_dir_if_exists(&root)?;
        Ok(())
    }

    fn checkout_skill() -> SkillDefinition {
        SkillDefinition {
            name: "checkout".into(),
            version: "1".into(),
            description: "open a page, type a note, and click buy".into(),
            side_effect: SideEffect::Write,
            inputs: vec![
                SkillInput::required("url"),
                SkillInput::required("buy_button"),
                SkillInput::required("note_box"),
                SkillInput::optional("note"),
            ],
            quiescence: QuiescencePolicy::Composite,
            steps: vec![
                ActionTemplate::Goto {
                    url: TemplateString::param("url"),
                },
                ActionTemplate::Type {
                    node: TemplateString::param("note_box"),
                    text: TemplateString::param("note"),
                },
                ActionTemplate::Click {
                    node: TemplateString::param("buy_button"),
                },
            ],
        }
    }

    fn unique_dir(label: &str) -> Result<PathBuf, std::time::SystemTimeError> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tempo-skills-{label}-{}-{nanos}",
            std::process::id()
        ));
        Ok(path)
    }

    fn remove_dir_if_exists(path: &Path) -> Result<(), std::io::Error> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}
