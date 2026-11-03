//! `stogas policy edit`: a saved policy in your own editor, saved again with the revision it
//! started from. Like `git commit` and `kubectl edit`, it opens `$VISUAL` or `$EDITOR`.

use crate::{
    account,
    dashboard::{ApiError, Dashboard, printable},
    topup::{parse_organization, uuid},
};
use anyhow::{Context as _, Result, anyhow, bail};
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    fs,
    io::IsTerminal as _,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use stogas::network::Network;

/// What can hold a policy, as the dashboard API names it.
const SCOPES: [&str; 7] = [
    "organization",
    "folder",
    "grant",
    "role",
    "member",
    "credential",
    "key",
];

/// Editors that read JSON Schema, such as VS Code, complete and check the file with this link.
/// It changes nothing in a policy.
pub const SCHEMA: &str = "https://stogas.ai/schemas/key-config-v1.json";

#[derive(clap::Args)]
pub struct EditArgs {
    /// What holds the policy.
    #[arg(value_parser = SCOPES)]
    scope: String,
    /// Its ID, from Copy ID in its menu on the dashboard or from `stogas api`. The organization
    /// scope needs none.
    #[arg(value_parser = parse_id)]
    id: Option<String>,
    /// The organization's ID; without it, your personal organization.
    #[arg(long, value_parser = parse_organization)]
    organization: Option<String>,
}

fn parse_id(value: &str) -> Result<String, String> {
    uuid(value).ok_or_else(|| "an ID is a UUID, as Copy ID copies it on the dashboard".into())
}

pub async fn run(args: EditArgs, network: &Network) -> Result<()> {
    let EditArgs {
        scope,
        id,
        organization,
    } = args;
    // An organization holds its own policy, so either argument names it.
    let (organization, id) = if scope == "organization" {
        if let (Some(id), Some(organization)) = (&id, &organization)
            && id != organization
        {
            bail!("the ID and --organization name different organizations; give it once");
        }
        (id.or(organization), None)
    } else {
        let id = id.with_context(|| format!("name the {scope} with its ID"))?;
        (organization, Some(id))
    };
    let dashboard = account::signed_in(network).await?;
    let organization = match organization {
        Some(organization) => organization,
        None => personal_organization(&dashboard).await?,
    };
    let id = id.unwrap_or_else(|| organization.clone());
    let api = Remote::new(&dashboard, &organization, &scope, &id);
    let directory = private_directory()?;
    let file = directory.join(format!("{scope}-{id}.json"));
    let mut editor = SystemEditor::from_environment();
    let mut ask = ask_on_terminal;
    let result = edit(&api, &mut editor, &mut ask, &file).await;
    // An edit that was not saved stays for its author, in a directory only they can open.
    let kept = result.as_ref().is_err_and(|failure| failure.edited);
    if !kept {
        fs::remove_dir_all(&directory).ok();
    }
    match result {
        Ok(Outcome::Saved(revision)) => {
            eprintln!("Saved revision {revision} of the {scope} policy.");
        }
        Ok(Outcome::Unchanged(revision)) => {
            eprintln!("No changes; the {scope} policy stays at revision {revision}.");
            if editor.returned_at_once {
                eprintln!(
                    "Your editor returned at once. If it opens a window, set VISUAL to a command \
                     that waits until you close the file, such as `code --wait`."
                );
            }
        }
        Ok(Outcome::Cancelled(revision)) => {
            eprintln!("Cancelled; the {scope} policy stays at revision {revision}.");
        }
        Ok(Outcome::AlreadySaved(revision)) => {
            eprintln!("Revision {revision} of the {scope} policy already has your changes.");
        }
        Err(failure) if kept => {
            return Err(failure.error.context(format!(
                "nothing was saved; your edit is in {}",
                file.display()
            )));
        }
        Err(failure) => return Err(failure.error),
    }
    Ok(())
}

/// Your personal organization, which the organization list names first.
pub async fn personal_organization(dashboard: &Dashboard) -> Result<String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Organization {
        organization_id: String,
        organization_type: String,
    }
    #[derive(Deserialize)]
    struct Page {
        items: Vec<Organization>,
    }
    let page: Page = dashboard.get("/api/organizations?limit=1").await?;
    page.items
        .into_iter()
        .find(|organization| organization.organization_type == "personal")
        .and_then(|organization| uuid(&organization.organization_id))
        .context(
            "your access token does not cover your personal organization; name an organization \
             with --organization",
        )
}

/// A policy as saved: its document, or null without one, and the revision that a change names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Saved {
    pub config: Value,
    pub revision: u64,
}

/// What `edit` reads and saves: the dashboard, or a stand-in in tests.
pub trait PolicyApi: Sync {
    fn read(&self) -> impl Future<Output = Result<Saved>> + Send;
    fn save(&self, config: &Value, revision: u64) -> impl Future<Output = Result<Saved>> + Send;
}

pub struct Remote<'a> {
    dashboard: &'a Dashboard,
    path: String,
}

impl<'a> Remote<'a> {
    pub fn new(dashboard: &'a Dashboard, organization: &str, scope: &str, id: &str) -> Self {
        Self {
            dashboard,
            path: format!("/api/{organization}/policies/{scope}/{id}"),
        }
    }
}

impl PolicyApi for Remote<'_> {
    async fn read(&self) -> Result<Saved> {
        self.dashboard.get(&self.path).await
    }

    async fn save(&self, config: &Value, revision: u64) -> Result<Saved> {
        self.dashboard
            .put(
                &self.path,
                &json!({ "config": config, "revision": revision }),
            )
            .await
    }
}

/// Opens a file for its author and returns once they close it.
pub trait Editor: Send {
    fn name(&self) -> &str;
    fn edit(&mut self, file: &Path) -> Result<()>;
}

/// `$VISUAL`, then `$EDITOR`, then the platform's own editor. The value runs through the shell,
/// as git runs it, so it can carry arguments such as `code --wait`.
struct SystemEditor {
    command: String,
    /// Whether the editor's last run ended within a second, as a window's launcher does.
    returned_at_once: bool,
}

impl SystemEditor {
    fn from_environment() -> Self {
        let configured = ["VISUAL", "EDITOR"]
            .iter()
            .filter_map(|name| std::env::var(name).ok())
            .find(|value| !value.trim().is_empty());
        let default = if cfg!(windows) { "notepad" } else { "vi" };
        Self {
            command: configured.unwrap_or_else(|| default.to_owned()),
            returned_at_once: false,
        }
    }
}

impl Editor for SystemEditor {
    fn name(&self) -> &str {
        &self.command
    }

    fn edit(&mut self, file: &Path) -> Result<()> {
        let started = Instant::now();
        let status = editor_command(&self.command, file)
            .status()
            .with_context(|| format!("could not start the editor `{}`", self.command))?;
        self.returned_at_once = started.elapsed() < Duration::from_secs(1);
        // The shell, and cmd on Windows, end with these codes when they find no such command.
        if matches!(status.code(), Some(127 | 9009)) {
            bail!(
                "could not find the editor `{}`; set VISUAL or EDITOR to one you have",
                self.command
            );
        }
        if !status.success() {
            bail!("the editor `{}` exited with {status}", self.command);
        }
        Ok(())
    }
}

#[cfg(not(windows))]
fn editor_command(editor: &str, file: &Path) -> Command {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!("{editor} \"$@\""))
        .arg(editor)
        .arg(file);
    command
}

#[cfg(windows)]
fn editor_command(editor: &str, file: &Path) -> Command {
    use std::os::windows::process::CommandExt as _;
    let mut command = Command::new("cmd");
    command
        .arg("/C")
        .raw_arg(format!("{editor} \"{}\"", file.display()));
    command
}

/// Asks on the terminal, yes by default. Without a terminal, or once its input ends, the answer is
/// no.
fn ask_on_terminal(question: &str) -> bool {
    std::io::stdin().is_terminal()
        && account::read_line(&format!("{question} [Y/n] "))
            .is_ok_and(|answer| !matches!(answer.to_ascii_lowercase().as_str(), "n" | "no"))
}

/// A new directory that only this user can open, because a policy can hold secrets in plain text,
/// such as an export's header values.
fn private_directory() -> Result<PathBuf> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|error| anyhow!("no randomness: {error}"))?;
    let directory = std::env::temp_dir().join(format!("stogas-policy-{}", hex::encode(random)));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(&directory)
        .with_context(|| format!("could not create {}", directory.display()))?;
    Ok(directory)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Saved(u64),
    Unchanged(u64),
    Cancelled(u64),
    AlreadySaved(u64),
}

/// A failed edit, and whether the file holds an edit that was not saved.
pub struct Failure {
    pub error: anyhow::Error,
    pub edited: bool,
}

impl<E: Into<anyhow::Error>> From<E> for Failure {
    fn from(error: E) -> Self {
        Self {
            error: error.into(),
            edited: false,
        }
    }
}

/// Writes the saved policy to `file`, opens it, and saves what its author leaves there. An empty
/// file cancels. A file that does not parse, or that the dashboard refuses, opens again on request
/// with the author's text. When someone saved the policy meanwhile, the author's changes move onto
/// that version, as the dashboard's editor moves them, and open for review before saving.
pub async fn edit(
    api: &impl PolicyApi,
    editor: &mut impl Editor,
    ask: &mut (impl FnMut(&str) -> bool + Send),
    file: &Path,
) -> Result<Outcome, Failure> {
    let mut saved = api.read().await?;
    write_private(file, &shown(&saved.config))?;
    eprintln!(
        "Opening revision {} in `{}`. Close the file to save it, or empty it to cancel.",
        saved.revision,
        printable(editor.name())
    );
    let kept = |error: anyhow::Error| Failure {
        error,
        edited: true,
    };
    // After the first round, the file holds the author's edit or the combined policy.
    let mut again = false;
    loop {
        let opened = editor
            .edit(file)
            .and_then(|()| {
                fs::read(file).with_context(|| format!("could not read {}", file.display()))
            })
            .map_err(|error| Failure {
                error,
                edited: again,
            });
        let text = opened?;
        again = true;
        // Some Windows editors start UTF-8 with a byte order mark, which JSON does not allow.
        let text = text.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&text);
        if text.iter().all(u8::is_ascii_whitespace) {
            return Ok(Outcome::Cancelled(saved.revision));
        }
        let edited = match parse(text) {
            Ok(document) => settings(&document),
            Err(error) => {
                eprintln!("The file is not valid JSON: {error}");
                if ask("Edit it again?") {
                    continue;
                }
                return Err(kept(error));
            }
        };
        let current = settings(&saved.config);
        if edited == current {
            return Ok(Outcome::Unchanged(saved.revision));
        }
        let error = match api
            .save(&linked(&edited, &saved.config), saved.revision)
            .await
        {
            Ok(record) => return Ok(Outcome::Saved(record.revision)),
            Err(error) => error,
        };
        let refusal = error.downcast_ref::<ApiError>();
        if refusal.is_some_and(|refusal| refusal.code.as_deref() == Some("POLICY_CHANGED")) {
            let latest = api.read().await.map_err(kept)?;
            let rebased = rebase(&current, &settings(&latest.config), &edited);
            saved = latest;
            if rebased.config == settings(&saved.config) {
                return Ok(Outcome::AlreadySaved(saved.revision));
            }
            write_private(file, &shown(&rebased.config)).map_err(kept)?;
            eprintln!(
                "Someone saved revision {} while you edited, so your changes now apply to it.",
                saved.revision
            );
            if !rebased.conflicts.is_empty() {
                eprintln!(
                    "You both changed these, and your values stay: {}",
                    printable(&rebased.conflicts.join(", "))
                );
            }
            if !rebased.newer.is_empty() {
                eprintln!(
                    "Only revision {} changed these: {}",
                    saved.revision,
                    printable(&rebased.newer.join(", "))
                );
            }
            if ask("Review the combined policy in your editor?") {
                continue;
            }
            return Err(kept(anyhow!(
                "revision {} changed the policy while you edited it",
                saved.revision
            )));
        }
        if refusal.is_some_and(fixable) {
            eprintln!("The dashboard refused the policy: {error}");
            if ask("Edit it again?") {
                continue;
            }
        }
        return Err(kept(error));
    }
}

/// Whether a refusal is about the policy itself, which another edit can fix.
fn fixable(refusal: &ApiError) -> bool {
    matches!(
        refusal.status,
        StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNPROCESSABLE_ENTITY
    ) || refusal.code.as_deref() == Some("INVALID_API_KEY_CONFIG")
}

fn write_private(file: &Path, document: &Value) -> Result<()> {
    let mut text = serde_json::to_string_pretty(document)?;
    text.push('\n');
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut handle = options
        .open(file)
        .with_context(|| format!("could not write {}", file.display()))?;
    std::io::Write::write_all(&mut handle, text.as_bytes())
        .with_context(|| format!("could not write {}", file.display()))
}

/// The file's form of a policy: the schema link, then its settings, two-space indented as the
/// dashboard's editor shows them.
fn shown(config: &Value) -> Value {
    let mut document = Map::new();
    document.insert("$schema".into(), SCHEMA.into());
    if let Value::Object(fields) = config {
        for (key, value) in fields {
            if key != "$schema" {
                document.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(document)
}

/// What a document sets, without the schema link. A document without settings, such as `{}`,
/// saves as no policy, which is null.
fn settings(document: &Value) -> Value {
    let Value::Object(fields) = document else {
        return document.clone();
    };
    let settings: Map<String, Value> = fields
        .iter()
        .filter(|(key, value)| !(*key == "$schema" && *value == SCHEMA))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if settings.is_empty() {
        Value::Null
    } else {
        Value::Object(settings)
    }
}

/// The settings to save, with the schema link only where the saved policy keeps one.
fn linked(settings: &Value, saved: &Value) -> Value {
    if settings.is_object() && saved.get("$schema").is_some() {
        shown(settings)
    } else {
        settings.clone()
    }
}

/// One JSON value. A repeated key is refused, as the dashboard refuses it, instead of the last
/// value silently winning.
fn parse(text: &[u8]) -> Result<Value> {
    Ok(stogas_sigstore::strict_json::from_slice(text)?)
}

/// A draft's changes applied to a newer version of the policy it started from.
#[derive(Debug, PartialEq)]
struct Rebased {
    config: Value,
    /// Settings that both versions changed differently; the draft's value stays.
    conflicts: Vec<String>,
    /// Settings that only the newer version changed.
    newer: Vec<String>,
}

// Sections and their settings merge separately. A setting's value, such as a sort list, the named
// request limits or an encrypted envelope, changes as one unit, and so does each rule. The
// dashboard's editor merges the same way, in `apps/web/src/lib/policy-rebase.ts`.
const SETTING_DEPTH: usize = 2;

/// Applies the changes that `draft` made to `base` onto `latest`. No policy reads as an empty one,
/// and an empty result is no policy.
fn rebase(base: &Value, latest: &Value, draft: &Value) -> Rebased {
    let read = |value: &Value| {
        if value.is_null() {
            Value::Object(Map::new())
        } else {
            value.clone()
        }
    };
    let mut report = Report::default();
    let merged = merge(
        Some(&read(base)),
        Some(&read(latest)),
        Some(&read(draft)),
        &[],
        &mut report,
    );
    let config = match merged {
        Some(Value::Object(fields)) if !fields.is_empty() => Value::Object(fields),
        _ => Value::Null,
    };
    Rebased {
        config,
        conflicts: report.conflicts,
        newer: report.newer,
    }
}

#[derive(Default)]
struct Report {
    conflicts: Vec<String>,
    newer: Vec<String>,
}

/// Whether the versions of the value at `path` change as one unit, not key by key. Encrypted
/// plugins replace every plaintext plugin, so the two forms never mix.
fn is_unit(path: &[String], versions: &[Option<&Value>]) -> bool {
    path.len() >= SETTING_DEPTH
        || versions
            .iter()
            .any(|value| value.is_some_and(|value| !value.is_object()))
        || (path.len() == 1
            && path[0] == "plugins"
            && versions.iter().any(|value| {
                value
                    .and_then(Value::as_object)
                    .is_some_and(|fields| fields.contains_key("encrypted"))
            }))
}

fn fields(value: Option<&Value>) -> Map<String, Value> {
    value
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// The keys of both objects, the first one's first.
fn keys(first: &Map<String, Value>, second: &Map<String, Value>) -> Vec<String> {
    let mut keys: Vec<String> = first.keys().cloned().collect();
    keys.extend(
        second
            .keys()
            .filter(|key| !first.contains_key(*key))
            .cloned(),
    );
    keys
}

/// `path` and one more key.
fn with(path: &[String], key: &str) -> Vec<String> {
    let mut path = path.to_vec();
    path.push(key.to_owned());
    path
}

/// Collects the units that differ between two versions.
fn changes(from: Option<&Value>, to: Option<&Value>, path: &[String], out: &mut Vec<String>) {
    if from == to {
        return;
    }
    if is_unit(path, &[from, to]) {
        out.push(path.join("."));
        return;
    }
    let (from, to) = (fields(from), fields(to));
    for key in keys(&from, &to) {
        changes(from.get(&key), to.get(&key), &with(path, &key), out);
    }
}

fn merge(
    base: Option<&Value>,
    latest: Option<&Value>,
    draft: Option<&Value>,
    path: &[String],
    report: &mut Report,
) -> Option<Value> {
    if latest == draft {
        return latest.cloned();
    }
    if base == draft {
        changes(base, latest, path, &mut report.newer);
        return latest.cloned();
    }
    if base == latest {
        return draft.cloned();
    }
    if is_unit(path, &[base, latest, draft]) {
        report.conflicts.push(path.join("."));
        return draft.cloned();
    }
    let (from, to, edited) = (fields(base), fields(latest), fields(draft));
    let mut merged = Map::new();
    for key in keys(&to, &edited) {
        let value = merge(
            from.get(&key),
            to.get(&key),
            edited.get(&key),
            &with(path, &key),
            report,
        );
        if let Some(value) = value {
            merged.insert(key, value);
        }
    }
    // A section without settings has no effect, and some sections must not be empty.
    (!merged.is_empty()).then_some(Value::Object(merged))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    #[test]
    fn shows_the_schema_link_and_saves_only_the_settings() {
        assert_eq!(shown(&Value::Null), json!({ "$schema": SCHEMA }));
        let policy = json!({ "limits": { "rpm": 5 } });
        let file = shown(&policy);
        assert_eq!(
            serde_json::to_string_pretty(&file).unwrap(),
            format!("{{\n  \"$schema\": \"{SCHEMA}\",\n  \"limits\": {{\n    \"rpm\": 5\n  }}\n}}")
        );
        assert_eq!(settings(&file), policy);
        // Without settings, a document is no policy, as the dashboard saves it.
        for empty in [json!({}), json!({ "$schema": SCHEMA }), Value::Null] {
            assert_eq!(settings(&empty), Value::Null);
        }
        // Another link is not this one, so the dashboard names the mistake.
        let wrong = json!({ "$schema": "https://example.com/schema.json" });
        assert_eq!(settings(&wrong), wrong);
        // A saved policy keeps its own link; others gain none.
        let linked_policy = json!({ "$schema": SCHEMA, "limits": { "rpm": 5 } });
        assert_eq!(linked(&policy, &linked_policy), linked_policy);
        assert_eq!(linked(&policy, &policy), policy);
        assert_eq!(linked(&Value::Null, &linked_policy), Value::Null);
    }

    #[test]
    fn reads_one_json_value_and_refuses_repeated_keys() {
        assert_eq!(
            parse(br#"{"b":1,"a":2}"#)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["b", "a"]
        );
        assert!(
            parse(br#"{"limits":{},"limits":{}}"#)
                .unwrap_err()
                .to_string()
                .contains("duplicate JSON key: limits")
        );
        assert!(parse(b"{} {}").is_err());
        assert_eq!(
            parse_id("0192F3A4-5B6C-7D8E-9F01-000000000001").as_deref(),
            Ok("0192f3a4-5b6c-7d8e-9f01-000000000001")
        );
        assert!(parse_id("../keys").is_err());
    }

    /// The dashboard's editor merges with `rebasePolicySource`; these are its cases, so that both
    /// editors combine the same edits the same way.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn merges_a_draft_as_the_dashboard_does() {
        let envelope = |label: &str| {
            json!({
                "version": 1,
                "keyId": "a".repeat(64),
                "salt": format!("{}A", label.repeat(42)),
                "nonce": label.repeat(16),
                "blob": label.repeat(24)
            })
        };
        let mixed = |label: &str, field: &str| {
            let mut mixed = envelope(label);
            mixed[field] = envelope("a")[field].clone();
            mixed
        };
        let night = json!({ "when": "a", "mode": "default" });
        let plaintext = json!({ "textExtraction": true });
        let encrypted = json!({ "encrypted": envelope("a") });
        let timeouts = json!({ "timeouts": { "totalSeconds": 60 } });
        let cases = [
            // Changes to different settings and rules combine.
            (
                json!({ "routing": { "retries": 1 }, "rules": { "night": night } }),
                json!({
                    "routing": { "retries": 1 },
                    "rules": { "night": night, "eu": { "when": "b", "routing": { "retries": 2 } } },
                    "timeouts": { "totalSeconds": 60 }
                }),
                json!({
                    "routing": { "retries": 1, "sort": ["price"] },
                    "rules": {
                        "night": night,
                        "large": { "when": "c", "timeouts": { "totalSeconds": 30 } }
                    }
                }),
                json!({
                    "routing": { "retries": 1, "sort": ["price"] },
                    "timeouts": { "totalSeconds": 60 },
                    "rules": {
                        "night": night,
                        "eu": { "when": "b", "routing": { "retries": 2 } },
                        "large": { "when": "c", "timeouts": { "totalSeconds": 30 } }
                    }
                }),
                &[][..],
                &["rules.eu", "timeouts.totalSeconds"][..],
            ),
            // Where both changed a setting, the draft's value stays.
            (
                json!({ "routing": { "retries": 1 }, "timeouts": { "totalSeconds": 60 } }),
                json!({ "routing": { "retries": 2 }, "timeouts": { "totalSeconds": 60 } }),
                json!({ "routing": { "retries": 3 }, "timeouts": { "totalSeconds": 30 } }),
                json!({ "routing": { "retries": 3 }, "timeouts": { "totalSeconds": 30 } }),
                &["routing.retries"],
                &[],
            ),
            // A section that one version removed and the other edited.
            (
                json!({ "timeouts": { "totalSeconds": 60 }, "input": { "asciiOnly": true } }),
                json!({ "input": { "asciiOnly": true } }),
                json!({ "timeouts": { "totalSeconds": 30 }, "input": { "asciiOnly": true } }),
                json!({ "timeouts": { "totalSeconds": 30 }, "input": { "asciiOnly": true } }),
                &["timeouts.totalSeconds"],
                &[],
            ),
            (
                json!({ "timeouts": { "totalSeconds": 60 }, "input": { "asciiOnly": true } }),
                json!({ "timeouts": { "totalSeconds": 30 }, "input": { "asciiOnly": true } }),
                json!({ "input": { "asciiOnly": true } }),
                json!({ "input": { "asciiOnly": true } }),
                &["timeouts.totalSeconds"],
                &[],
            ),
            // The fields of an encrypted envelope or a rule never mix.
            (
                json!({
                    "plugins": { "encrypted": envelope("a") },
                    "rules": { "night": { "when": "a", "routing": { "retries": 1 } } }
                }),
                json!({
                    "plugins": { "encrypted": mixed("b", "blob") },
                    "rules": { "night": { "when": "b", "routing": { "retries": 1 } } }
                }),
                json!({
                    "plugins": { "encrypted": mixed("c", "salt") },
                    "rules": { "night": { "when": "a", "routing": { "retries": 2 } } }
                }),
                json!({
                    "plugins": { "encrypted": mixed("c", "salt") },
                    "rules": { "night": { "when": "a", "routing": { "retries": 2 } } }
                }),
                &["plugins", "rules.night"],
                &[],
            ),
            // Nor do encrypted and plaintext plugins.
            (
                json!({ "plugins": plaintext }),
                json!({ "plugins": encrypted }),
                json!({ "plugins": { "textExtraction": false } }),
                json!({ "plugins": { "textExtraction": false } }),
                &["plugins"],
                &[],
            ),
            (
                json!({ "plugins": plaintext }),
                json!({ "plugins": { "textExtraction": true, "redaction": { "emails": true } } }),
                json!({ "plugins": encrypted }),
                json!({ "plugins": encrypted }),
                &["plugins"],
                &[],
            ),
            (
                json!({ "plugins": plaintext }),
                json!({ "plugins": encrypted }),
                json!({ "plugins": plaintext }),
                json!({ "plugins": encrypted }),
                &[],
                &["plugins"],
            ),
            // Only the settings that the newer version alone changed are its own.
            (
                json!({ "routing": { "retries": 1 }, "timeouts": { "totalSeconds": 60 } }),
                json!({ "routing": { "retries": 2 }, "timeouts": { "totalSeconds": 30 } }),
                json!({
                    "routing": { "retries": 1 },
                    "timeouts": { "totalSeconds": 30 },
                    "input": { "asciiOnly": true }
                }),
                json!({
                    "routing": { "retries": 2 },
                    "timeouts": { "totalSeconds": 30 },
                    "input": { "asciiOnly": true }
                }),
                &[],
                &["routing.retries"],
            ),
            // Cleared policies, and sections left without settings. Clearing changed the setting
            // that the draft kept.
            (
                timeouts.clone(),
                Value::Null,
                timeouts.clone(),
                Value::Null,
                &[],
                &["timeouts.totalSeconds"],
            ),
            (
                Value::Null,
                Value::Null,
                timeouts.clone(),
                timeouts.clone(),
                &[],
                &[],
            ),
            (
                timeouts.clone(),
                Value::Null,
                json!({ "timeouts": { "totalSeconds": 60 }, "input": { "asciiOnly": true } }),
                json!({ "input": { "asciiOnly": true } }),
                &[],
                &["timeouts.totalSeconds"],
            ),
            (
                json!({ "timeouts": { "totalSeconds": 60, "outputIdleSeconds": 30 } }),
                timeouts,
                json!({ "timeouts": { "outputIdleSeconds": 30 } }),
                Value::Null,
                &[],
                &["timeouts.outputIdleSeconds"],
            ),
            // A whole list is one setting.
            (
                json!({ "routing": { "sort": ["price"] } }),
                json!({ "routing": { "sort": ["latency"] } }),
                json!({ "routing": { "sort": ["throughput", "price"] } }),
                json!({ "routing": { "sort": ["throughput", "price"] } }),
                &["routing.sort"],
                &[],
            ),
        ];
        for (base, latest, draft, expected, conflicts, newer) in cases {
            let rebased = rebase(&base, &latest, &draft);
            let context = format!("{base} | {latest} | {draft}");
            assert_eq!(rebased.config, expected, "{context}");
            assert_eq!(rebased.conflicts, conflicts, "{context}");
            assert_eq!(rebased.newer, newer, "{context}");
        }

        // A newer version that already has the draft's changes comes back as it is, in its order.
        let latest = json!({ "timeouts": { "totalSeconds": 30 }, "routing": { "retries": 2 } });
        let rebased = rebase(
            &json!({ "timeouts": { "totalSeconds": 60 } }),
            &latest,
            &json!({ "routing": { "retries": 2 }, "timeouts": { "totalSeconds": 30 } }),
        );
        assert_eq!(rebased.config.to_string(), latest.to_string());
        assert!(rebased.conflicts.is_empty() && rebased.newer.is_empty());
    }

    /// Answers reads and saves from a script, and records each save.
    struct Script {
        reads: Mutex<VecDeque<Saved>>,
        saves: Mutex<VecDeque<Result<Saved, ApiError>>>,
        sent: Mutex<Vec<(Value, u64)>>,
    }

    impl Script {
        fn new(reads: Vec<Saved>, saves: Vec<Result<Saved, ApiError>>) -> Self {
            Self {
                reads: Mutex::new(reads.into()),
                saves: Mutex::new(saves.into()),
                sent: Mutex::default(),
            }
        }

        fn sent(&self) -> Vec<(Value, u64)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl PolicyApi for Script {
        async fn read(&self) -> Result<Saved> {
            Ok(self
                .reads
                .lock()
                .unwrap()
                .pop_front()
                .expect("an unscripted read"))
        }

        async fn save(&self, config: &Value, revision: u64) -> Result<Saved> {
            self.sent.lock().unwrap().push((config.clone(), revision));
            let answer = self
                .saves
                .lock()
                .unwrap()
                .pop_front()
                .expect("an unscripted save");
            Ok(answer?)
        }
    }

    /// Writes each scripted text in turn, after checking what the file held.
    pub struct Typist {
        steps: VecDeque<(Option<Value>, String)>,
    }

    impl Editor for Typist {
        fn name(&self) -> &'static str {
            "typist"
        }

        fn edit(&mut self, file: &Path) -> Result<()> {
            let (expected, text) = self.steps.pop_front().expect("an unscripted edit");
            if let Some(expected) = expected {
                let shown = fs::read_to_string(file)?;
                assert_eq!(serde_json::from_str::<Value>(&shown)?, expected);
                assert!(shown.ends_with("}\n"));
            }
            fs::write(file, text)?;
            Ok(())
        }
    }

    fn saved(config: Value, revision: u64) -> Saved {
        Saved { config, revision }
    }

    fn refused(status: StatusCode, code: &str, message: &str) -> ApiError {
        ApiError {
            status,
            code: Some(code.into()),
            message: message.into(),
            issues: Vec::new(),
        }
    }

    /// Runs `edit` with a scripted editor and answers, and returns its result and the file it
    /// left.
    pub async fn run_edit(
        api: &impl PolicyApi,
        steps: Vec<(Option<Value>, &str)>,
        answers: Vec<bool>,
    ) -> (Result<Outcome, Failure>, String) {
        let directory = private_directory().unwrap();
        let file = directory.join("key.json");
        let mut answers = VecDeque::from(answers);
        let mut ask = |_: &str| answers.pop_front().expect("an unscripted question");
        let mut typist = Typist {
            steps: steps
                .into_iter()
                .map(|(expected, text)| (expected, text.to_owned()))
                .collect(),
        };
        let result = edit(api, &mut typist, &mut ask, &file).await;
        assert!(typist.steps.is_empty() && answers.is_empty());
        let left = fs::read_to_string(&file).unwrap_or_default();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&directory), 0o700);
            assert_eq!(mode(&file), 0o600);
        }
        fs::remove_dir_all(directory).unwrap();
        (result, left)
    }

    #[tokio::test]
    async fn saves_a_change_with_the_revision_it_started_from() {
        let api = Script::new(
            vec![saved(json!({ "limits": { "rpm": 5 } }), 7)],
            vec![Ok(saved(json!({ "limits": { "rpm": 9 } }), 8))],
        );
        let (result, _) = run_edit(
            &api,
            vec![(
                Some(json!({ "$schema": SCHEMA, "limits": { "rpm": 5 } })),
                // A byte order mark and the schema link are not part of the policy.
                "\u{feff}{\"$schema\":\"https://stogas.ai/schemas/key-config-v1.json\",\"limits\":{\"rpm\":9}}",
            )],
            vec![],
        )
        .await;
        assert_eq!(result.ok(), Some(Outcome::Saved(8)));
        assert_eq!(api.sent(), [(json!({ "limits": { "rpm": 9 } }), 7)]);
    }

    #[tokio::test]
    async fn saves_nothing_when_the_policy_is_unchanged_or_the_file_is_empty() {
        let policy = json!({ "limits": { "rpm": 5 } });
        // Spacing, and the schema link alone, are no change.
        let api = Script::new(vec![saved(policy.clone(), 3)], vec![]);
        let (result, _) =
            run_edit(&api, vec![(None, r#"{ "limits": { "rpm": 5 } }"#)], vec![]).await;
        assert_eq!(result.ok(), Some(Outcome::Unchanged(3)));
        let api = Script::new(vec![saved(Value::Null, 1)], vec![]);
        let (result, _) = run_edit(
            &api,
            vec![(Some(json!({ "$schema": SCHEMA })), "{}")],
            vec![],
        )
        .await;
        assert_eq!(result.ok(), Some(Outcome::Unchanged(1)));
        let api = Script::new(vec![saved(policy, 3)], vec![]);
        let (result, _) = run_edit(&api, vec![(None, " \n")], vec![]).await;
        assert_eq!(result.ok(), Some(Outcome::Cancelled(3)));
        assert!(api.sent().is_empty());
        // `null`, like a document without settings, removes a policy.
        let api = Script::new(
            vec![saved(json!({ "limits": { "rpm": 5 } }), 3)],
            vec![Ok(saved(Value::Null, 4))],
        );
        let (result, _) = run_edit(&api, vec![(None, "null")], vec![]).await;
        assert_eq!(result.ok(), Some(Outcome::Saved(4)));
        assert_eq!(api.sent(), [(Value::Null, 3)]);
    }

    #[tokio::test]
    async fn opens_a_broken_file_again_with_its_author_s_text() {
        let api = Script::new(
            vec![saved(Value::Null, 1)],
            vec![Ok(saved(json!({ "limits": { "rpm": 2 } }), 2))],
        );
        let (result, _) = run_edit(
            &api,
            vec![
                (None, r#"{"limits":{"rpm":1},"limits":{"rpm":2}}"#),
                (None, r#"{"limits":{"rpm":2}}"#),
            ],
            vec![true],
        )
        .await;
        assert_eq!(result.ok(), Some(Outcome::Saved(2)));
        assert_eq!(api.sent(), [(json!({ "limits": { "rpm": 2 } }), 1)]);

        // Declining keeps the file, so the edit is not lost.
        let api = Script::new(vec![saved(Value::Null, 1)], vec![]);
        let (result, left) = run_edit(&api, vec![(None, "{")], vec![false]).await;
        assert!(result.as_ref().is_err_and(|failure| failure.edited));
        assert_eq!(left, "{");
    }

    #[tokio::test]
    async fn opens_a_refused_policy_again_and_stops_on_other_errors() {
        let api = Script::new(
            vec![saved(Value::Null, 1)],
            vec![
                Err(refused(
                    StatusCode::BAD_REQUEST,
                    "INVALID_API_KEY_CONFIG",
                    "limits.rpm: Too big",
                )),
                Ok(saved(json!({ "limits": { "rpm": 9 } }), 2)),
            ],
        );
        let (result, _) = run_edit(
            &api,
            vec![
                (None, r#"{"limits":{"rpm":9999999}}"#),
                (None, r#"{"limits":{"rpm":9}}"#),
            ],
            vec![true],
        )
        .await;
        assert_eq!(result.ok(), Some(Outcome::Saved(2)));
        assert_eq!(api.sent().len(), 2);

        // A refusal that another edit cannot fix ends the command and keeps the edit.
        let api = Script::new(
            vec![saved(Value::Null, 1)],
            vec![Err(refused(
                StatusCode::FORBIDDEN,
                "TOKEN_READ_ONLY",
                "Read only",
            ))],
        );
        let (result, left) = run_edit(&api, vec![(None, r#"{"limits":{"rpm":1}}"#)], vec![]).await;
        let failure = result.err().unwrap();
        assert!(failure.edited && failure.error.to_string().contains("Read only"));
        assert_eq!(left, r#"{"limits":{"rpm":1}}"#);
    }

    #[tokio::test]
    async fn moves_an_edit_onto_a_policy_saved_meanwhile_for_review() {
        let changed = || {
            Err(refused(
                StatusCode::CONFLICT,
                "POLICY_CHANGED",
                "This policy changed.",
            ))
        };
        let api = Script::new(
            vec![
                saved(json!({ "limits": { "rpm": 5, "tpm": 100 } }), 4),
                saved(json!({ "limits": { "rpm": 5, "tpm": 200 } }), 5),
            ],
            vec![
                changed(),
                Ok(saved(json!({ "limits": { "rpm": 9, "tpm": 200 } }), 6)),
            ],
        );
        let combined = json!({ "$schema": SCHEMA, "limits": { "rpm": 9, "tpm": 200 } });
        let (result, _) = run_edit(
            &api,
            vec![
                (None, r#"{"limits":{"rpm":9,"tpm":100}}"#),
                // The author reviews the combination and closes the file as it is.
                (
                    Some(combined.clone()),
                    r#"{"$schema":"https://stogas.ai/schemas/key-config-v1.json","limits":{"rpm":9,"tpm":200}}"#,
                ),
            ],
            vec![true],
        )
        .await;
        assert_eq!(result.ok(), Some(Outcome::Saved(6)));
        assert_eq!(
            api.sent(),
            [
                (json!({ "limits": { "rpm": 9, "tpm": 100 } }), 4),
                (json!({ "limits": { "rpm": 9, "tpm": 200 } }), 5)
            ]
        );

        // Without a review, nothing is saved and the combination stays in the file.
        let api = Script::new(
            vec![
                saved(json!({ "limits": { "rpm": 5, "tpm": 100 } }), 4),
                saved(json!({ "limits": { "rpm": 5, "tpm": 200 } }), 5),
            ],
            vec![changed()],
        );
        let (result, left) = run_edit(
            &api,
            vec![(None, r#"{"limits":{"rpm":9,"tpm":100}}"#)],
            vec![false],
        )
        .await;
        assert!(result.as_ref().is_err_and(|failure| failure.edited));
        assert_eq!(serde_json::from_str::<Value>(&left).unwrap(), combined);

        // When the newer version already has the change, nothing is left to save.
        let api = Script::new(
            vec![
                saved(json!({ "limits": { "rpm": 5 } }), 4),
                saved(json!({ "limits": { "rpm": 9 } }), 5),
            ],
            vec![changed()],
        );
        let (result, _) = run_edit(&api, vec![(None, r#"{"limits":{"rpm":9}}"#)], vec![]).await;
        assert_eq!(result.ok(), Some(Outcome::AlreadySaved(5)));
    }

    /// Breaks the JSON, then quits without saving, as `:cq` quits vi.
    struct Quitter {
        rounds: usize,
    }

    impl Editor for Quitter {
        fn name(&self) -> &'static str {
            "quitter"
        }

        fn edit(&mut self, file: &Path) -> Result<()> {
            self.rounds += 1;
            if self.rounds > 1 {
                bail!("the editor `quitter` exited with exit status: 1");
            }
            fs::write(file, "{")?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn keeps_an_earlier_edit_when_the_editor_quits_later() {
        let api = Script::new(vec![saved(Value::Null, 1)], vec![]);
        let directory = private_directory().unwrap();
        let file = directory.join("key.json");
        let result = edit(&api, &mut Quitter { rounds: 0 }, &mut |_: &str| true, &file).await;
        assert!(result.is_err_and(|failure| failure.edited));
        assert_eq!(fs::read_to_string(&file).unwrap(), "{");
        fs::remove_dir_all(directory).unwrap();

        // Quitting in the first round leaves nothing of the author's to keep.
        let api = Script::new(vec![saved(Value::Null, 1)], vec![]);
        let directory = private_directory().unwrap();
        let file = directory.join("key.json");
        let mut quitter = Quitter { rounds: 1 };
        let result = edit(&api, &mut quitter, &mut |_: &str| true, &file).await;
        assert!(result.is_err_and(|failure| !failure.edited));
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn opens_the_file_in_the_configured_editor() {
        let directory = private_directory().unwrap();
        let file = directory.join("key policy.json");
        fs::write(&file, "{}").unwrap();
        let editor = |command: &str| SystemEditor {
            command: command.into(),
            returned_at_once: false,
        };
        let mut sed = editor("sed -i.bak s/{}/null/");
        sed.edit(&file).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "null");
        assert!(sed.returned_at_once);
        let refused = editor("false").edit(&file).unwrap_err().to_string();
        assert!(refused.contains("exited with"), "{refused}");
        let missing = editor("stogas-no-such-editor")
            .edit(&file)
            .unwrap_err()
            .to_string();
        assert!(
            missing.starts_with("could not find the editor"),
            "{missing}"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn runs_the_editor_through_the_shell_with_its_arguments() {
        let command = editor_command("code --wait", Path::new("/tmp/a b.json"));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(command.get_program(), "sh");
        assert_eq!(
            args,
            ["-c", "code --wait \"$@\"", "code --wait", "/tmp/a b.json"]
        );
    }
}
