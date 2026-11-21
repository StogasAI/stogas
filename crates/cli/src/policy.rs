//! `stogas policy edit`: a saved policy in your own editor, saved again with the revision it
//! started from. Like `git commit` and `kubectl edit`, it opens `$VISUAL` or `$EDITOR`. With an
//! organization key it shows the values that the key encrypts in plain text and encrypts them
//! again when it saves, as `sops edit` does, so nobody keeps a copy of the policy in plain text.

use crate::{
    account,
    customer_encryption::{self, Opened, OrganizationKey},
    dashboard::{ApiError, Dashboard, printable},
    encryption_key::{self, parse_label},
    policy_check::{self, CheckGateway, GrantApi},
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
    sync::Mutex,
    time::{Duration, Instant},
};
use stogas::{TransportOptions, network::Network};

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
pub const SCHEMA: &str = "https://stogas.ai/schemas/policy-v1.json";

/// The link of a file that an organization key opened, where the schema also takes a value to
/// encrypt as `{"encrypt": value}`.
const KEY_SCHEMA: &str = "https://stogas.ai/schemas/policy-edit-v1.json";

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
    /// The file with your organization key. The editor then shows each value that the key
    /// encrypts in plain text as {"encrypt": value}, and saving encrypts every value of an export
    /// or redaction plugin that is written so, after the gateway checks those plugins. To change
    /// keys, give the new key first and then the old one: saving encrypts what the old key opened
    /// with the new key.
    #[arg(long, conflicts_with = "key")]
    key_file: Vec<PathBuf>,
    /// The label of a key that `stogas encryption-key` saved for the organization on this
    /// machine, in place of --key-file.
    #[arg(long, value_parser = parse_label)]
    key: Vec<String>,
}

fn parse_id(value: &str) -> Result<String, String> {
    uuid(value).ok_or_else(|| "an ID is a UUID, as Copy ID copies it on the dashboard".into())
}

pub async fn run(args: EditArgs, network: &Network, gateway: TransportOptions) -> Result<()> {
    let EditArgs {
        scope,
        id,
        organization,
        key_file,
        key,
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
        None => account::personal_organization(&dashboard).await?,
    };
    let id = id.unwrap_or_else(|| organization.clone());
    let mut keys = Vec::new();
    for path in &key_file {
        keys.push(customer_encryption::read_key(path)?);
    }
    for label in &key {
        keys.push(encryption_key::saved(&organization, label).await?);
    }
    let api = Remote::new(&dashboard, &organization, &scope, &id);
    let directory = private_directory()?;
    let file = directory.join(format!("{scope}-{id}.json"));
    let mut editor = SystemEditor::from_environment();
    let mut ask = ask_on_terminal;
    let result = if keys.is_empty() {
        edit(&api, &mut editor, &mut ask, &file).await
    } else {
        eprintln!(
            "Your key opens the values that it encrypts as {{\"encrypt\": value}}. Saving \
             encrypts each value of an export or redaction plugin that is written so{}.",
            if keys.len() > 1 {
                ", with the first key"
            } else {
                ""
            }
        );
        let gateway = policy_check::Verified(gateway);
        let api = Opening::new(&api, keys, &organization, &dashboard, &gateway);
        edit(&api, &mut editor, &mut ask, &file).await
    };
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
    /// The schema link of the file that shows what `read` returns.
    fn schema(&self) -> &'static str {
        SCHEMA
    }
    /// Whether saving what `read` returned would change what is stored, so that a file closed
    /// unchanged is saved too.
    fn rewrites(&self) -> bool {
        false
    }
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

/// A policy with the values that organization keys encrypt in plain text. Reading marks each
/// `{"encrypt": value}`, and saving encrypts every value that is marked so with the first key,
/// after the gateway checks the plugins that hold them. A value that its author left as it was
/// keeps its envelope when the first key made it, so the other keys' values move to the first.
pub struct Opening<'a, A, G, C> {
    api: &'a A,
    keys: Vec<OrganizationKey>,
    organization: &'a str,
    grants: &'a G,
    gateway: &'a C,
    /// The values that the last read opened.
    opened: Mutex<Vec<Opened>>,
}

impl<'a, A, G, C> Opening<'a, A, G, C> {
    pub const fn new(
        api: &'a A,
        keys: Vec<OrganizationKey>,
        organization: &'a str,
        grants: &'a G,
        gateway: &'a C,
    ) -> Self {
        Self {
            api,
            keys,
            organization,
            grants,
            gateway,
            opened: Mutex::new(Vec::new()),
        }
    }
}

/// A mark or a plugin that cannot be encrypted, which another edit can fix.
fn unencryptable(error: &anyhow::Error) -> anyhow::Error {
    ApiError {
        status: StatusCode::BAD_REQUEST,
        code: None,
        message: format!("{error:#}"),
        issues: Vec::new(),
    }
    .into()
}

impl<A: PolicyApi, G: GrantApi, C: CheckGateway> PolicyApi for Opening<'_, A, G, C> {
    async fn read(&self) -> Result<Saved> {
        let saved = self.api.read().await?;
        let (config, opened) =
            customer_encryption::open_policy(&self.keys, self.organization, saved.config)?;
        *self.opened.lock().expect("no panic holds the lock") = opened;
        Ok(Saved {
            config,
            revision: saved.revision,
        })
    }

    async fn save(&self, config: &Value, revision: u64) -> Result<Saved> {
        let (plain, parts) =
            customer_encryption::marked_parts(config.clone()).map_err(|e| unencryptable(&e))?;
        if !parts.is_empty() {
            let source = customer_encryption::policy_check_source(&plain, &parts);
            policy_check::check(self.grants, self.gateway, self.organization, &source)
                .await
                .map_err(|e| unencryptable(&e))?;
        }
        let sealed = {
            let opened = self.opened.lock().expect("no panic holds the lock");
            customer_encryption::seal_policy(
                &self.keys[0],
                self.organization,
                plain,
                &parts,
                &opened,
            )
            .map_err(|e| unencryptable(&e))?
        };
        let saved = self.api.save(&sealed, revision).await?;
        Ok(Saved {
            config: config.clone(),
            revision: saved.revision,
        })
    }

    fn schema(&self) -> &'static str {
        KEY_SCHEMA
    }

    fn rewrites(&self) -> bool {
        let opened = self.opened.lock().expect("no panic holds the lock");
        opened.iter().any(|value| !value.sealed_by(&self.keys[0]))
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
    #[cfg(unix)]
    let builder = {
        let mut builder = fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
    };
    // Windows gives each user a temporary directory that no other user can open.
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
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
    write_private(file, &shown(&saved.config, api.schema()))?;
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
        if edited == current && !api.rewrites() {
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
            write_private(file, &shown(&rebased.config, api.schema())).map_err(kept)?;
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
            eprintln!("The policy was not saved: {error}");
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
fn shown(config: &Value, schema: &str) -> Value {
    let mut document = Map::new();
    document.insert("$schema".into(), schema.into());
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
        .filter(|(key, value)| !(*key == "$schema" && (*value == SCHEMA || *value == KEY_SCHEMA)))
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
        shown(settings, SCHEMA)
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
// request limits or an encrypted plugin, changes as one unit, and so does each rule. The
// dashboard's editor merges the same way.
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

/// Whether the versions of the value at `path` change as one unit, not key by key.
fn is_unit(path: &[String], versions: &[Option<&Value>]) -> bool {
    path.len() >= SETTING_DEPTH
        || versions
            .iter()
            .any(|value| value.is_some_and(|value| !value.is_object()))
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
    use crate::policy_check::tests::{Api, ORGANIZATION, gateway};
    use std::{collections::VecDeque, sync::Mutex};

    #[test]
    fn shows_the_schema_link_and_saves_only_the_settings() {
        assert_eq!(shown(&Value::Null, SCHEMA), json!({ "$schema": SCHEMA }));
        let policy = json!({ "limits": { "rpm": 5 } });
        let file = shown(&policy, SCHEMA);
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

    /// The dashboard's editor merges with `rebasePolicySource`, and both read these cases, so that
    /// both editors combine the same edits the same way.
    #[test]
    fn merges_a_draft_as_the_dashboard_does() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/policy-rebase-v1.json"
        ))
        .unwrap();
        let labels = |value: &Value| {
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|label| label.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        let sorted = |mut labels: Vec<String>| {
            labels.sort();
            labels
        };
        for case in vectors["cases"].as_array().unwrap() {
            let rebased = rebase(&case["base"], &case["latest"], &case["draft"]);
            let name = &case["name"];
            assert_eq!(rebased.config, case["policy"], "{name}");
            assert_eq!(
                sorted(rebased.conflicts),
                labels(&case["conflicts"]),
                "{name}"
            );
            assert_eq!(sorted(rebased.newer), labels(&case["newer"]), "{name}");
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
                "\u{feff}{\"$schema\":\"https://stogas.ai/schemas/policy-v1.json\",\"limits\":{\"rpm\":9}}",
            )],
            vec![],
        )
        .await;
        assert_eq!(result.ok(), Some(Outcome::Saved(8)));
        assert_eq!(api.sent(), [(json!({ "limits": { "rpm": 9 } }), 7)]);
    }

    /// A policy whose export destination and redaction literals `key` encrypts.
    fn encrypted_policy(key: &OrganizationKey, policy: Value) -> Value {
        let parts = customer_encryption::policy_parts(
            &policy,
            &[
                "/plugins/export/destinations/0".into(),
                "/plugins/redaction/literals".into(),
            ],
        )
        .unwrap();
        customer_encryption::seal_policy(key, ORGANIZATION, policy, &parts, &[]).unwrap()
    }

    #[tokio::test]
    async fn a_key_opens_encrypted_values_and_encrypts_the_marked_ones_again() {
        let key = customer_encryption::generate().unwrap();
        let destination = json!({ "url": "https://logs.example.com/a", "content": false });
        let stored = encrypted_policy(
            &key,
            json!({
                "limits": { "rpm": 5 },
                "plugins": {
                    "export": { "destinations": [destination.clone()] },
                    "redaction": { "literals": [{ "values": ["Falcon"] }] }
                }
            }),
        );
        let api = Script::new(
            vec![saved(stored.clone(), 7)],
            vec![Ok(saved(Value::Null, 8))],
        );
        let grants = Api(Mutex::new(Vec::new()));
        let valid = gateway(StatusCode::OK, json!({ "status": "valid" }));
        let opening = Opening::new(&api, vec![key], ORGANIZATION, &grants, &valid);
        // The file shows both values in plain text. The edit changes the literals, leaves the
        // destination as it is and marks a new one.
        let edited = json!({
            "$schema": KEY_SCHEMA,
            "limits": { "rpm": 5 },
            "plugins": {
                "export": { "destinations": [
                    { "encrypt": destination.clone() },
                    { "url": { "encrypt": "https://audit.example.com/b?token=t" } }
                ] },
                "redaction": { "literals": { "encrypt": [{ "values": ["Osprey"] }] } }
            }
        })
        .to_string();
        let (result, _) = run_edit(
            &opening,
            vec![(
                Some(json!({
                    "$schema": KEY_SCHEMA,
                    "limits": { "rpm": 5 },
                    "plugins": {
                        "export": { "destinations": [{ "encrypt": destination.clone() }] },
                        "redaction": { "literals": { "encrypt": [{ "values": ["Falcon"] }] } }
                    }
                })),
                &edited,
            )],
            vec![],
        )
        .await;
        assert_eq!(result.ok(), Some(Outcome::Saved(8)));
        // The gateway checked both plugins in plain text.
        assert_eq!(
            valid.sent.lock().unwrap()[0].1["policySources"][0]["config"],
            json!({ "plugins": {
                "export": { "destinations": [
                    destination,
                    { "url": "https://audit.example.com/b?token=t" }
                ] },
                "redaction": { "literals": [{ "values": ["Osprey"] }] }
            } })
        );
        let [(sent, 7)] = &api.sent()[..] else {
            panic!("one save with the revision it started from");
        };
        assert_eq!(sent["limits"], json!({ "rpm": 5 }));
        // The unchanged destination keeps its envelope, and the others get new ones.
        let destinations = &sent["plugins"]["export"]["destinations"];
        assert_eq!(
            destinations[0],
            stored["plugins"]["export"]["destinations"][0]
        );
        assert!(destinations[1]["url"]["encrypted"]["blob"].is_string());
        let literals = &sent["plugins"]["redaction"]["literals"]["encrypted"];
        assert_ne!(
            *literals,
            stored["plugins"]["redaction"]["literals"]["encrypted"]
        );
        assert!(!sent.to_string().contains("Osprey") && !sent.to_string().contains("audit"));
        // A second edit opens what the first one saved, and a file closed unchanged saves nothing.
        let reopened = Script::new(vec![saved(sent.clone(), 8)], vec![]);
        let opening = Opening {
            api: &reopened,
            ..opening
        };
        let (result, _) = run_edit(&opening, vec![(None, &edited)], vec![]).await;
        assert_eq!(result.ok(), Some(Outcome::Unchanged(8)));
        assert_eq!(valid.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_new_key_before_the_old_one_takes_over_its_values() {
        let old = customer_encryption::generate().unwrap();
        let new = customer_encryption::generate().unwrap();
        let new_id = new.id.clone();
        let stored = encrypted_policy(
            &old,
            json!({ "plugins": {
                "export": { "destinations": [{ "url": "https://logs.example.com/a" }] },
                "redaction": { "literals": [{ "values": ["Falcon"] }] }
            } }),
        );
        let api = Script::new(vec![saved(stored, 8)], vec![Ok(saved(Value::Null, 9))]);
        let grants = Api(Mutex::new(Vec::new()));
        let valid = gateway(StatusCode::OK, json!({ "status": "valid" }));
        let opening = Opening::new(&api, vec![new, old], ORGANIZATION, &grants, &valid);
        // The old key opens both values, and closing the file as it opened encrypts each of them
        // with the new key, after the gateway checks them.
        let unchanged = json!({ "$schema": KEY_SCHEMA, "plugins": {
            "export": { "destinations": [{ "encrypt": { "url": "https://logs.example.com/a" } }] },
            "redaction": { "literals": { "encrypt": [{ "values": ["Falcon"] }] } }
        } });
        let text = unchanged.to_string();
        let (result, _) = run_edit(&opening, vec![(Some(unchanged), &text)], vec![]).await;
        assert_eq!(result.ok(), Some(Outcome::Saved(9)));
        let [(sent, 8)] = &api.sent()[..] else {
            panic!("one save with the revision it started from");
        };
        for envelope in [
            &sent["plugins"]["export"]["destinations"][0]["encrypted"],
            &sent["plugins"]["redaction"]["literals"]["encrypted"],
        ] {
            assert_eq!(envelope["keyId"], *new_id);
        }
        assert_eq!(valid.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_mark_that_cannot_be_encrypted_opens_the_file_again() {
        let key = customer_encryption::generate().unwrap();
        let api = Script::new(vec![saved(json!({ "limits": { "rpm": 5 } }), 3)], vec![]);
        let grants = Api(Mutex::new(Vec::new()));
        let refusing = gateway(
            StatusCode::BAD_REQUEST,
            json!({ "error": { "message": "Policy configuration is invalid: unknown preset" } }),
        );
        let opening = Opening::new(&api, vec![key], ORGANIZATION, &grants, &refusing);
        // Headers are encrypted only with their URL, and the gateway refuses an unknown preset.
        // Neither reaches the dashboard, and each time the author can edit again.
        let (result, left) = run_edit(
            &opening,
            vec![
                (
                    None,
                    r#"{"plugins":{"export":{"destinations":[{"url":"https://a.example","headers":{"encrypt":{"X":"y"}}}]}}}"#,
                ),
                (
                    None,
                    r#"{"plugins":{"redaction":{"presets":{"encrypt":["email_adress"]}}}}"#,
                ),
            ],
            vec![true, false],
        )
        .await;
        let failure = result.unwrap_err();
        assert!(failure.edited);
        assert_eq!(
            failure.error.to_string(),
            "Policy configuration is invalid: unknown preset"
        );
        assert!(left.contains("email_adress"));
        assert!(api.sent().is_empty());
        assert_eq!(refusing.sent.lock().unwrap().len(), 1);
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
                    r#"{"$schema":"https://stogas.ai/schemas/policy-v1.json","limits":{"rpm":9,"tpm":200}}"#,
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
