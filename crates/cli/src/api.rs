//! `stogas api`: any dashboard API request, with the request flags of `gh api`.

use crate::{
    account,
    dashboard::{self, Dashboard, Reply},
    topup,
};
use anyhow::{Context as _, Result, bail};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
    io::{IsTerminal as _, Write},
    path::PathBuf,
};
use stogas::network::Network;

/// The placeholder that the organization's ID replaces.
const ORGANIZATION: &str = "{org}";

#[derive(clap::Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag of `gh api` is its own switch"
)]
pub struct Args {
    /// A path under /api/, such as /api/account or {org}/keys. The method can come first, as in
    /// `stogas api POST {org}/keys`.
    #[arg(value_name = "[METHOD] PATH", num_args = 1..=2, required = true)]
    request: Vec<String>,
    /// GET, POST, PUT, PATCH or DELETE. Without it, GET, or POST when fields or --input add a body.
    #[arg(short = 'X', long, value_parser = crate::method_parser(), ignore_case = true)]
    method: Option<Method>,
    /// A string field, as key=value. A key can nest, as in key[name]=value, and key[]=value adds
    /// to a list.
    #[arg(short = 'f', long = "raw-field", value_name = "KEY=VALUE")]
    raw_field: Vec<String>,
    /// A typed field, as key=value: true, false, null and integers become JSON values, @file
    /// reads a file (@- standard input), and {org} becomes the organization's ID.
    #[arg(short = 'F', long, value_name = "KEY=VALUE")]
    field: Vec<String>,
    /// A request header, as "Name: value".
    #[arg(short = 'H', long, value_name = "NAME: VALUE")]
    header: Vec<String>,
    /// Print the response status and headers before the body.
    #[arg(short = 'i', long)]
    include: bool,
    /// A file with the JSON request body, or `-` for standard input. Fields then go in the query.
    #[arg(long)]
    input: Option<PathBuf>,
    /// Get every page of a list, following each response's next cursor.
    #[arg(long)]
    paginate: bool,
    /// With --paginate, print one JSON array of every page.
    #[arg(long, requires = "paginate")]
    slurp: bool,
    /// Print no response body.
    #[arg(long)]
    silent: bool,
    /// The organization that {org} names. Without it, your personal organization.
    #[arg(long, env = "STOGAS_ORG", value_parser = topup::parse_organization)]
    organization: Option<String>,
}

pub async fn run(args: Args, network: &Network) -> Result<()> {
    let method = request_method(&args)?;
    let dashboard = account::signed_in(network).await?;
    let Request {
        path,
        query,
        headers,
        body,
    } = prepare(&args, &method, &dashboard).await?;
    let mut printer = Printer {
        out: std::io::stdout(),
        terminal: std::io::stdout().is_terminal(),
        include: args.include,
        silent: args.silent,
        slurp: args.slurp.then(Vec::new),
    };
    let (method, headers, body, dashboard) = (&method, &headers, body.as_ref(), &dashboard);
    follow(
        args.paginate,
        &path,
        query,
        &mut printer,
        move |target| async move {
            dashboard
                .exchange(method.clone(), &target, headers.clone(), body)
                .await
        },
    )
    .await
}

/// Sends the request through `exchange` and prints the reply. With `paginate`, it then asks for
/// each next page until the last one.
async fn follow<W: Write, F: Future<Output = Result<Reply>>>(
    paginate: bool,
    path: &str,
    mut query: Vec<(String, String)>,
    printer: &mut Printer<W>,
    mut exchange: impl FnMut(String) -> F,
) -> Result<()> {
    let mut cursors = HashSet::new();
    loop {
        let reply = exchange(with_query(path, &query)).await?;
        printer.status(&reply)?;
        if !reply.status.is_success() {
            // A --slurp array prints only once every page arrived, so a partial list never
            // looks whole.
            printer.slurp = None;
            printer.error_body(&reply.body)?;
            return Err(dashboard::api_error(reply.status, &reply.body).into());
        }
        if !paginate {
            return printer.body(&reply.body);
        }
        let page: Value =
            serde_json::from_slice(&reply.body).context("--paginate needs JSON pages")?;
        let cursor = next_cursor(&page).map(str::to_owned);
        printer.page(&reply.body, page)?;
        let Some(cursor) = cursor else { break };
        if !cursors.insert(cursor.clone()) {
            bail!("the API sent a page cursor twice");
        }
        query.retain(|(name, _)| name != "cursor");
        query.push(("cursor".to_owned(), cursor));
    }
    printer.finish()
}

/// The method that the flag or the path names, or else the one that the body implies.
fn request_method(args: &Args) -> Result<Method> {
    let (positional, _) = method_and_path(&args.request)?;
    let method = match (positional, args.method.clone()) {
        (Some(positional), Some(flag)) if positional != flag => {
            bail!("the path's method {positional} and -X {flag} differ")
        }
        (Some(method), _) | (None, Some(method)) => method,
        (None, None)
            if args.input.is_some() || !args.raw_field.is_empty() || !args.field.is_empty() =>
        {
            Method::POST
        }
        (None, None) => Method::GET,
    };
    if args.paginate && method != Method::GET {
        bail!("--paginate follows the pages of a GET request");
    }
    if method == Method::GET && args.input.is_some() {
        bail!("a GET request has no body; give fields for its query instead");
    }
    Ok(method)
}

struct Request {
    path: String,
    query: Vec<(String, String)>,
    headers: HeaderMap,
    body: Option<Value>,
}

/// The path, query, headers and body, with `{org}` replaced and files read.
async fn prepare(args: &Args, method: &Method, dashboard: &Dashboard) -> Result<Request> {
    let (_, path) = method_and_path(&args.request)?;
    let fields = args
        .raw_field
        .iter()
        .map(|spec| parse_field(spec, false))
        .chain(args.field.iter().map(|spec| parse_field(spec, true)))
        .collect::<Result<Vec<_>>>()?;
    let mut headers = HeaderMap::new();
    for spec in &args.header {
        let (name, value) = parse_header(spec)?;
        headers.append(name, value);
    }
    // Standard input can be read once.
    let stdin_readers = fields
        .iter()
        .filter_map(|field| match &field.value {
            Some(FieldValue::File(path)) => Some(path),
            _ => None,
        })
        .chain(&args.input)
        .filter(|path| path.as_os_str() == "-")
        .count();
    if stdin_readers > 1 {
        bail!("only one field or the body can read standard input");
    }
    let names_organization = path.contains(ORGANIZATION)
        || fields.iter().any(
            |field| matches!(&field.value, Some(FieldValue::Typed(text)) if text.contains(ORGANIZATION)),
        );
    let organization = match (names_organization, &args.organization) {
        (false, _) => None,
        (true, Some(organization)) => Some(organization.clone()),
        (true, None) => Some(account::personal_organization(dashboard).await?),
    };
    let substitute = |text: &str| {
        organization.as_ref().map_or_else(
            || text.to_owned(),
            |organization| text.replace(ORGANIZATION, organization),
        )
    };

    let (path, mut query) = api_path(&substitute(path))?;
    let in_query = *method == Method::GET || args.input.is_some();
    let mut object = Map::new();
    for field in fields {
        let value = match field.value {
            None => None,
            Some(FieldValue::Raw(text)) => Some(Value::String(text)),
            Some(FieldValue::Typed(text)) => Some(typed(&substitute(&text))),
            Some(FieldValue::File(path)) => Some(Value::String(
                String::from_utf8(
                    crate::read_bounded_input(&path, dashboard::MAX_BODY_BYTES, "a field's file")
                        .await?,
                )
                .with_context(|| format!("{} is not UTF-8 text", path.display()))?,
            )),
        };
        if in_query {
            let ([Part::Key(name)], Some(value)) = (field.parts.as_slice(), value) else {
                bail!(
                    "{}: only a plain key=value field can go in a query",
                    dashboard::printable(&field.key)
                );
            };
            query.push((name.clone(), query_text(&value)));
        } else {
            insert(&mut object, &field.parts, value, &field.key)?;
        }
    }
    let body = match &args.input {
        Some(input) => Some(
            serde_json::from_slice::<Value>(
                &crate::read_bounded_input(input, dashboard::MAX_BODY_BYTES, "request body")
                    .await?,
            )
            .context("the request body is not JSON")?,
        ),
        None => (!object.is_empty()).then_some(Value::Object(object)),
    };
    Ok(Request {
        path,
        query,
        headers,
        body,
    })
}

/// The method that can come before the path, and the path.
fn method_and_path(request: &[String]) -> Result<(Option<Method>, &str)> {
    match request {
        [path] => Ok((None, path)),
        [method, path] => Ok((Some(parse_method(method)?), path)),
        _ => bail!("give a path, after its method if you like"),
    }
}

fn parse_method(text: &str) -> Result<Method> {
    Ok(match text.to_ascii_uppercase().as_str() {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "PATCH" => Method::PATCH,
        "DELETE" => Method::DELETE,
        _ => bail!(
            "{} is not GET, POST, PUT, PATCH or DELETE",
            dashboard::printable(text)
        ),
    })
}

/// The path under /api/ and the query that it carries. `/api/` is optional.
fn api_path(text: &str) -> Result<(String, Vec<(String, String)>)> {
    let (path, query) = text.split_once('?').unwrap_or((text, ""));
    let path = path.trim();
    let rest = path.strip_prefix('/').unwrap_or(path);
    let rest = rest.strip_prefix("api/").unwrap_or(rest);
    if rest.is_empty() || rest == "api" {
        bail!("name a path under /api/, such as /api/account");
    }
    let query = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    Ok((format!("/api/{rest}"), query))
}

fn with_query(path: &str, query: &[(String, String)]) -> String {
    if query.is_empty() {
        return path.to_owned();
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query)
        .finish();
    format!("{path}?{query}")
}

#[derive(Debug, PartialEq)]
enum Part {
    Key(String),
    /// `[]`: the next item of a list.
    Append,
}

#[derive(Debug, PartialEq)]
enum FieldValue {
    Raw(String),
    Typed(String),
    File(PathBuf),
}

#[derive(Debug, PartialEq)]
struct Field {
    key: String,
    parts: Vec<Part>,
    /// None for `key[]` alone, an empty list.
    value: Option<FieldValue>,
}

fn parse_field(spec: &str, typed: bool) -> Result<Field> {
    let (key, value) = match spec.split_once('=') {
        Some((key, value)) => (key, Some(value)),
        None if spec.ends_with("[]") => (spec, None),
        None => bail!("{}: a field is key=value", dashboard::printable(spec)),
    };
    let parts = parse_key(key)?;
    let value = value.map(|value| match value.strip_prefix('@') {
        Some(path) if typed => {
            if path.is_empty() {
                bail!("{}: name a file after @", dashboard::printable(key));
            }
            Ok(FieldValue::File(PathBuf::from(path)))
        }
        _ if typed => Ok(FieldValue::Typed(value.to_owned())),
        _ => Ok(FieldValue::Raw(value.to_owned())),
    });
    Ok(Field {
        key: key.to_owned(),
        parts,
        value: value.transpose()?,
    })
}

/// `name`, then any number of `[key]` or `[]`.
fn parse_key(key: &str) -> Result<Vec<Part>> {
    let invalid = || anyhow::anyhow!("{} is not a field name", dashboard::printable(key));
    let (name, mut rest) = key.find('[').map_or((key, ""), |at| key.split_at(at));
    if name.is_empty() || name.contains(']') {
        return Err(invalid());
    }
    let mut parts = vec![Part::Key(name.to_owned())];
    while !rest.is_empty() {
        let inner = rest.strip_prefix('[').ok_or_else(invalid)?;
        let (segment, after) = inner.split_once(']').ok_or_else(invalid)?;
        if segment.contains('[') {
            return Err(invalid());
        }
        parts.push(if segment.is_empty() {
            Part::Append
        } else {
            Part::Key(segment.to_owned())
        });
        rest = after;
    }
    Ok(parts)
}

/// `true`, `false`, `null` and integers as JSON values, and any other text as a string.
fn typed(text: &str) -> Value {
    match text {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "null" => Value::Null,
        _ => {
            let digits = text.strip_prefix('-').unwrap_or(text);
            let canonical = !digits.is_empty()
                && digits.bytes().all(|byte| byte.is_ascii_digit())
                && (digits == "0" || !digits.starts_with('0'));
            match text.parse::<i64>() {
                Ok(number) if canonical && text != "-0" => Value::from(number),
                _ => Value::String(text.to_owned()),
            }
        }
    }
}

fn query_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        value => value.to_string(),
    }
}

/// Puts `value` at `parts` in `object`. `[]` adds to a list, and `[][key]` fills the list's last
/// object until it already has that key, as `gh api` does. A key that another field set, even to
/// null, conflicts.
fn insert(
    object: &mut Map<String, Value>,
    parts: &[Part],
    value: Option<Value>,
    key: &str,
) -> Result<()> {
    let conflict = || anyhow::anyhow!("{} conflicts with another field", dashboard::printable(key));
    // parse_key starts every field and every list item with a name.
    let Some((Part::Key(name), rest)) = parts.split_first() else {
        return Err(conflict());
    };
    match rest.split_first() {
        None => {
            if object.contains_key(name) {
                return Err(conflict());
            }
            let value = value.ok_or_else(|| {
                anyhow::anyhow!("{}: a field is key=value", dashboard::printable(key))
            })?;
            object.insert(name.clone(), value);
            Ok(())
        }
        Some((Part::Key(_), _)) => {
            let Value::Object(inner) = object
                .entry(name.clone())
                .or_insert_with(|| Value::Object(Map::new()))
            else {
                return Err(conflict());
            };
            insert(inner, rest, value, key)
        }
        Some((Part::Append, after)) => {
            let Value::Array(items) = object
                .entry(name.clone())
                .or_insert_with(|| Value::Array(Vec::new()))
            else {
                return Err(conflict());
            };
            match after.first() {
                None => {
                    items.extend(value);
                    Ok(())
                }
                Some(Part::Key(next)) => {
                    if !matches!(
                        items.last(),
                        Some(Value::Object(last)) if !last.contains_key(next)
                    ) {
                        items.push(Value::Object(Map::new()));
                    }
                    let Some(Value::Object(last)) = items.last_mut() else {
                        return Err(conflict());
                    };
                    insert(last, after, value, key)
                }
                Some(Part::Append) => bail!(
                    "{}: a list of lists needs --input",
                    dashboard::printable(key)
                ),
            }
        }
    }
}

fn parse_header(spec: &str) -> Result<(HeaderName, HeaderValue)> {
    let (name, value) = spec.split_once(':').with_context(|| {
        format!(
            "{}: a header is \"Name: value\"",
            dashboard::printable(spec)
        )
    })?;
    let name = HeaderName::from_bytes(name.trim().as_bytes())
        .with_context(|| format!("{} is not a header name", dashboard::printable(name)))?;
    let value = HeaderValue::from_str(value.trim())
        .with_context(|| format!("the {name} header has characters that a header cannot carry"))?;
    Ok((name, value))
}

/// A list page's cursor for the next page, under either name that the API uses.
fn next_cursor(page: &Value) -> Option<&str> {
    ["nextCursor", "next_cursor"]
        .iter()
        .find_map(|name| page.get(name)?.as_str())
        .filter(|cursor| !cursor.is_empty())
}

struct Printer<W> {
    out: W,
    terminal: bool,
    include: bool,
    silent: bool,
    /// The pages of --slurp, printed as one list at the end.
    slurp: Option<Vec<Value>>,
}

impl<W: Write> Printer<W> {
    fn status(&mut self, reply: &Reply) -> Result<()> {
        if !self.include {
            return Ok(());
        }
        writeln!(self.out, "HTTP {}", reply.status)?;
        for (name, value) in &reply.headers {
            writeln!(
                self.out,
                "{name}: {}",
                dashboard::printable(&String::from_utf8_lossy(value.as_bytes()))
            )?;
        }
        writeln!(self.out)?;
        Ok(())
    }

    /// A terminal gets formatted JSON with control characters made inert; anything else gets the
    /// exact bytes.
    fn body(&mut self, body: &[u8]) -> Result<()> {
        if self.silent || body.is_empty() {
            return Ok(());
        }
        if !self.terminal {
            self.out.write_all(body)?;
            return Ok(());
        }
        let value: Value = serde_json::from_slice(body)
            .context("the response is not JSON; send it to a file instead")?;
        print_value(&mut self.out, &value)
    }

    /// A refusal's body. A terminal shows it only when it is JSON, since the error names the
    /// status either way.
    fn error_body(&mut self, body: &[u8]) -> Result<()> {
        if self.terminal && serde_json::from_slice::<Value>(body).is_err() {
            return Ok(());
        }
        self.body(body)
    }

    /// Each page as its own JSON document, one after another, or saved for --slurp.
    fn page(&mut self, body: &[u8], page: Value) -> Result<()> {
        if let Some(pages) = &mut self.slurp {
            pages.push(page);
            return Ok(());
        }
        self.body(body)?;
        if !self.terminal && !self.silent && !body.ends_with(b"\n") {
            self.out.write_all(b"\n")?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let Some(pages) = self.slurp.take() else {
            return Ok(());
        };
        if self.silent {
            return Ok(());
        }
        let pages = Value::Array(pages);
        if self.terminal {
            print_value(&mut self.out, &pages)
        } else {
            serde_json::to_writer(&mut self.out, &pages)?;
            self.out.write_all(b"\n")?;
            Ok(())
        }
    }
}

fn print_value(stdout: &mut impl Write, value: &Value) -> Result<()> {
    for line in serde_json::to_string_pretty(value)?.lines() {
        writeln!(stdout, "{}", dashboard::printable(line))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn takes_the_method_before_the_path_or_infers_it() {
        let request = |items: &[&str]| {
            items
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>()
        };
        let two = request(&["get", "/api/account"]);
        assert_eq!(
            method_and_path(&two).unwrap(),
            (Some(Method::GET), "/api/account")
        );
        let one = request(&["{org}/keys"]);
        assert_eq!(method_and_path(&one).unwrap(), (None, "{org}/keys"));
        assert!(method_and_path(&request(&["FETCH", "/api/account"])).is_err());
        assert!(method_and_path(&request(&["/api/account", "/api/keys"])).is_err());
    }

    #[test]
    fn keeps_every_path_under_api_with_its_query() {
        assert_eq!(
            api_path("/api/account").unwrap(),
            ("/api/account".to_owned(), vec![])
        );
        assert_eq!(api_path("account").unwrap().0, "/api/account");
        assert_eq!(api_path("api/account").unwrap().0, "/api/account");
        assert_eq!(api_path("/account").unwrap().0, "/api/account");
        assert_eq!(
            api_path("x/keys?limit=5&filter=name%3Aa+b").unwrap(),
            (
                "/api/x/keys".to_owned(),
                vec![
                    ("limit".into(), "5".into()),
                    ("filter".into(), "name:a b".into())
                ]
            )
        );
        for path in ["", "/", "/api", "/api/", "api"] {
            assert!(api_path(path).is_err(), "{path}");
        }
        assert_eq!(
            with_query(
                "/api/x",
                &[
                    ("filter".into(), "a b&c".into()),
                    ("cursor".into(), "=".into())
                ]
            ),
            "/api/x?filter=a+b%26c&cursor=%3D"
        );
        assert_eq!(with_query("/api/x", &[]), "/api/x");
    }

    #[test]
    fn reads_field_names_with_nested_keys_and_lists() {
        assert_eq!(parse_key("name").unwrap(), vec![Part::Key("name".into())]);
        assert_eq!(
            parse_key("a[b][]").unwrap(),
            vec![Part::Key("a".into()), Part::Key("b".into()), Part::Append]
        );
        for key in ["", "[a]", "a[b", "a]b", "a[b]c", "a[[b]]", "a[b]]"] {
            assert!(parse_key(key).is_err(), "{key}");
        }
        assert_eq!(
            parse_field("tags[]", true).unwrap(),
            Field {
                key: "tags[]".into(),
                parts: vec![Part::Key("tags".into()), Part::Append],
                value: None
            }
        );
        assert!(parse_field("name", true).is_err());
        assert!(parse_field("file=@", true).is_err());
        assert_eq!(
            parse_field("file=@body.txt", true).unwrap().value,
            Some(FieldValue::File("body.txt".into()))
        );
        // -f keeps text as it is, @ included.
        assert_eq!(
            parse_field("handle=@me", false).unwrap().value,
            Some(FieldValue::Raw("@me".into()))
        );
        assert_eq!(
            parse_field("expression=a=b", true).unwrap().value,
            Some(FieldValue::Typed("a=b".into()))
        );
    }

    #[test]
    fn types_only_literal_booleans_null_and_canonical_integers() {
        assert_eq!(typed("true"), json!(true));
        assert_eq!(typed("false"), json!(false));
        assert_eq!(typed("null"), Value::Null);
        assert_eq!(typed("42"), json!(42));
        assert_eq!(typed("-7"), json!(-7));
        assert_eq!(typed("0"), json!(0));
        for text in [
            "007",
            "-0",
            "1.5",
            "1e3",
            "9223372036854775808",
            "",
            "-",
            "True",
            "+1",
        ] {
            assert_eq!(typed(text), Value::String(text.to_owned()), "{text}");
        }
        assert_eq!(query_text(&json!(5)), "5");
        assert_eq!(query_text(&Value::Null), "");
        assert_eq!(query_text(&json!("a b")), "a b");
    }

    #[test]
    fn builds_nested_objects_and_lists_like_gh_api() {
        let mut body = Map::new();
        for (key, value) in [
            ("name", Some(json!("Build bot"))),
            ("limits[requests]", Some(json!(10))),
            ("limits[models][]", Some(json!("gpt-5.6-sol"))),
            ("limits[models][]", Some(json!("claude-fable-5-1"))),
            ("rules[][name]", Some(json!("first"))),
            ("rules[][value]", Some(json!(1))),
            ("rules[][name]", Some(json!("second"))),
            ("tags[]", None),
        ] {
            insert(&mut body, &parse_key(key).unwrap(), value, key).unwrap();
        }
        assert_eq!(
            Value::Object(body.clone()),
            json!({
                "name": "Build bot",
                "limits": { "requests": 10, "models": ["gpt-5.6-sol", "claude-fable-5-1"] },
                "rules": [{ "name": "first", "value": 1 }, { "name": "second" }],
                "tags": []
            })
        );
        for key in [
            "name",
            "name[first]",
            "limits",
            "limits[models][x]",
            "tags[][]",
        ] {
            let mut copy = body.clone();
            assert!(
                insert(&mut copy, &parse_key(key).unwrap(), Some(json!(1)), key).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn a_key_set_to_null_conflicts_in_either_order() {
        for pair in [
            [("limit", Value::Null), ("limit", json!(20))],
            [("limit", json!(20)), ("limit", Value::Null)],
            [("a", Value::Null), ("a[b]", json!(1))],
            [("a[b]", json!(1)), ("a", Value::Null)],
            [("a", Value::Null), ("a[]", json!(1))],
        ] {
            let mut body = Map::new();
            let [(first, one), (second, two)] = pair;
            insert(&mut body, &parse_key(first).unwrap(), Some(one), first).unwrap();
            assert!(
                insert(&mut body, &parse_key(second).unwrap(), Some(two), second).is_err(),
                "{first} then {second}"
            );
        }
        // A list item that has the key already starts the next item, as with any other value.
        let mut body = Map::new();
        for (key, value) in [
            ("rules[][name]", Value::Null),
            ("rules[][name]", json!("b")),
        ] {
            insert(&mut body, &parse_key(key).unwrap(), Some(value), key).unwrap();
        }
        assert_eq!(
            Value::Object(body),
            json!({ "rules": [{ "name": null }, { "name": "b" }] })
        );
    }

    #[test]
    fn reads_headers_and_refuses_ones_that_could_carry_other_lines() {
        let (name, value) = parse_header("Accept: text/csv").unwrap();
        assert_eq!(
            (name.as_str(), value.to_str().unwrap()),
            ("accept", "text/csv")
        );
        assert_eq!(
            parse_header("If-Match:\"3\"").unwrap().1.to_str().unwrap(),
            "\"3\""
        );
        for spec in ["NoColon", "Bad Name: x", ": x", "X-Test: a\r\nInjected: b"] {
            assert!(parse_header(spec).is_err(), "{spec:?}");
        }
    }

    #[test]
    fn follows_either_cursor_name_until_the_last_page() {
        assert_eq!(
            next_cursor(&json!({ "items": [], "nextCursor": "c2" })),
            Some("c2")
        );
        assert_eq!(
            next_cursor(&json!({ "entries": [], "next_cursor": "c3" })),
            Some("c3")
        );
        assert_eq!(
            next_cursor(&json!({ "items": [], "nextCursor": null })),
            None
        );
        assert_eq!(next_cursor(&json!({ "items": [], "nextCursor": "" })), None);
        assert_eq!(next_cursor(&json!([1, 2])), None);
    }

    /// Runs `follow` against `pages`, which answer the requests in order, and returns the paths
    /// that it asked for, what it printed and its result.
    async fn follow_pages(
        paginate: bool,
        slurp: bool,
        pages: &[(u16, Value)],
    ) -> (Vec<String>, String, Result<()>) {
        let mut printer = Printer {
            out: Vec::new(),
            terminal: false,
            include: false,
            silent: false,
            slurp: slurp.then(Vec::new),
        };
        let mut asked = Vec::new();
        let mut replies = pages.iter();
        let query = vec![("limit".to_owned(), "2".to_owned())];
        let result = follow(paginate, "/api/x/keys", query, &mut printer, |target| {
            asked.push(target);
            let (status, body) = replies.next().expect("a request past the last page");
            let reply = Reply {
                status: http::StatusCode::from_u16(*status).unwrap(),
                headers: HeaderMap::new(),
                body: serde_json::to_vec(body).unwrap(),
            };
            async move { Ok(reply) }
        })
        .await;
        (asked, String::from_utf8(printer.out).unwrap(), result)
    }

    #[tokio::test]
    async fn follows_each_next_cursor_until_the_last_page() {
        let served = [
            (200, json!({ "items": [1, 2], "nextCursor": "c2" })),
            (200, json!({ "items": [3, 4], "nextCursor": "c3" })),
            (200, json!({ "items": [5], "nextCursor": null })),
        ];
        let pages: Vec<Value> = served.iter().map(|(_, page)| page.clone()).collect();
        let (asked, printed, result) = follow_pages(true, true, &served).await;
        result.unwrap();
        assert_eq!(
            asked,
            [
                "/api/x/keys?limit=2",
                "/api/x/keys?limit=2&cursor=c2",
                "/api/x/keys?limit=2&cursor=c3"
            ]
        );
        assert_eq!(
            serde_json::from_str::<Value>(&printed).unwrap(),
            Value::Array(pages.clone())
        );
        // Without --slurp, each page prints as its own line as it arrives.
        let (_, printed, result) = follow_pages(true, false, &served).await;
        result.unwrap();
        let lines: Vec<Value> = printed
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines, pages);
        // Without --paginate, the first page is the whole answer.
        let (asked, printed, result) = follow_pages(false, false, &served).await;
        result.unwrap();
        assert_eq!(asked, ["/api/x/keys?limit=2"]);
        assert_eq!(serde_json::from_str::<Value>(&printed).unwrap(), pages[0]);
    }

    #[tokio::test]
    async fn a_failed_page_or_a_repeated_cursor_prints_no_slurp_array() {
        let refused = json!({ "code": "UNAUTHORIZED", "message": "Your token expired." });
        let (asked, printed, result) = follow_pages(
            true,
            true,
            &[
                (200, json!({ "items": [1], "nextCursor": "c2" })),
                (401, refused.clone()),
            ],
        )
        .await;
        assert!(result.is_err());
        assert_eq!(asked.len(), 2);
        assert_eq!(serde_json::from_str::<Value>(&printed).unwrap(), refused);

        let (asked, printed, result) = follow_pages(
            true,
            true,
            &[
                (200, json!({ "items": [1], "nextCursor": "c2" })),
                (200, json!({ "items": [2], "nextCursor": "c2" })),
            ],
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "the API sent a page cursor twice"
        );
        assert_eq!(asked.len(), 2);
        assert_eq!(printed, "");
    }
}
