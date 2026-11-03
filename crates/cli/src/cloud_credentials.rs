//! Checks an AWS, Azure or Google Cloud credential document with the rules gateways use, before it
//! is encrypted, and derives the public target that lets routing choose an AWS or Google Cloud
//! credential without decrypting it. An Azure credential needs no target: gateways discover the
//! account's deployments with it.

use anyhow::{Result, bail};
use aws_lc_rs::signature::RsaKeyPair;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

const AWS_SCHEMA: &str = "stogas.aws-byok.v1";
const AZURE_SCHEMA: &str = "stogas.azure-byok.v6";
const GOOGLE_SCHEMA: &str = "stogas.google-cloud-byok.v1";

pub struct Registration {
    pub plaintext: Zeroizing<Vec<u8>>,
    /// What the dashboard shows of the secret. An Azure credential shows the name of the account
    /// that it connects instead, which the dashboard asks for.
    pub preview: Option<String>,
    pub target: Option<Value>,
}

/// Prepares a provider credential for `byok/{provider}`. AWS and Google Cloud take a credential
/// document, and Google Cloud also takes the key file it downloads. Azure takes the application's
/// tenant ID, client ID and client secret, or what `az ad sp create-for-rbac` prints. Other
/// providers take the key exactly as given.
pub fn prepare(purpose: &str, input: &[u8]) -> Result<Registration> {
    match purpose {
        "byok/aws" => aws(&object(input)?),
        "byok/azure" => azure(&object(input)?),
        "byok/google-cloud" => google(&object(input)?),
        _ => {
            let shown =
                String::from_utf8_lossy(&input[input.len().saturating_sub(4)..]).into_owned();
            Ok(Registration {
                plaintext: Zeroizing::new(input.to_vec()),
                preview: Some(format!("•••• {shown}")),
                target: None,
            })
        }
    }
}

/// Reads a JSON object as UTF-8, or as UTF-16 after its byte order mark, which Windows
/// PowerShell 5.1 writes when it saves a command's output with `>`.
fn object(input: &[u8]) -> Result<Map<String, Value>> {
    let decoded = match input {
        [0xff, 0xfe, rest @ ..] | [0xfe, 0xff, rest @ ..] if rest.len() % 2 == 0 => {
            let units = rest.chunks_exact(2).map(|pair| {
                if input[0] == 0xff {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            });
            char::decode_utf16(units)
                .collect::<Result<String, _>>()
                .ok()
                .map(|text| Zeroizing::new(text.into_bytes()))
        }
        [0xef, 0xbb, 0xbf, rest @ ..] => Some(Zeroizing::new(rest.to_vec())),
        _ => Some(Zeroizing::new(input.to_vec())),
    };
    match decoded.map(|bytes| serde_json::from_slice(&bytes)) {
        Some(Ok(Value::Object(map))) => Ok(map),
        _ => bail!("The credential must be a JSON object"),
    }
}

fn field<'a>(map: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>> {
    match map.get(name) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => bail!("{name} must be a string"),
    }
}

fn required<'a>(map: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    field(map, name)?.ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

fn only(map: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    if let Some(key) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        bail!("{key} is not a credential field");
    }
    Ok(())
}

fn chars(value: &str, allowed: impl Fn(char) -> bool) -> bool {
    value.chars().all(allowed)
}

// Commercial Regions only, such as us-east-1.
fn aws_region(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    let [area, direction, number] = parts.as_slice() else {
        return false;
    };
    ["af", "ap", "ca", "eu", "il", "me", "mx", "sa", "us"].contains(area)
        && [
            "central",
            "east",
            "west",
            "north",
            "south",
            "northeast",
            "northwest",
            "southeast",
            "southwest",
        ]
        .contains(direction)
        && (1..=2).contains(&number.len())
        && !number.starts_with('0')
        && chars(number, |c| c.is_ascii_digit())
}

fn workspace(value: &str) -> bool {
    value.strip_prefix("wrkspc_").is_some_and(|rest| {
        (1..=64).contains(&rest.len()) && chars(rest, |c| c.is_ascii_alphanumeric())
    })
}

fn printable(value: &str) -> bool {
    (1..=4096).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn last4(value: &str) -> String {
    format!("•••• {}", &value[value.len().saturating_sub(4)..])
}

fn aws(map: &Map<String, Value>) -> Result<Registration> {
    only(
        map,
        &[
            "schema",
            "region",
            "accessKeyId",
            "secretAccessKey",
            "apiKey",
            "workspaceId",
        ],
    )?;
    if required(map, "schema")? != AWS_SCHEMA {
        bail!("schema must be {AWS_SCHEMA}");
    }
    let region = required(map, "region")?;
    if !aws_region(region) {
        bail!("region must be a commercial AWS Region, such as us-east-1");
    }
    let workspace_id = field(map, "workspaceId")?;
    if workspace_id.is_some_and(|value| !workspace(value)) {
        bail!("workspaceId must be the ID of an Anthropic workspace, such as wrkspc_01...");
    }
    let mut document = Map::new();
    document.insert("schema".into(), AWS_SCHEMA.into());
    document.insert("region".into(), region.into());
    let (hosting, shown) = match (field(map, "accessKeyId")?, field(map, "apiKey")?) {
        (Some(key_id), None) => {
            let secret = required(map, "secretAccessKey")?;
            if key_id.len() != 20
                || !key_id.starts_with("AKIA")
                || !chars(key_id, |c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                bail!("accessKeyId must be a long-term access key ID (AKIA...)");
            }
            if secret.len() != 40
                || !chars(secret, |c| {
                    c.is_ascii_alphanumeric() || c == '/' || c == '+'
                })
            {
                bail!("secretAccessKey must be the 40-character secret access key");
            }
            document.insert("accessKeyId".into(), key_id.into());
            document.insert("secretAccessKey".into(), secret.into());
            let hosting = if workspace_id.is_some() {
                vec!["anthropic", "aws"]
            } else {
                vec!["aws"]
            };
            (hosting, key_id)
        }
        (None, Some(api_key)) if map.get("secretAccessKey").is_none() => {
            if !printable(api_key) {
                bail!("apiKey must be printable ASCII without spaces");
            }
            document.insert("apiKey".into(), api_key.into());
            (
                vec![if workspace_id.is_some() {
                    "anthropic"
                } else {
                    "aws"
                }],
                api_key,
            )
        }
        _ => bail!("Give either accessKeyId with secretAccessKey, or apiKey"),
    };
    if let Some(value) = workspace_id {
        document.insert("workspaceId".into(), value.into());
    }
    Ok(Registration {
        plaintext: Zeroizing::new(serde_json::to_vec(&document)?),
        preview: Some(last4(shown)),
        target: Some(json!({ "hosting": hosting, "region": region })),
    })
}

/// A Microsoft Entra ID in lowercase, as gateways compare it, if it is one.
fn entra_id(value: &str) -> Option<String> {
    let id = value.trim().to_ascii_lowercase();
    let valid = id.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && chars(&id, |c| {
            c == '-' || c.is_ascii_digit() || ('a'..='f').contains(&c)
        })
        && (b'1'..=b'8').contains(&id.as_bytes()[14])
        && matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b');
    valid.then_some(id)
}

// The application that gateways sign in to Microsoft Entra ID as. The Azure CLI prints it as
// `tenant`, `appId` and `password`, and the dashboard asks for it as tenant ID, client ID and
// client secret.
fn azure(map: &Map<String, Value>) -> Result<Registration> {
    let [tenant, client, secret] = if map.contains_key("appId") {
        only(map, &["appId", "displayName", "password", "tenant"])?;
        field(map, "displayName")?;
        ["tenant", "appId", "password"]
    } else {
        only(map, &["schema", "tenantId", "clientId", "clientSecret"])?;
        if field(map, "schema")?.is_some_and(|schema| schema != AZURE_SCHEMA) {
            bail!("schema must be {AZURE_SCHEMA}");
        }
        ["tenantId", "clientId", "clientSecret"]
    };
    let Some(tenant_id) = entra_id(required(map, tenant)?) else {
        bail!("{tenant} must be the ID of your Microsoft Entra tenant");
    };
    let Some(client_id) = entra_id(required(map, client)?) else {
        bail!("{client} must be the application (client) ID");
    };
    let client_secret = required(map, secret)?;
    if !printable(client_secret) {
        bail!("{secret} must be the client secret, in printable ASCII without spaces");
    }
    // The keys in the order that Control writes them, so the same application encrypts alike.
    let document = json!({
        "clientId": client_id,
        "clientSecret": client_secret,
        "schema": AZURE_SCHEMA,
        "tenantId": tenant_id,
    });
    Ok(Registration {
        plaintext: Zeroizing::new(serde_json::to_vec(&document)?),
        preview: None,
        target: None,
    })
}

// Google's key file names its fields its own way and wraps the key in PEM.
fn from_key_file(map: &Map<String, Value>) -> Result<Option<Value>> {
    if map.get("type").and_then(Value::as_str) != Some("service_account") {
        return Ok(None);
    }
    let body: String = required(map, "private_key")?
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .split_whitespace()
        .collect();
    Ok(Some(json!({
        "schema": GOOGLE_SCHEMA,
        "projectId": required(map, "project_id")?,
        "clientEmail": required(map, "client_email")?,
        "privateKeyId": required(map, "private_key_id")?,
        "privateKey": body,
    })))
}

fn google(map: &Map<String, Value>) -> Result<Registration> {
    let converted = from_key_file(map)?;
    let map = converted.as_ref().and_then(Value::as_object).unwrap_or(map);
    only(
        map,
        &[
            "schema",
            "projectId",
            "clientEmail",
            "privateKeyId",
            "privateKey",
            "workspaceId",
        ],
    )?;
    if required(map, "schema")? != GOOGLE_SCHEMA {
        bail!("schema must be {GOOGLE_SCHEMA}");
    }
    let project = required(map, "projectId")?;
    if !(6..=30).contains(&project.len())
        || !project.starts_with(|c: char| c.is_ascii_lowercase())
        || project.ends_with('-')
        || !chars(project, |c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
        })
    {
        bail!("projectId must be a Google Cloud project ID");
    }
    let email = required(map, "clientEmail")?;
    let valid_email = email.split_once('@').is_some_and(|(name, domain)| {
        (1..=63).contains(&name.len())
            && !name.starts_with('-')
            && chars(name, |c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
            })
            && domain
                .strip_suffix(".gserviceaccount.com")
                .is_some_and(|host| {
                    !host.is_empty()
                        && host.len() <= 201
                        && !host.starts_with(['.', '-'])
                        && chars(host, |c| {
                            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'
                        })
                })
    });
    if !valid_email {
        bail!("clientEmail must be a service account email");
    }
    let key_id = required(map, "privateKeyId")?;
    if key_id.len() != 40 || !chars(key_id, |c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
        bail!("privateKeyId must be the private_key_id from the key file");
    }
    let private_key = required(map, "privateKey")?;
    let der = Zeroizing::new(
        STANDARD
            .decode(private_key)
            .map_err(|_| anyhow::anyhow!("privateKey must be the key in base64"))?,
    );
    match RsaKeyPair::from_pkcs8(&der) {
        Ok(key) if key.public_modulus_len() >= 256 => {}
        _ => bail!("privateKey must be an RSA key of at least 2048 bits in PKCS #8 form"),
    }
    let workspace_id = field(map, "workspaceId")?;
    if workspace_id.is_some_and(|value| !workspace(value)) {
        bail!("workspaceId must be the ID of an Anthropic workspace, such as wrkspc_01...");
    }
    let mut document = Map::new();
    document.insert("schema".into(), GOOGLE_SCHEMA.into());
    document.insert("projectId".into(), project.into());
    document.insert("clientEmail".into(), email.into());
    document.insert("privateKeyId".into(), key_id.into());
    document.insert("privateKey".into(), private_key.into());
    if let Some(value) = workspace_id {
        document.insert("workspaceId".into(), value.into());
    }
    let hosting = if workspace_id.is_some() {
        vec!["anthropic", "google"]
    } else {
        vec!["google"]
    };
    Ok(Registration {
        plaintext: Zeroizing::new(serde_json::to_vec(&document)?),
        preview: Some(last4(key_id)),
        target: Some(json!({ "hosting": hosting })),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IAM: &str = r#"{
        "schema": "stogas.aws-byok.v1",
        "region": "us-east-1",
        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "workspaceId": "wrkspc_01Test"
    }"#;

    #[test]
    fn aws_documents_become_compact_with_their_target() {
        let registration = prepare("byok/aws", IAM.as_bytes()).unwrap();
        assert!(!registration.plaintext.iter().any(u8::is_ascii_whitespace));
        assert_eq!(registration.preview.as_deref(), Some("•••• MPLE"));
        assert_eq!(
            registration.target.unwrap(),
            json!({"hosting": ["anthropic", "aws"], "region": "us-east-1"})
        );
        let api = prepare(
            "byok/aws",
            br#"{"schema":"stogas.aws-byok.v1","region":"eu-west-1","apiKey":"bedrock-key"}"#,
        )
        .unwrap();
        assert_eq!(
            api.target.unwrap(),
            json!({"hosting": ["aws"], "region": "eu-west-1"})
        );
        for bad in [
            IAM.replace("us-east-1", "us-gov-west-1"),
            IAM.replace("AKIA", "ASIA"),
            IAM.replace("wrkspc_01Test", "workspace"),
            IAM.replace("\"region\"", "\"sessionToken\": \"x\", \"region\""),
            IAM.replace("\"accessKeyId\"", "\"apiKey\": \"x\", \"accessKeyId\""),
            IAM.replace("v1", "v0"),
        ] {
            assert!(prepare("byok/aws", bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn google_key_files_become_documents() {
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let der =
            aws_lc_rs::encoding::AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&key).unwrap();
        let body = STANDARD.encode(der.as_ref());
        let wrapped: Vec<String> = body
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        let key_file = json!({
            "type": "service_account",
            "project_id": "stogas-test",
            "private_key_id": "0123456789abcdef0123456789abcdef01234567",
            "private_key": format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", wrapped.join("\n")),
            "client_email": "runner@stogas-test.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        });
        let registration = prepare("byok/google-cloud", key_file.to_string().as_bytes()).unwrap();
        let document: Value = serde_json::from_slice(&registration.plaintext).unwrap();
        assert_eq!(document["privateKey"], body);
        assert_eq!(document["schema"], GOOGLE_SCHEMA);
        assert_eq!(registration.target.unwrap(), json!({"hosting": ["google"]}));
        let mut bad = key_file;
        bad["client_email"] = "person@example.com".into();
        assert!(prepare("byok/google-cloud", bad.to_string().as_bytes()).is_err());
    }

    #[test]
    fn azure_applications_become_the_document_that_gateways_read() {
        let expected = br#"{"clientId":"5a9d1c2e-7b3f-4e8a-9c1d-2e3f4a5b6c7d","clientSecret":"Q~abc.DEF_123-xyz","schema":"stogas.azure-byok.v6","tenantId":"0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"}"#;
        // What the dashboard asks for, with IDs as Azure may show them, and the document itself.
        let fields = json!({
            "tenantId": " 0F1E2D3C-4B5A-4968-8776-A5B4C3D2E1F0 ",
            "clientId": "5A9D1C2E-7B3F-4E8A-9C1D-2E3F4A5B6C7D",
            "clientSecret": "Q~abc.DEF_123-xyz",
        });
        let mut document = fields.clone();
        document["schema"] = AZURE_SCHEMA.into();
        // What `az ad sp create-for-rbac` prints.
        let az = json!({
            "appId": "5a9d1c2e-7b3f-4e8a-9c1d-2e3f4a5b6c7d",
            "displayName": "stogas-gateway",
            "password": "Q~abc.DEF_123-xyz",
            "tenant": "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0",
        });
        let pretty = serde_json::to_string_pretty(&az).unwrap();
        // Windows PowerShell 5.1 saves output with `>` in UTF-16 after a byte order mark.
        let mut utf16 = vec![0xff, 0xfe];
        utf16.extend(pretty.encode_utf16().flat_map(u16::to_le_bytes));
        let mut big_endian = vec![0xfe, 0xff];
        big_endian.extend(pretty.encode_utf16().flat_map(u16::to_be_bytes));
        let mut utf8 = vec![0xef, 0xbb, 0xbf];
        utf8.extend(pretty.as_bytes());
        for input in [
            fields.to_string().into_bytes(),
            document.to_string().into_bytes(),
            pretty.clone().into_bytes(),
            utf16,
            big_endian,
            utf8,
        ] {
            let registration = prepare("byok/azure", &input).unwrap();
            assert_eq!(registration.plaintext.as_slice(), expected.as_slice());
            assert_eq!(registration.preview, None);
            assert_eq!(registration.target, None);
        }
        let error = |input: Value| {
            prepare("byok/azure", input.to_string().as_bytes())
                .err()
                .unwrap()
                .to_string()
        };
        let with = |base: &Value, name: &str, value: Value| {
            let mut changed = base.clone();
            changed[name] = value;
            changed
        };
        assert_eq!(
            error(with(&az, "tenant", "contoso.onmicrosoft.com".into())),
            "tenant must be the ID of your Microsoft Entra tenant"
        );
        assert_eq!(
            error(with(
                &fields,
                "clientId",
                "00000000-0000-0000-0000-000000000000".into()
            )),
            "clientId must be the application (client) ID"
        );
        assert_eq!(
            error(with(&az, "password", "two words".into())),
            "password must be the client secret, in printable ASCII without spaces"
        );
        assert_eq!(
            error(with(&fields, "clientSecret", "x".repeat(4097).into())),
            "clientSecret must be the client secret, in printable ASCII without spaces"
        );
        assert_eq!(
            error(with(&az, "clientSecret", "x".into())),
            "clientSecret is not a credential field"
        );
        assert_eq!(
            error(with(&document, "schema", "stogas.azure-byok.v5".into())),
            "schema must be stogas.azure-byok.v6"
        );
        assert_eq!(
            error(with(&az, "displayName", 7.into())),
            "displayName must be a string"
        );
        assert_eq!(
            error(json!({ "tenantId": fields["tenantId"], "clientId": fields["clientId"] })),
            "clientSecret is required"
        );
        for broken in [b"\xff\xfe\x00".as_slice(), b"\xff\xfe\x00\xd8", b"[]"] {
            assert_eq!(
                prepare("byok/azure", broken).err().unwrap().to_string(),
                "The credential must be a JSON object"
            );
        }
    }
}
