#![cfg(unix)]

use std::process::{Command, Stdio};

/// A reader such as `head` can stop reading before the command prints. The command then ends
/// quietly, as other command-line tools do, instead of panicking.
#[test]
fn ends_quietly_when_its_reader_has_stopped() {
    let mut suffix = [0_u8; 16];
    getrandom::fill(&mut suffix).unwrap();
    let key = std::env::temp_dir().join(format!("stogas-output-test-{}", hex::encode(suffix)));
    // A pipe without a reader fails every write with a broken pipe.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_stogas"))
        .args(["encryption-key", "create", "--output"])
        .arg(&key)
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    std::fs::remove_file(&key).unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

/// A key file gives the same identifier later as when the key was created, so its owner can
/// register it without the first command's output.
#[test]
fn prints_the_identifier_of_a_key_file() {
    let mut suffix = [0_u8; 16];
    getrandom::fill(&mut suffix).unwrap();
    let key = std::env::temp_dir().join(format!("stogas-id-test-{}", hex::encode(suffix)));
    let run = |arguments: [&str; 2]| {
        Command::new(env!("CARGO_BIN_EXE_stogas"))
            .args(["encryption-key", arguments[0], arguments[1]])
            .arg(&key)
            .output()
            .unwrap()
    };
    let created = run(["create", "--output"]);
    let printed = run(["id", "--key-file"]);
    std::fs::remove_file(&key).unwrap();
    assert!(created.status.success(), "{created:?}");
    assert!(printed.status.success(), "{printed:?}");
    assert_eq!(created.stdout.len(), 65, "{created:?}");
    assert_eq!(printed.stdout, created.stdout);
}
