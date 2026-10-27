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
        .args(["encryption-key", "--output"])
        .arg(&key)
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    std::fs::remove_file(&key).unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}
