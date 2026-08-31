use assert_cmd::Command;

#[test]
fn clean_skill_exits_zero() {
    Command::cargo_bin("skillguardai").unwrap()
        .args(["scan", "tests/fixtures/clean"])
        .assert().success();
}

#[test]
fn exfil_skill_exits_one() {
    Command::cargo_bin("skillguardai").unwrap()
        .args(["scan", "tests/fixtures/exfil"])
        .assert().code(1);
}

#[test]
fn json_output_is_valid_json() {
    let out = Command::cargo_bin("skillguardai").unwrap()
        .args(["scan", "tests/fixtures/exfil", "--json"])
        .output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.is_array());
}

fn assert_category_flagged(fixture: &str, category: &str) {
    let out = Command::cargo_bin("skillguardai").unwrap()
        .args(["scan", &format!("tests/fixtures/{fixture}"), "--json"])
        .output().unwrap();
    let body = String::from_utf8(out.stdout).unwrap();
    assert!(body.contains(category), "expected category '{category}' in output for fixture '{fixture}':\n{body}");
}

#[test]
fn exfil_fixture_flags_data_exfiltration() {
    assert_category_flagged("exfil", "data-exfiltration");
}

#[test]
fn cred_fixture_flags_credential_access() {
    assert_category_flagged("cred", "credential-access");
}

#[test]
fn exec_fixture_flags_dangerous_exec() {
    assert_category_flagged("exec", "dangerous-exec");
}

#[test]
fn inject_fixture_flags_prompt_injection() {
    assert_category_flagged("inject", "prompt-injection");
}

#[test]
fn supply_fixture_flags_supply_chain() {
    assert_category_flagged("supply", "supply-chain");
}

#[test]
fn obfus_fixture_flags_obfuscation() {
    assert_category_flagged("obfus", "obfuscation");
}

#[test]
fn trigger_fixture_flags_excessive_trigger() {
    assert_category_flagged("trigger", "excessive-trigger");
}

#[test]
fn baseline_suppresses_finding_and_flips_exit() {
    // Without a baseline, exfil exits 1. A baseline suppressing its rule flips it to 0.
    let dir = tempfile::tempdir().unwrap();
    let baseline = dir.path().join("bl.toml");
    std::fs::write(
        &baseline,
        "[[suppress]]\nrule_id = \"exfil-curl-pipe-sh\"\nreason = \"test\"\n",
    )
    .unwrap();
    Command::cargo_bin("skillguardai")
        .unwrap()
        .args(["scan", "tests/fixtures/exfil", "--baseline"])
        .arg(&baseline)
        .assert()
        .success();
}
