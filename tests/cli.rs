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
