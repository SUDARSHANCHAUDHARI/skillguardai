//! Minimal MCP (Model Context Protocol) server over stdio.
//!
//! Exposes one tool, `scan_skill`, so an agent can vet a skill directory at runtime
//! before trusting it. Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout —
//! local IPC with the parent agent, no outbound network, consistent with the tool's
//! static/offline promise. `handle_request` is a pure dispatcher so it can be tested
//! without wiring real stdio.

use std::io::{BufRead, Write};
use std::path::Path;

use serde_json::{json, Value};

use crate::report::SkillReport;
use crate::rules::RulePack;
use crate::walker::WalkCaps;
use crate::{engine, report, score, skill, walker};

const DEFAULT_PROTOCOL: &str = "2024-11-05";

fn scan_path(root: &Path, rules: &RulePack) -> anyhow::Result<SkillReport> {
    let files = walker::collect_text_files(root, &WalkCaps::default())?;
    let sk = skill::load(root);
    let res = engine::scan(&sk, &files, rules);
    let sc = score::score(&res.findings, res.has_executable_scripts);
    let name = sk
        .frontmatter
        .as_ref()
        .and_then(|f| f.name.clone())
        .unwrap_or_else(|| {
            root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
        });
    Ok(SkillReport {
        skill: name,
        score: sc,
        findings: res.findings,
        has_executable_scripts: res.has_executable_scripts,
    })
}

/// Dispatch one JSON-RPC request. Returns `Some(response)` for requests (those with an
/// `id`) and `None` for notifications (which get no reply).
pub fn handle_request(req: &Value, rules: &RulePack) -> Option<Value> {
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    match method {
        "initialize" => {
            let pv = req["params"]["protocolVersion"].as_str().unwrap_or(DEFAULT_PROTOCOL);
            Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": pv,
                    "serverInfo": { "name": "skillguardai", "version": env!("CARGO_PKG_VERSION") },
                    "capabilities": { "tools": {} }
                }
            }))
        }
        "tools/list" => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "tools": [ {
                "name": "scan_skill",
                "description": "Statically scan an AI-agent skill/plugin directory and return its risk verdict (band, score, findings). Never executes the skill.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "path": { "type": "string", "description": "Path to the skill directory to scan" } },
                    "required": ["path"]
                }
            } ] }
        })),
        "tools/call" => {
            let name = req["params"]["name"].as_str().unwrap_or("");
            if name != "scan_skill" {
                return Some(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": format!("unknown tool: {name}") }
                }));
            }
            let path = req["params"]["arguments"]["path"].as_str().unwrap_or("");
            let (text, is_error) = match scan_path(Path::new(path), rules) {
                Ok(r) => {
                    let summary = format!(
                        "{} [{:?} {}] — {} finding(s)",
                        r.skill, r.score.band, r.score.value, r.findings.len()
                    );
                    let body = report::to_json(std::slice::from_ref(&r));
                    (format!("{summary}\n{body}"), r.score.exit_code == 1)
                }
                Err(e) => (format!("scan error: {e}"), true),
            };
            Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "content": [ { "type": "text", "text": text } ], "isError": is_error }
            }))
        }
        // Unknown method: error for requests, silence for notifications.
        _ if id.is_some() => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") }
        })),
        _ => None,
    }
}

/// Run the stdio server loop until EOF. Returns a process exit code.
pub fn serve() -> i32 {
    let rules = match RulePack::load_default() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // ignore malformed frames
        };
        if let Some(resp) = handle_request(&req, &rules) {
            if writeln!(out, "{}", serde_json::to_string(&resp).expect("serialize response")).is_err() {
                break;
            }
            let _ = out.flush();
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> RulePack {
        RulePack::load_default().unwrap()
    }

    #[test]
    fn initialize_echoes_protocol_and_names_server() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}});
        let resp = handle_request(&req, &rules()).unwrap();
        assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(resp["result"]["serverInfo"]["name"], "skillguardai");
    }

    #[test]
    fn tools_list_exposes_scan_skill() {
        let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let resp = handle_request(&req, &rules()).unwrap();
        assert_eq!(resp["result"]["tools"][0]["name"], "scan_skill");
    }

    #[test]
    fn tools_call_scans_a_fixture() {
        let req = json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params": {"name":"scan_skill","arguments":{"path":"tests/fixtures/exfil"}}
        });
        let resp = handle_request(&req, &rules()).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("exfil"));
        assert_eq!(resp["result"]["isError"], true); // exfil is HIGH -> exit 1
    }

    #[test]
    fn unknown_tool_is_an_error() {
        let req = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}});
        let resp = handle_request(&req, &rules()).unwrap();
        assert!(resp["error"]["message"].as_str().unwrap().contains("unknown tool"));
    }

    #[test]
    fn notification_gets_no_response() {
        let req = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        assert!(handle_request(&req, &rules()).is_none());
    }
}
