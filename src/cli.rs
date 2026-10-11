use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use crate::{baseline::Baseline, engine, report, rules::RulePack, sarif, score, skill, walker};
use crate::baseline;
use crate::walker::WalkCaps;
use crate::report::SkillReport;

#[derive(Parser)]
#[command(name = "skillguardai", version, about = "SkillGuardAI — static security scanner for AI-agent skills")]
struct Cli { #[command(subcommand)] command: Command }

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Human-readable terminal report (default).
    Terminal,
    /// Machine-readable JSON.
    Json,
    /// SARIF 2.1.0 for CI / GitHub code scanning.
    Sarif,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a skill directory (or, with --all, every subdirectory containing a SKILL.md)
    Scan {
        path: PathBuf,
        #[arg(long)] all: bool,
        /// Output format. Overrides --json when both are given.
        #[arg(long, value_enum, default_value_t = Format::Terminal)]
        format: Format,
        /// Deprecated alias for `--format json`.
        #[arg(long)] json: bool,
        /// Suppress known findings listed in a baseline TOML file. If omitted,
        /// `$XDG_CONFIG_HOME/skillguardai/baseline.toml` (else `~/.config/...`) is used
        /// when present. A baseline inside the scanned directory is never loaded.
        #[arg(long, value_name = "FILE")]
        baseline: Option<PathBuf>,
    },
    /// Run as an MCP server over stdio, exposing a `scan_skill` tool.
    Mcp,
}

/// Scan one skill, dropping any findings the baseline suppresses BEFORE scoring.
/// Returns the report and one stderr line per suppressed finding, so a suppression is
/// never silent.
fn scan_one(root: &Path, rules: &RulePack, baseline: &Baseline) -> anyhow::Result<(SkillReport, Vec<String>)> {
    let files = walker::collect_text_files(root, &WalkCaps::default())?;
    let sk = skill::load(root);
    let res = engine::scan(&sk, &files, rules);
    let name = sk.frontmatter.as_ref().and_then(|f| f.name.clone())
        .unwrap_or_else(|| root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    let mut suppressed = Vec::new();
    let mut findings = res.findings;
    findings.retain(|f| {
        if baseline.suppresses(&name, f) {
            suppressed.push(format!(
                "  {} [{}] {}:{} {}",
                name,
                f.rule_id,
                f.file,
                f.line.map(|l| l.to_string()).unwrap_or_else(|| "-".into()),
                f.description
            ));
            return false;
        }
        true
    });
    let sc = score::score(&findings, res.has_executable_scripts);
    Ok((SkillReport { skill: name, score: sc, findings, has_executable_scripts: res.has_executable_scripts }, suppressed))
}

/// Resolve the baseline: explicit `--baseline` wins; otherwise the user's config file when
/// it exists. Nothing inside the scanned tree is ever loaded — a hostile skill shipping its
/// own baseline must not be able to suppress the rules that catch it.
fn resolve_baseline(explicit: Option<PathBuf>) -> anyhow::Result<Baseline> {
    if let Some(p) = explicit {
        return Baseline::load(&p);
    }
    match baseline::user_config_path() {
        Some(p) if p.is_file() => Baseline::load(&p),
        _ => Ok(Baseline::default()),
    }
}

fn subdirs_with_skill(root: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(root).into_iter().flatten().flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("SKILL.md").exists())
        .collect()
}

pub fn run() -> i32 {
    let cli = Cli::parse();
    let rules = match RulePack::load_default() {
        Ok(r) => r,
        Err(e) => { eprintln!("error: {e}"); return 2; }
    };
    match cli.command {
        Command::Scan { path, all, format, json, baseline } => {
            // --json is a back-compat alias; --format wins when it is non-default.
            let format = if json && format == Format::Terminal { Format::Json } else { format };
            let baseline = match resolve_baseline(baseline) {
                Ok(b) => b,
                Err(e) => { eprintln!("error: {e}"); return 2; }
            };
            let targets = if all { subdirs_with_skill(&path) } else { vec![path.clone()] };
            let mut reports = Vec::new();
            let mut had_error = false;
            let mut suppressed_lines: Vec<String> = Vec::new();
            for t in targets {
                match scan_one(&t, &rules, &baseline) {
                    Ok((r, suppressed)) => { suppressed_lines.extend(suppressed); reports.push(r); }
                    Err(e) => {
                        eprintln!("error scanning {}: {e}", t.display());
                        if !all { return 2; }
                        had_error = true;
                    }
                }
            }
            match format {
                Format::Json => println!("{}", report::to_json(&reports)),
                Format::Sarif => println!("{}", sarif::to_sarif(&reports)),
                Format::Terminal => report::print_terminal(&reports),
            }
            if !suppressed_lines.is_empty() {
                eprintln!("{} finding(s) suppressed by baseline:", suppressed_lines.len());
                for l in &suppressed_lines {
                    eprintln!("{l}");
                }
            }
            let worst = reports.iter().map(|r| r.score.exit_code).max().unwrap_or(0);
            worst.max(if had_error { 2 } else { 0 })
        }
        Command::Mcp => crate::mcp::serve(),
    }
}
