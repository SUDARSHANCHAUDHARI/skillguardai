use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use crate::{baseline::Baseline, engine, report, rules::RulePack, score, skill, walker};
use crate::baseline;
use crate::walker::WalkCaps;
use crate::report::SkillReport;

#[derive(Parser)]
#[command(name = "skillguardai", version, about = "SkillGuardAI — static security scanner for AI-agent skills")]
struct Cli { #[command(subcommand)] command: Command }

#[derive(Subcommand)]
enum Command {
    /// Scan a skill directory (or, with --all, every subdirectory containing a SKILL.md)
    Scan {
        path: PathBuf,
        #[arg(long)] all: bool,
        #[arg(long)] json: bool,
        /// Suppress known findings listed in a baseline TOML file. If omitted, a
        /// `.skillguardai-baseline.toml` in the scanned directory is used when present.
        #[arg(long, value_name = "FILE")]
        baseline: Option<PathBuf>,
    },
}

/// Scan one skill, dropping any findings the baseline suppresses BEFORE scoring.
/// Returns the report and the number of findings suppressed.
fn scan_one(root: &Path, rules: &RulePack, baseline: &Baseline) -> anyhow::Result<(SkillReport, usize)> {
    let files = walker::collect_text_files(root, &WalkCaps::default())?;
    let sk = skill::load(root);
    let res = engine::scan(&sk, &files, rules);
    let name = sk.frontmatter.as_ref().and_then(|f| f.name.clone())
        .unwrap_or_else(|| root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    let before = res.findings.len();
    let mut findings = res.findings;
    findings.retain(|f| !baseline.suppresses(&name, f));
    let suppressed = before - findings.len();
    let sc = score::score(&findings, res.has_executable_scripts);
    Ok((SkillReport { skill: name, score: sc, findings, has_executable_scripts: res.has_executable_scripts }, suppressed))
}

/// Resolve the baseline: explicit `--baseline` wins; otherwise auto-load
/// `.skillguardai-baseline.toml` from the scan directory when it exists.
fn resolve_baseline(path: &Path, explicit: Option<PathBuf>) -> anyhow::Result<Baseline> {
    if let Some(p) = explicit {
        return Baseline::load(&p);
    }
    let auto = path.join(baseline::DEFAULT_FILENAME);
    if auto.is_file() {
        return Baseline::load(&auto);
    }
    Ok(Baseline::default())
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
        Command::Scan { path, all, json, baseline } => {
            let baseline = match resolve_baseline(&path, baseline) {
                Ok(b) => b,
                Err(e) => { eprintln!("error: {e}"); return 2; }
            };
            let targets = if all { subdirs_with_skill(&path) } else { vec![path.clone()] };
            let mut reports = Vec::new();
            let mut had_error = false;
            let mut suppressed_total = 0usize;
            for t in targets {
                match scan_one(&t, &rules, &baseline) {
                    Ok((r, suppressed)) => { suppressed_total += suppressed; reports.push(r); }
                    Err(e) => {
                        eprintln!("error scanning {}: {e}", t.display());
                        if !all { return 2; }
                        had_error = true;
                    }
                }
            }
            if json { println!("{}", report::to_json(&reports)); }
            else { report::print_terminal(&reports); }
            if suppressed_total > 0 {
                eprintln!("({suppressed_total} finding(s) suppressed by baseline)");
            }
            let worst = reports.iter().map(|r| r.score.exit_code).max().unwrap_or(0);
            worst.max(if had_error { 2 } else { 0 })
        }
    }
}
