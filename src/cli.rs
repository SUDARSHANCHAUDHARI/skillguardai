use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use crate::{engine, report, rules::RulePack, score, skill, walker};
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
    },
}

fn scan_one(root: &Path, rules: &RulePack) -> anyhow::Result<SkillReport> {
    let files = walker::collect_text_files(root, &WalkCaps::default())?;
    let sk = skill::load(root);
    let res = engine::scan(&sk, &files, rules);
    let sc = score::score(&res.findings, res.has_executable_scripts);
    let name = sk.frontmatter.as_ref().and_then(|f| f.name.clone())
        .unwrap_or_else(|| root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
    Ok(SkillReport { skill: name, score: sc, findings: res.findings, has_executable_scripts: res.has_executable_scripts })
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
        Command::Scan { path, all, json } => {
            let targets = if all { subdirs_with_skill(&path) } else { vec![path.clone()] };
            let mut reports = Vec::new();
            let mut had_error = false;
            for t in targets {
                match scan_one(&t, &rules) {
                    Ok(r) => reports.push(r),
                    Err(e) => {
                        eprintln!("error scanning {}: {e}", t.display());
                        if !all { return 2; }
                        had_error = true;
                    }
                }
            }
            if json { println!("{}", report::to_json(&reports)); }
            else { report::print_terminal(&reports); }
            let worst = reports.iter().map(|r| r.score.exit_code).max().unwrap_or(0);
            worst.max(if had_error { 2 } else { 0 })
        }
    }
}
