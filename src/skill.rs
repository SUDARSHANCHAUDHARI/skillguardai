use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Deserialize)]
pub struct Frontmatter {
    #[serde(default)] pub name: Option<String>,
    // Part of the documented Frontmatter interface; not read internally yet.
    #[serde(default)] #[allow(dead_code)] pub description: Option<String>,
    #[serde(default)] pub triggers: Vec<String>,
}

pub struct Skill {
    // Part of the documented Skill interface; not read internally yet.
    #[allow(dead_code)] pub root: PathBuf,
    pub frontmatter: Option<Frontmatter>,
    pub frontmatter_error: Option<String>,
    #[allow(dead_code)] pub has_skill_md: bool,
    pub scripts: Vec<PathBuf>,
}

pub fn parse_frontmatter(md: &str) -> Result<Frontmatter, String> {
    let s = md.strip_prefix('\u{feff}').unwrap_or(md);
    let rest = s.strip_prefix("---").ok_or("no frontmatter block")?;
    let end = rest.find("\n---").ok_or("unterminated frontmatter block")?;
    serde_yaml::from_str::<Frontmatter>(&rest[..end]).map_err(|e| e.to_string())
}

fn is_script(path: &Path) -> bool {
    matches!(path.extension().and_then(|e| e.to_str()),
        Some("sh" | "bash" | "py" | "js" | "ts" | "rb" | "pl"))
}

pub fn load(root: &Path) -> Skill {
    let md_path = root.join("SKILL.md");
    let (frontmatter, frontmatter_error, has_skill_md) = match std::fs::read_to_string(&md_path) {
        Ok(md) => match parse_frontmatter(&md) {
            Ok(fm) => (Some(fm), None, true),
            Err(e) => (None, Some(e), true),
        },
        Err(_) => (None, None, false),
    };
    let mut scripts = Vec::new();
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        if entry.file_type().is_file() && is_script(entry.path()) {
            scripts.push(entry.path().to_path_buf());
        }
    }
    Skill { root: root.to_path_buf(), frontmatter, frontmatter_error, has_skill_md, scripts }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_name_and_description() {
        let md = "---\nname: demo\ndescription: does a thing\n---\n# body\n";
        let fm = parse_frontmatter(md).unwrap();
        assert_eq!(fm.name.as_deref(), Some("demo"));
        assert_eq!(fm.description.as_deref(), Some("does a thing"));
    }
    #[test]
    fn missing_frontmatter_is_error() {
        assert!(parse_frontmatter("# no frontmatter\n").is_err());
    }
    #[test]
    fn broad_triggers_parse_into_list() {
        let md = "---\nname: x\ntriggers:\n  - \"*\"\n---\n";
        let fm = parse_frontmatter(md).unwrap();
        assert_eq!(fm.triggers, vec!["*".to_string()]);
    }
}
