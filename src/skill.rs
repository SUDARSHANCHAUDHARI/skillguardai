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
    let yaml = &rest[..end];
    // Strict YAML first — it handles proper lists and multi-line values.
    match serde_yaml::from_str::<Frontmatter>(yaml) {
        Ok(fm) => Ok(fm),
        // Real skill frontmatter is often fragile YAML — e.g. an unquoted description
        // containing "Trigger: /x" (a colon-space) trips serde_yaml. Fall back to a
        // lenient line scan for the fields we need; only report malformed when even that
        // recovers nothing, so a scanner never chokes on a slightly-off-but-present manifest.
        Err(e) => {
            let fm = lenient_frontmatter(yaml);
            if fm.name.is_none() && fm.description.is_none() && fm.triggers.is_empty() {
                Err(e.to_string())
            } else {
                Ok(fm)
            }
        }
    }
}

/// Tolerant top-level `key: value` extractor for the three fields we care about.
/// Takes everything after the first `:` as the value, so colons inside a value are fine.
fn lenient_frontmatter(yaml: &str) -> Frontmatter {
    fn clean(v: &str) -> String {
        v.trim().trim_matches('"').trim_matches('\'').to_string()
    }
    let mut fm = Frontmatter::default();
    let mut lines = yaml.lines().peekable();
    while let Some(line) = lines.next() {
        // Only consider unindented top-level keys.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else { continue };
        match key.trim() {
            "name" => fm.name = Some(clean(value)),
            "description" => fm.description = Some(clean(value)),
            "triggers" => {
                let inline = value.trim();
                if inline.is_empty() {
                    // Gather following "- item" list entries.
                    while let Some(peek) = lines.peek() {
                        let entry = peek.trim();
                        if let Some(item) = entry.strip_prefix("- ") {
                            fm.triggers.push(clean(item));
                            lines.next();
                        } else {
                            break;
                        }
                    }
                } else {
                    // Inline form: "[a, b]" or "a, b" or a single value.
                    let inline = inline.trim_start_matches('[').trim_end_matches(']');
                    for part in inline.split(',') {
                        let t = clean(part);
                        if !t.is_empty() {
                            fm.triggers.push(t);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    fm
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
    #[test]
    fn colon_in_description_recovers_via_lenient_fallback() {
        // Strict YAML rejects the "Trigger: /x" colon-space; the fallback must recover.
        let md = "---\nname: typescript-reviewer\ndescription: Review .ts files. Trigger: /typescript-reviewer or on any change.\ntools: Read, Bash\n---\n# body\n";
        let fm = parse_frontmatter(md).unwrap();
        assert_eq!(fm.name.as_deref(), Some("typescript-reviewer"));
        assert!(fm.description.as_deref().unwrap().contains("Trigger: /typescript-reviewer"));
    }
    #[test]
    fn unrecoverable_frontmatter_still_errors() {
        // A block with no recoverable known keys is still reported malformed.
        let md = "---\n: : : garbage\n\t- broken\n---\n# body\n";
        assert!(parse_frontmatter(md).is_err());
    }
}
