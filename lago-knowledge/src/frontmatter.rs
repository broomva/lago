//! YAML frontmatter parsing for `.md` files.
//!
//! Parses the `---\nyaml\n---\nmarkdown` format used by Obsidian and
//! other knowledge management tools.

/// Parse YAML frontmatter from markdown content.
///
/// Returns `(frontmatter, body)` where `frontmatter` is the parsed YAML
/// (or `Null` if no frontmatter is present) and `body` is the remaining
/// markdown content.
pub fn parse_frontmatter(content: &str) -> (serde_yaml::Value, &str) {
    // Must start with "---" on the first line
    let trimmed = content.trim_start_matches('\u{feff}'); // strip BOM
    if !trimmed.starts_with("---") {
        return (serde_yaml::Value::Null, content);
    }

    // Find the closing "---" delimiter
    let after_open = &trimmed[3..];
    let rest = after_open.strip_prefix('\n').unwrap_or(after_open);

    if let Some(close_pos) = rest.find("\n---") {
        let yaml_str = &rest[..close_pos];
        let body_start = close_pos + 4; // "\n---".len()
        let body = if body_start < rest.len() {
            let remaining = &rest[body_start..];
            remaining.strip_prefix('\n').unwrap_or(remaining)
        } else {
            ""
        };

        match serde_yaml::from_str(yaml_str) {
            Ok(value) => (value, body),
            Err(_) => (serde_yaml::Value::Null, content),
        }
    } else {
        // No closing delimiter — treat entire content as body
        (serde_yaml::Value::Null, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_frontmatter() {
        let content = "---\ntitle: Hello\ntags:\n  - rust\n  - lago\n---\n# Body\n\nSome content.";
        let (fm, body) = parse_frontmatter(content);
        assert_eq!(fm["title"].as_str(), Some("Hello"));
        let tags = fm["tags"].as_sequence().unwrap();
        assert_eq!(tags.len(), 2);
        assert!(body.starts_with("# Body"));
    }

    #[test]
    fn empty_frontmatter() {
        let content = "---\n---\n# Just body";
        let (fm, body) = parse_frontmatter(content);
        // Empty YAML parses as Null
        assert!(fm.is_null());
        assert!(body.contains("Just body"));
    }

    #[test]
    fn no_frontmatter() {
        let content = "# No frontmatter here\n\nJust markdown.";
        let (fm, body) = parse_frontmatter(content);
        assert!(fm.is_null());
        assert_eq!(body, content);
    }

    #[test]
    fn frontmatter_no_trailing_newline() {
        let content = "---\nname: test\n---";
        let (fm, body) = parse_frontmatter(content);
        assert_eq!(fm["name"].as_str(), Some("test"));
        assert_eq!(body, "");
    }

    #[test]
    fn frontmatter_with_bom() {
        let content = "\u{feff}---\ntitle: BOM\n---\nBody";
        let (fm, body) = parse_frontmatter(content);
        assert_eq!(fm["title"].as_str(), Some("BOM"));
        assert_eq!(body, "Body");
    }

    #[test]
    fn invalid_yaml_frontmatter() {
        let content = "---\n: : : invalid\n---\nBody";
        let (fm, body) = parse_frontmatter(content);
        // Invalid YAML → treat entire content as body
        assert!(fm.is_null());
        assert_eq!(body, content);
    }
}
