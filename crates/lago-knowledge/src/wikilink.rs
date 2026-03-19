//! Wikilink extraction from markdown content.
//!
//! Extracts `[[target]]` and `[[target|alias]]` style wikilinks,
//! returning deduplicated target strings.

use regex::Regex;
use std::sync::LazyLock;

static WIKILINK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]").unwrap());

/// Extract all wikilink targets from markdown content.
///
/// Handles both `[[target]]` and `[[target|alias]]` syntax.
/// Returns deduplicated targets in order of first appearance.
pub fn extract_wikilinks(content: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut links = Vec::new();

    for cap in WIKILINK_RE.captures_iter(content) {
        let target = cap[1].trim().to_string();
        if !target.is_empty() && seen.insert(target.clone()) {
            links.push(target);
        }
    }

    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_wikilink() {
        let links = extract_wikilinks("See [[Note A]] for details.");
        assert_eq!(links, vec!["Note A"]);
    }

    #[test]
    fn wikilink_with_alias() {
        let links = extract_wikilinks("Read [[Architecture|arch docs]] here.");
        assert_eq!(links, vec!["Architecture"]);
    }

    #[test]
    fn wikilink_with_heading() {
        let links = extract_wikilinks("See [[Note#Section]] for context.");
        assert_eq!(links, vec!["Note#Section"]);
    }

    #[test]
    fn multiple_wikilinks() {
        let content = "Links: [[A]], [[B|alias]], and [[C]].";
        let links = extract_wikilinks(content);
        assert_eq!(links, vec!["A", "B", "C"]);
    }

    #[test]
    fn deduplication() {
        let content = "See [[A]] and [[A]] again, plus [[A|other]].";
        let links = extract_wikilinks(content);
        assert_eq!(links, vec!["A"]);
    }

    #[test]
    fn empty_content() {
        let links = extract_wikilinks("");
        assert!(links.is_empty());
    }

    #[test]
    fn no_wikilinks() {
        let links = extract_wikilinks("Just plain markdown without any links.");
        assert!(links.is_empty());
    }

    #[test]
    fn nested_brackets() {
        // Malformed triple brackets — regex captures "[Bad" (leading bracket included)
        let links = extract_wikilinks("[[[Bad]]]");
        // The outer [ is not part of the wikilink pattern, so [[Bad]] matches with target "[Bad"
        assert_eq!(links.len(), 1);
        // This is acceptable behavior for malformed input
    }
}
