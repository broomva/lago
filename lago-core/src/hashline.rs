use serde::{Deserialize, Serialize};
use std::fmt;

/// 4 hex chars from FNV-1a 16-bit hash of line content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LineHash(String);

impl LineHash {
    /// Create a `LineHash` from raw bytes by computing FNV-1a 16-bit.
    pub fn from_content(content: &str) -> Self {
        let h = fnv1a_16(content.as_bytes());
        Self(format!("{h:04x}"))
    }

    /// Create a `LineHash` from an existing hex string (e.g. parsed from hashline format).
    pub fn from_hex(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LineHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single annotated line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashLine {
    pub line_num: u32,
    pub hash: LineHash,
    pub content: String,
}

/// A complete file with line hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashLineFile {
    pub lines: Vec<HashLine>,
}

impl HashLineFile {
    /// Build a `HashLineFile` from raw file content.
    pub fn from_content(content: &str) -> Self {
        if content.is_empty() {
            return Self { lines: Vec::new() };
        }

        let lines = content
            .split('\n')
            .enumerate()
            .map(|(i, line)| HashLine {
                line_num: (i + 1) as u32,
                hash: LineHash::from_content(line),
                content: line.to_string(),
            })
            .collect();

        Self { lines }
    }

    /// Render to the hashline text format: `N:HHHH|content`
    pub fn to_hashline_text(&self) -> String {
        let mut out = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(&format!(
                "{}:{}|{}",
                line.line_num,
                line.hash.as_str(),
                line.content
            ));
        }
        out
    }

    /// Find all lines matching a given hash.
    pub fn find_by_hash(&self, hash: &LineHash) -> Vec<&HashLine> {
        self.lines.iter().filter(|l| l.hash == *hash).collect()
    }

    /// Reconstruct file content from lines.
    pub fn to_content(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.content.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Apply a set of edits, validating hashes and returning the new content.
    ///
    /// Algorithm: validate all hashes → sort edits by line (reverse) → apply bottom-up.
    pub fn apply_edits(&self, edits: &[HashLineEdit]) -> Result<String, HashLineError> {
        if edits.is_empty() {
            return Ok(self.to_content());
        }

        // Validate all edits first
        for edit in edits {
            self.validate_edit(edit)?;
        }

        // Check for overlapping edits
        self.check_overlaps(edits)?;

        let mut lines: Vec<String> = self.lines.iter().map(|l| l.content.clone()).collect();

        // Sort edits by primary line number, descending (apply bottom-up)
        let mut sorted: Vec<&HashLineEdit> = edits.iter().collect();
        sorted.sort_by_key(|e| std::cmp::Reverse(primary_line(e)));

        for edit in sorted {
            match edit {
                HashLineEdit::Replace {
                    line_num,
                    new_content,
                    ..
                } => {
                    let idx = (*line_num as usize) - 1;
                    lines[idx] = new_content.clone();
                }
                HashLineEdit::InsertAfter {
                    line_num,
                    new_content,
                    ..
                } => {
                    let idx = *line_num as usize; // insert after this line
                    let new_lines: Vec<String> =
                        new_content.split('\n').map(|s| s.to_string()).collect();
                    for (i, nl) in new_lines.into_iter().enumerate() {
                        lines.insert(idx + i, nl);
                    }
                }
                HashLineEdit::InsertBefore {
                    line_num,
                    new_content,
                    ..
                } => {
                    let idx = (*line_num as usize) - 1;
                    let new_lines: Vec<String> =
                        new_content.split('\n').map(|s| s.to_string()).collect();
                    for (i, nl) in new_lines.into_iter().enumerate() {
                        lines.insert(idx + i, nl);
                    }
                }
                HashLineEdit::Delete { line_num, .. } => {
                    let idx = (*line_num as usize) - 1;
                    lines.remove(idx);
                }
                HashLineEdit::ReplaceRange {
                    start_line,
                    end_line,
                    new_content,
                    ..
                } => {
                    let start_idx = (*start_line as usize) - 1;
                    let end_idx = (*end_line as usize) - 1;
                    let new_lines: Vec<String> =
                        new_content.split('\n').map(|s| s.to_string()).collect();
                    // Remove the range
                    lines.drain(start_idx..=end_idx);
                    // Insert replacement
                    for (i, nl) in new_lines.into_iter().enumerate() {
                        lines.insert(start_idx + i, nl);
                    }
                }
            }
        }

        Ok(lines.join("\n"))
    }

    fn validate_edit(&self, edit: &HashLineEdit) -> Result<(), HashLineError> {
        let total = self.lines.len() as u32;

        match edit {
            HashLineEdit::Replace {
                anchor_hash,
                line_num,
                ..
            }
            | HashLineEdit::InsertAfter {
                anchor_hash,
                line_num,
                ..
            }
            | HashLineEdit::InsertBefore {
                anchor_hash,
                line_num,
                ..
            }
            | HashLineEdit::Delete {
                anchor_hash,
                line_num,
            } => {
                if *line_num == 0 || *line_num > total {
                    return Err(HashLineError::LineOutOfBounds {
                        line_num: *line_num,
                        total_lines: total,
                    });
                }
                let idx = (*line_num as usize) - 1;
                let actual = &self.lines[idx].hash;
                if actual != anchor_hash {
                    return Err(HashLineError::HashMismatch {
                        line_num: *line_num,
                        expected: anchor_hash.clone(),
                        actual: actual.clone(),
                    });
                }
            }
            HashLineEdit::ReplaceRange {
                start_hash,
                start_line,
                end_hash,
                end_line,
                ..
            } => {
                if *start_line == 0 || *start_line > total {
                    return Err(HashLineError::LineOutOfBounds {
                        line_num: *start_line,
                        total_lines: total,
                    });
                }
                if *end_line == 0 || *end_line > total {
                    return Err(HashLineError::LineOutOfBounds {
                        line_num: *end_line,
                        total_lines: total,
                    });
                }
                let start_actual = &self.lines[(*start_line as usize) - 1].hash;
                if start_actual != start_hash {
                    return Err(HashLineError::HashMismatch {
                        line_num: *start_line,
                        expected: start_hash.clone(),
                        actual: start_actual.clone(),
                    });
                }
                let end_actual = &self.lines[(*end_line as usize) - 1].hash;
                if end_actual != end_hash {
                    return Err(HashLineError::HashMismatch {
                        line_num: *end_line,
                        expected: end_hash.clone(),
                        actual: end_actual.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    fn check_overlaps(&self, edits: &[HashLineEdit]) -> Result<(), HashLineError> {
        let mut touched: Vec<u32> = Vec::new();
        for edit in edits {
            match edit {
                HashLineEdit::Replace { line_num, .. }
                | HashLineEdit::InsertAfter { line_num, .. }
                | HashLineEdit::InsertBefore { line_num, .. }
                | HashLineEdit::Delete { line_num, .. } => {
                    if touched.contains(line_num) {
                        return Err(HashLineError::OverlappingEdits {
                            line_num: *line_num,
                        });
                    }
                    touched.push(*line_num);
                }
                HashLineEdit::ReplaceRange {
                    start_line,
                    end_line,
                    ..
                } => {
                    for ln in *start_line..=*end_line {
                        if touched.contains(&ln) {
                            return Err(HashLineError::OverlappingEdits { line_num: ln });
                        }
                        touched.push(ln);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Edit operations referencing lines by hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum HashLineEdit {
    Replace {
        anchor_hash: LineHash,
        line_num: u32,
        new_content: String,
    },
    InsertAfter {
        anchor_hash: LineHash,
        line_num: u32,
        new_content: String,
    },
    InsertBefore {
        anchor_hash: LineHash,
        line_num: u32,
        new_content: String,
    },
    Delete {
        anchor_hash: LineHash,
        line_num: u32,
    },
    ReplaceRange {
        start_hash: LineHash,
        start_line: u32,
        end_hash: LineHash,
        end_line: u32,
        new_content: String,
    },
}

/// Hashline-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum HashLineError {
    #[error("hash mismatch at line {line_num}: expected {expected}, actual {actual}")]
    HashMismatch {
        line_num: u32,
        expected: LineHash,
        actual: LineHash,
    },

    #[error("line {line_num} out of bounds (file has {total_lines} lines)")]
    LineOutOfBounds { line_num: u32, total_lines: u32 },

    #[error("ambiguous hash {hash}: matches lines {matching_lines:?}")]
    AmbiguousHash {
        hash: LineHash,
        matching_lines: Vec<u32>,
    },

    #[error("overlapping edits at line {line_num}")]
    OverlappingEdits { line_num: u32 },
}

/// Get the primary line number from an edit (for sorting).
fn primary_line(edit: &HashLineEdit) -> u32 {
    match edit {
        HashLineEdit::Replace { line_num, .. }
        | HashLineEdit::InsertAfter { line_num, .. }
        | HashLineEdit::InsertBefore { line_num, .. }
        | HashLineEdit::Delete { line_num, .. } => *line_num,
        HashLineEdit::ReplaceRange { start_line, .. } => *start_line,
    }
}

/// FNV-1a 16-bit hash (pure Rust, no dependencies).
fn fnv1a_16(data: &[u8]) -> u16 {
    // FNV-1a 32-bit then fold to 16 bits via xor-folding
    let mut hash: u32 = 0x811c_9dc5; // FNV offset basis
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193); // FNV prime
    }
    // Xor-fold to 16 bits
    ((hash >> 16) ^ (hash & 0xFFFF)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_known_hashes() {
        // Empty string — FNV-1a 32-bit of "" is 0x811c9dc5, xor-folded to 16 bits
        let h = fnv1a_16(b"");
        assert_eq!(format!("{h:04x}"), "1cd9");

        // Known content produces consistent hashes
        let h1 = fnv1a_16(b"fn main() {");
        let h2 = fnv1a_16(b"fn main() {");
        assert_eq!(h1, h2);

        // Different content produces different hashes (probabilistically)
        let h3 = fnv1a_16(b"fn main() {");
        let h4 = fnv1a_16(b"fn other() {");
        assert_ne!(h3, h4);
    }

    #[test]
    fn line_hash_from_content() {
        let h = LineHash::from_content("fn main() {");
        assert_eq!(h.as_str().len(), 4);
        // Consistent
        assert_eq!(h, LineHash::from_content("fn main() {"));
    }

    #[test]
    fn line_hash_display() {
        let h = LineHash::from_hex("a3f1");
        assert_eq!(format!("{h}"), "a3f1");
    }

    #[test]
    fn from_content_multiline() {
        let content = "fn main() {\n    println!(\"hello\");\n}";
        let file = HashLineFile::from_content(content);
        assert_eq!(file.lines.len(), 3);
        assert_eq!(file.lines[0].line_num, 1);
        assert_eq!(file.lines[0].content, "fn main() {");
        assert_eq!(file.lines[1].line_num, 2);
        assert_eq!(file.lines[1].content, "    println!(\"hello\");");
        assert_eq!(file.lines[2].line_num, 3);
        assert_eq!(file.lines[2].content, "}");
    }

    #[test]
    fn from_content_empty() {
        let file = HashLineFile::from_content("");
        assert!(file.lines.is_empty());
    }

    #[test]
    fn from_content_single_line() {
        let file = HashLineFile::from_content("hello");
        assert_eq!(file.lines.len(), 1);
        assert_eq!(file.lines[0].line_num, 1);
        assert_eq!(file.lines[0].content, "hello");
    }

    #[test]
    fn to_hashline_text_format() {
        let content = "fn main() {\n    println!(\"hello\");\n}";
        let file = HashLineFile::from_content(content);
        let text = file.to_hashline_text();
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines.len(), 3);

        // Each line matches N:HHHH|content
        for line in &lines {
            let parts: Vec<&str> = line.splitn(2, '|').collect();
            assert_eq!(parts.len(), 2);
            let prefix = parts[0];
            assert!(prefix.contains(':'));
            let hash_part: Vec<&str> = prefix.splitn(2, ':').collect();
            assert_eq!(hash_part[1].len(), 4); // 4 hex chars
        }
    }

    #[test]
    fn to_hashline_text_roundtrip() {
        let content = "line one\nline two\nline three";
        let file = HashLineFile::from_content(content);
        let reconstructed = file.to_content();
        assert_eq!(reconstructed, content);
    }

    #[test]
    fn find_by_hash_found() {
        let content = "aaa\nbbb\nccc";
        let file = HashLineFile::from_content(content);
        let hash = &file.lines[1].hash;
        let found = file.find_by_hash(hash);
        assert!(found.iter().any(|l| l.content == "bbb"));
    }

    #[test]
    fn find_by_hash_duplicates() {
        // Same content on two lines produces same hash
        let content = "dup\nother\ndup";
        let file = HashLineFile::from_content(content);
        let hash = &file.lines[0].hash;
        let found = file.find_by_hash(hash);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].line_num, 1);
        assert_eq!(found[1].line_num, 3);
    }

    #[test]
    fn apply_edit_replace() {
        let content = "aaa\nbbb\nccc";
        let file = HashLineFile::from_content(content);
        let hash = file.lines[1].hash.clone();
        let edits = vec![HashLineEdit::Replace {
            anchor_hash: hash,
            line_num: 2,
            new_content: "BBB".to_string(),
        }];
        let result = file.apply_edits(&edits).unwrap();
        assert_eq!(result, "aaa\nBBB\nccc");
    }

    #[test]
    fn apply_edit_insert_after() {
        let content = "aaa\nccc";
        let file = HashLineFile::from_content(content);
        let hash = file.lines[0].hash.clone();
        let edits = vec![HashLineEdit::InsertAfter {
            anchor_hash: hash,
            line_num: 1,
            new_content: "bbb".to_string(),
        }];
        let result = file.apply_edits(&edits).unwrap();
        assert_eq!(result, "aaa\nbbb\nccc");
    }

    #[test]
    fn apply_edit_insert_before() {
        let content = "bbb\nccc";
        let file = HashLineFile::from_content(content);
        let hash = file.lines[0].hash.clone();
        let edits = vec![HashLineEdit::InsertBefore {
            anchor_hash: hash,
            line_num: 1,
            new_content: "aaa".to_string(),
        }];
        let result = file.apply_edits(&edits).unwrap();
        assert_eq!(result, "aaa\nbbb\nccc");
    }

    #[test]
    fn apply_edit_delete() {
        let content = "aaa\nbbb\nccc";
        let file = HashLineFile::from_content(content);
        let hash = file.lines[1].hash.clone();
        let edits = vec![HashLineEdit::Delete {
            anchor_hash: hash,
            line_num: 2,
        }];
        let result = file.apply_edits(&edits).unwrap();
        assert_eq!(result, "aaa\nccc");
    }

    #[test]
    fn apply_edit_replace_range() {
        let content = "aaa\nbbb\nccc\nddd";
        let file = HashLineFile::from_content(content);
        let start_hash = file.lines[1].hash.clone();
        let end_hash = file.lines[2].hash.clone();
        let edits = vec![HashLineEdit::ReplaceRange {
            start_hash,
            start_line: 2,
            end_hash,
            end_line: 3,
            new_content: "xxx\nyyy".to_string(),
        }];
        let result = file.apply_edits(&edits).unwrap();
        assert_eq!(result, "aaa\nxxx\nyyy\nddd");
    }

    #[test]
    fn apply_edit_error_hash_mismatch() {
        let content = "aaa\nbbb";
        let file = HashLineFile::from_content(content);
        let edits = vec![HashLineEdit::Replace {
            anchor_hash: LineHash::from_hex("0000"),
            line_num: 1,
            new_content: "xxx".to_string(),
        }];
        let err = file.apply_edits(&edits).unwrap_err();
        assert!(matches!(err, HashLineError::HashMismatch { .. }));
    }

    #[test]
    fn apply_edit_error_line_out_of_bounds() {
        let content = "aaa\nbbb";
        let file = HashLineFile::from_content(content);
        let edits = vec![HashLineEdit::Delete {
            anchor_hash: LineHash::from_hex("0000"),
            line_num: 5,
        }];
        let err = file.apply_edits(&edits).unwrap_err();
        assert!(matches!(err, HashLineError::LineOutOfBounds { .. }));
    }

    #[test]
    fn apply_edit_error_overlapping() {
        let content = "aaa\nbbb\nccc";
        let file = HashLineFile::from_content(content);
        let hash = file.lines[1].hash.clone();
        let edits = vec![
            HashLineEdit::Replace {
                anchor_hash: hash.clone(),
                line_num: 2,
                new_content: "xxx".to_string(),
            },
            HashLineEdit::Delete {
                anchor_hash: hash,
                line_num: 2,
            },
        ];
        let err = file.apply_edits(&edits).unwrap_err();
        assert!(matches!(err, HashLineError::OverlappingEdits { .. }));
    }

    #[test]
    fn apply_multiple_non_overlapping_edits() {
        let content = "aaa\nbbb\nccc\nddd";
        let file = HashLineFile::from_content(content);
        let hash1 = file.lines[0].hash.clone();
        let hash3 = file.lines[2].hash.clone();
        let edits = vec![
            HashLineEdit::Replace {
                anchor_hash: hash1,
                line_num: 1,
                new_content: "AAA".to_string(),
            },
            HashLineEdit::Replace {
                anchor_hash: hash3,
                line_num: 3,
                new_content: "CCC".to_string(),
            },
        ];
        let result = file.apply_edits(&edits).unwrap();
        assert_eq!(result, "AAA\nbbb\nCCC\nddd");
    }

    #[test]
    fn apply_empty_edits() {
        let content = "aaa\nbbb";
        let file = HashLineFile::from_content(content);
        let result = file.apply_edits(&[]).unwrap();
        assert_eq!(result, content);
    }

    #[test]
    fn serde_roundtrip_hash_line_edit_replace() {
        let edit = HashLineEdit::Replace {
            anchor_hash: LineHash::from_hex("a3f1"),
            line_num: 5,
            new_content: "new line".to_string(),
        };
        let json = serde_json::to_string(&edit).unwrap();
        assert!(json.contains("\"op\":\"Replace\""));
        let back: HashLineEdit = serde_json::from_str(&json).unwrap();
        if let HashLineEdit::Replace {
            anchor_hash,
            line_num,
            new_content,
        } = back
        {
            assert_eq!(anchor_hash.as_str(), "a3f1");
            assert_eq!(line_num, 5);
            assert_eq!(new_content, "new line");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn serde_roundtrip_hash_line_edit_delete() {
        let edit = HashLineEdit::Delete {
            anchor_hash: LineHash::from_hex("beef"),
            line_num: 3,
        };
        let json = serde_json::to_string(&edit).unwrap();
        let back: HashLineEdit = serde_json::from_str(&json).unwrap();
        if let HashLineEdit::Delete {
            anchor_hash,
            line_num,
        } = back
        {
            assert_eq!(anchor_hash.as_str(), "beef");
            assert_eq!(line_num, 3);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn serde_roundtrip_hash_line_edit_replace_range() {
        let edit = HashLineEdit::ReplaceRange {
            start_hash: LineHash::from_hex("aaaa"),
            start_line: 2,
            end_hash: LineHash::from_hex("bbbb"),
            end_line: 5,
            new_content: "x\ny".to_string(),
        };
        let json = serde_json::to_string(&edit).unwrap();
        let back: HashLineEdit = serde_json::from_str(&json).unwrap();
        if let HashLineEdit::ReplaceRange {
            start_hash,
            start_line,
            end_hash,
            end_line,
            new_content,
        } = back
        {
            assert_eq!(start_hash.as_str(), "aaaa");
            assert_eq!(start_line, 2);
            assert_eq!(end_hash.as_str(), "bbbb");
            assert_eq!(end_line, 5);
            assert_eq!(new_content, "x\ny");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn hashline_error_display() {
        let err = HashLineError::HashMismatch {
            line_num: 3,
            expected: LineHash::from_hex("aaaa"),
            actual: LineHash::from_hex("bbbb"),
        };
        assert!(err.to_string().contains("hash mismatch at line 3"));

        let err = HashLineError::LineOutOfBounds {
            line_num: 10,
            total_lines: 5,
        };
        assert!(err.to_string().contains("line 10 out of bounds"));

        let err = HashLineError::OverlappingEdits { line_num: 2 };
        assert!(err.to_string().contains("overlapping edits at line 2"));
    }

    #[test]
    fn insert_multiline_after() {
        let content = "aaa\nccc";
        let file = HashLineFile::from_content(content);
        let hash = file.lines[0].hash.clone();
        let edits = vec![HashLineEdit::InsertAfter {
            anchor_hash: hash,
            line_num: 1,
            new_content: "b1\nb2".to_string(),
        }];
        let result = file.apply_edits(&edits).unwrap();
        assert_eq!(result, "aaa\nb1\nb2\nccc");
    }
}
