//! Compound key encoding and decoding for redb tables.
//!
//! ULID strings are exactly 26 characters. We store them as fixed-width
//! 26-byte UTF-8 slices so that lexicographic byte ordering on the compound
//! key groups events by (session, branch, seq) naturally.

/// Width of a ULID string in bytes.
const ID_WIDTH: usize = 26;

/// Total width of an event compound key: session_id + branch_id + seq.
pub const EVENT_KEY_LEN: usize = ID_WIDTH + ID_WIDTH + 8; // 60 bytes

/// Total width of a branch compound key: session_id + branch_id.
pub const BRANCH_KEY_LEN: usize = ID_WIDTH + ID_WIDTH; // 52 bytes

// ---  Event key helpers

/// Encode a compound event key: session_id (26B) || branch_id (26B) || seq (8B BE).
///
/// The session_id and branch_id are right-padded with spaces if shorter than
/// 26 bytes (should not happen for valid ULIDs, but we handle it defensively).
/// The sequence number is encoded in big-endian so that lexicographic ordering
/// of the byte slice corresponds to numeric ordering.
pub fn encode_event_key(session_id: &str, branch_id: &str, seq: u64) -> Vec<u8> {
    let mut buf = vec![0u8; EVENT_KEY_LEN];
    write_padded_id(&mut buf[..ID_WIDTH], session_id);
    write_padded_id(&mut buf[ID_WIDTH..ID_WIDTH * 2], branch_id);
    buf[ID_WIDTH * 2..].copy_from_slice(&seq.to_be_bytes());
    buf
}

/// Decode a compound event key back into (session_id, branch_id, seq).
///
/// # Panics
/// Panics if `bytes.len() != EVENT_KEY_LEN`.
pub fn decode_event_key(bytes: &[u8]) -> (String, String, u64) {
    assert_eq!(bytes.len(), EVENT_KEY_LEN, "invalid event key length");
    let session_id = read_padded_id(&bytes[..ID_WIDTH]);
    let branch_id = read_padded_id(&bytes[ID_WIDTH..ID_WIDTH * 2]);
    let seq = u64::from_be_bytes(bytes[ID_WIDTH * 2..].try_into().unwrap());
    (session_id, branch_id, seq)
}

// ---  Branch key helpers

/// Encode a compound branch key: session_id (26B) || branch_id (26B).
pub fn encode_branch_key(session_id: &str, branch_id: &str) -> Vec<u8> {
    let mut buf = vec![0u8; BRANCH_KEY_LEN];
    write_padded_id(&mut buf[..ID_WIDTH], session_id);
    write_padded_id(&mut buf[ID_WIDTH..], branch_id);
    buf
}

/// Decode a compound branch key back into (session_id, branch_id).
///
/// # Panics
/// Panics if `bytes.len() != BRANCH_KEY_LEN`.
pub fn decode_branch_key(bytes: &[u8]) -> (String, String) {
    assert_eq!(bytes.len(), BRANCH_KEY_LEN, "invalid branch key length");
    let session_id = read_padded_id(&bytes[..ID_WIDTH]);
    let branch_id = read_padded_id(&bytes[ID_WIDTH..]);
    (session_id, branch_id)
}

// ---  Internal helpers

/// Write an ID string into a fixed-width buffer, padding with spaces on the right.
fn write_padded_id(buf: &mut [u8], id: &str) {
    let id_bytes = id.as_bytes();
    let copy_len = id_bytes.len().min(buf.len());
    buf[..copy_len].copy_from_slice(&id_bytes[..copy_len]);
    // Pad remaining bytes with spaces (0x20) for consistent ordering
    for byte in &mut buf[copy_len..] {
        *byte = b' ';
    }
}

/// Read a padded ID from a fixed-width buffer, trimming trailing spaces.
fn read_padded_id(buf: &[u8]) -> String {
    let s = std::str::from_utf8(buf).unwrap_or("");
    s.trim_end_matches(' ').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_key_roundtrip() {
        let sid = "01HQJG5B8P9RJXK7M3N4T6W2YA";
        let bid = "01HQJG5B8P9RJXK7M3N4T6W2YB";
        let seq = 42u64;

        let key = encode_event_key(sid, bid, seq);
        assert_eq!(key.len(), EVENT_KEY_LEN);

        let (s, b, n) = decode_event_key(&key);
        assert_eq!(s, sid);
        assert_eq!(b, bid);
        assert_eq!(n, seq);
    }

    #[test]
    fn branch_key_roundtrip() {
        let sid = "01HQJG5B8P9RJXK7M3N4T6W2YA";
        let bid = "01HQJG5B8P9RJXK7M3N4T6W2YB";

        let key = encode_branch_key(sid, bid);
        assert_eq!(key.len(), BRANCH_KEY_LEN);

        let (s, b) = decode_branch_key(&key);
        assert_eq!(s, sid);
        assert_eq!(b, bid);
    }

    #[test]
    fn event_keys_order_by_seq() {
        let sid = "01HQJG5B8P9RJXK7M3N4T6W2YA";
        let bid = "01HQJG5B8P9RJXK7M3N4T6W2YB";

        let k1 = encode_event_key(sid, bid, 1);
        let k2 = encode_event_key(sid, bid, 2);
        let k100 = encode_event_key(sid, bid, 100);

        assert!(k1 < k2);
        assert!(k2 < k100);
    }

    #[test]
    fn event_keys_order_by_session_then_branch() {
        let s1 = "AAAAAAAAAAAAAAAAAAAAAAAAA1";
        let s2 = "AAAAAAAAAAAAAAAAAAAAAAAAA2";
        let b1 = "BBBBBBBBBBBBBBBBBBBBBBBBB1";
        let b2 = "BBBBBBBBBBBBBBBBBBBBBBBBB2";

        let k_s1b1 = encode_event_key(s1, b1, 1);
        let k_s1b2 = encode_event_key(s1, b2, 1);
        let k_s2b1 = encode_event_key(s2, b1, 1);

        // Same session, different branch
        assert!(k_s1b1 < k_s1b2);
        // Different session
        assert!(k_s1b2 < k_s2b1);
    }

    #[test]
    fn short_id_gets_padded() {
        let key = encode_event_key("short", "also_short", 0);
        let (s, b, n) = decode_event_key(&key);
        assert_eq!(s, "short");
        assert_eq!(b, "also_short");
        assert_eq!(n, 0);
    }
}
