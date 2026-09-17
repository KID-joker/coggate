use std::io::Cursor;

use agentgate_release::canonical::{
    MAX_METADATA_BYTES, canonical_compact, canonical_pretty_sorted, parse_strict_json,
    read_bounded, safe_relative_path, sha256_hex, validate_sha256,
};

#[test]
fn strict_json_and_paths_reject_ambiguous_inputs() {
    assert!(parse_strict_json(br#"{"a":1,"a":2}"#, 64).is_err());
    assert!(parse_strict_json(&[0xff], 64).is_err());
    assert!(safe_relative_path("../escape").is_err());
    assert!(safe_relative_path("/absolute").is_err());
    assert!(safe_relative_path("nested/file.txt").is_ok());
}

#[test]
fn canonical_encoders_and_hashes_are_stable() {
    let value = parse_strict_json(br#"{"z":1,"a":{"b":2}}"#, 128).unwrap();
    assert_eq!(
        canonical_compact(&value).unwrap(),
        br#"{"a":{"b":2},"z":1}"#
    );
    assert_eq!(
        String::from_utf8(canonical_pretty_sorted(&value).unwrap()).unwrap(),
        "{\n  \"a\": {\n    \"b\": 2\n  },\n  \"z\": 1\n}\n"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn bounded_reader_rejects_before_unbounded_allocation() {
    assert!(read_bounded(&b"1234"[..], 3).is_err());
    assert_eq!(read_bounded(Cursor::new(b"1234"), 4).unwrap(), b"1234");
    assert_eq!(read_bounded(Cursor::new(b"1"), usize::MAX).unwrap(), b"1");
}

#[test]
fn metadata_limits_are_exact() {
    assert_eq!(MAX_METADATA_BYTES, 8 * 1024 * 1024);
    assert!(parse_strict_json(br#"{}"#, 2).is_ok());
    assert!(parse_strict_json(br#"{}"#, 1).is_err());
}

#[test]
fn hashes_must_be_lowercase_sha256_hex() {
    assert!(validate_sha256(&"a".repeat(64)).is_ok());
    assert!(validate_sha256(&"a".repeat(63)).is_err());
    assert!(validate_sha256(&"A".repeat(64)).is_err());
    assert!(validate_sha256(&format!("{}g", "a".repeat(63))).is_err());
    assert!(validate_sha256(&"é".repeat(32)).is_err());
}

#[test]
fn relative_paths_are_bounded_and_unambiguous() {
    for value in [
        "",
        ".",
        "..",
        "nested//file.txt",
        "nested/./file.txt",
        "nested/../file.txt",
        "/absolute",
        "nested\\file.txt",
        "nested/\0file.txt",
        "nested/\u{001f}file.txt",
        &format!("a/{}", "b".repeat(255)),
        "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q",
    ] {
        assert!(safe_relative_path(value).is_err(), "{value:?}");
    }

    assert_eq!(
        safe_relative_path("a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p").unwrap(),
        std::path::PathBuf::from("a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p")
    );
    assert!(safe_relative_path(&"a".repeat(256)).is_ok());
}

#[test]
fn relative_paths_reject_windows_unsafe_components_on_every_host() {
    for value in [
        "file<name",
        "file>name",
        "file:stream",
        "file\"name",
        "file|name",
        "file?name",
        "file*name",
        "NUL",
        "con.txt",
        "Com1.LOG",
        "lPt9",
        "file.",
        "file ",
        "nested/PRN.csv",
    ] {
        assert!(safe_relative_path(value).is_err(), "{value:?}");
    }
}

#[test]
fn canonical_errors_do_not_echo_untrusted_input() {
    let duplicate_key = "k".repeat(4 * 1024);
    let duplicate_json = format!("{{\"{duplicate_key}\":1,\"{duplicate_key}\":2}}");
    let duplicate_diagnostic = parse_strict_json(duplicate_json.as_bytes(), MAX_METADATA_BYTES)
        .unwrap_err()
        .to_string();
    assert!(!duplicate_diagnostic.contains(&duplicate_key));
    assert!(duplicate_diagnostic.len() < 256);

    let rejected_path = format!("{}\u{001f}attack", "x".repeat(300));
    let path_diagnostic = safe_relative_path(&rejected_path).unwrap_err().to_string();
    assert!(!path_diagnostic.contains(&rejected_path));
    assert!(!path_diagnostic.contains('\u{001f}'));
    assert!(path_diagnostic.len() < 256);
}

#[test]
fn nested_duplicate_json_keys_are_rejected() {
    assert!(parse_strict_json(br#"{"outer":{"a":1,"a":2}}"#, 64).is_err());
}

#[test]
fn canonical_encoders_sort_objects_at_every_depth() {
    let value = parse_strict_json(br#"[{"z":0,"a":{"z":2,"a":1}}]"#, 128).unwrap();
    assert_eq!(
        canonical_compact(&value).unwrap(),
        br#"[{"a":{"a":1,"z":2},"z":0}]"#
    );
}
