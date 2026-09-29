"""
Tests for SecureMailScope Zeek JSONL log reader (Phase 3).
"""

from pathlib import Path

from securemailscope.zeek.log_reader import read_jsonl_log

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "zeek_logs"


def test_read_valid_conn_log() -> None:
    path = FIXTURES_DIR / "conn_basic.jsonl"
    records, warnings = read_jsonl_log(path, log_type="conn")

    assert len(records) == 2
    assert len(warnings) == 0
    assert records[0]["uid"] == "CiA7yB3xkFaQvInJl"
    assert records[1]["uid"] == "Dj8Bz4yLgGbRwJoKm"


def test_read_empty_file() -> None:
    path = FIXTURES_DIR / "empty.jsonl"
    records, warnings = read_jsonl_log(path, log_type="conn")

    assert records == []
    assert warnings == []


def test_read_nonexistent_optional_log(tmp_path: Path) -> None:
    missing_path = tmp_path / "nonexistent.jsonl"
    records, warnings = read_jsonl_log(missing_path, log_type="smtp")

    assert records == []
    assert len(warnings) == 1
    assert warnings[0].log_type == "smtp"
    assert warnings[0].line_number == 0
    assert "not found" in warnings[0].issue.lower()


def test_read_malformed_json_line() -> None:
    path = FIXTURES_DIR / "conn_malformed.jsonl"
    records, warnings = read_jsonl_log(path, log_type="conn")

    # In conn_malformed.jsonl:
    # Line 1: valid record (uid="ValidRecord001")
    # Line 2: "this is not valid json {{{" -> Malformed JSON warning
    # Line 3: ["array", "not", "object"] -> Non-object root warning
    # Line 4: {"proto": "tcp", "conn_state": "SF"} -> valid JSON object
    # (reader preserves it; correlator handles missing uid)
    assert len(records) == 2
    assert records[0]["uid"] == "ValidRecord001"
    assert records[1]["proto"] == "tcp"

    assert len(warnings) == 2

    # Verify line 2 malformed JSON warning
    w1 = warnings[0]
    assert w1.line_number == 2
    assert "Malformed JSON" in w1.issue
    assert "this is not valid json" in (w1.raw_line or "")

    # Verify line 3 non-object warning
    w2 = warnings[1]
    assert w2.line_number == 3
    assert "not an object" in w2.issue.lower()


def test_read_non_object_json_root(tmp_path: Path) -> None:
    log_file = tmp_path / "array_root.jsonl"
    log_file.write_text("[1, 2, 3]\n\"just a string\"\n42\n", encoding="utf-8")

    records, warnings = read_jsonl_log(log_file, log_type="conn")

    assert records == []
    assert len(warnings) == 3
    for w in warnings:
        assert "not an object" in w.issue.lower()


def test_read_hash_comment_lines_skipped(tmp_path: Path) -> None:
    log_file = tmp_path / "commented.jsonl"
    log_file.write_text(
        "#separator \\x09\n"
        "#set_separator ,\n"
        '{"uid": "c1", "proto": "tcp"}\n'
        "#close 2026-09-29\n",
        encoding="utf-8",
    )

    records, warnings = read_jsonl_log(log_file, log_type="conn")

    assert len(records) == 1
    assert records[0]["uid"] == "c1"
    assert len(warnings) == 0


def test_read_blank_lines_skipped(tmp_path: Path) -> None:
    log_file = tmp_path / "blank_lines.jsonl"
    log_file.write_text(
        "\n\n"
        '{"uid": "c1"}\n'
        "\n"
        '{"uid": "c2"}\n'
        "\n\n",
        encoding="utf-8",
    )

    records, warnings = read_jsonl_log(log_file, log_type="conn")

    assert len(records) == 2
    assert records[0]["uid"] == "c1"
    assert records[1]["uid"] == "c2"
    assert len(warnings) == 0


def test_no_filesystem_writes(tmp_path: Path) -> None:
    log_file = tmp_path / "test.jsonl"
    content = '{"uid": "test1234"}\n'
    log_file.write_text(content, encoding="utf-8")

    stat_before = log_file.stat()
    items_before = set(tmp_path.iterdir())

    records, warnings = read_jsonl_log(log_file, log_type="conn")

    stat_after = log_file.stat()
    items_after = set(tmp_path.iterdir())

    assert len(records) == 1
    assert items_before == items_after
    assert stat_before.st_mtime_ns == stat_after.st_mtime_ns
    assert stat_before.st_size == stat_after.st_size


def test_unknown_fields_preserved(tmp_path: Path) -> None:
    log_file = tmp_path / "custom_fields.jsonl"
    log_file.write_text(
        '{"uid": "c1", "zeek_custom_field": "custom_value", "nested": {"key": 123}}\n',
        encoding="utf-8",
    )

    records, warnings = read_jsonl_log(log_file, log_type="conn")

    assert len(records) == 1
    assert records[0]["zeek_custom_field"] == "custom_value"
    assert records[0]["nested"] == {"key": 123}
    assert len(warnings) == 0
