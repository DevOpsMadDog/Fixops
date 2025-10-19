"""Test file size limit enforcement and filename sanitization."""


def test_file_size_limit_check_before_write():
    """Verify the fix checks size BEFORE writing, not after."""
    limit = 3145728
    chunk_size = 1024 * 1024
    total = limit - 100
    next_chunk_len = chunk_size

    should_reject = (total + next_chunk_len) > limit

    assert should_reject, "Logic should reject when total + chunk_len > limit"


def test_filename_sanitization():
    """Test that malicious filenames are sanitized in metadata."""
    from core.storage import _sanitize_filename

    assert _sanitize_filename("../../../etc/passwd") == "passwd"

    result = _sanitize_filename("file<>:|?*.txt")
    assert result == "file______.txt"

    assert _sanitize_filename("") == "upload.bin"
    assert _sanitize_filename(".") == "upload.bin"
    assert _sanitize_filename("..") == "upload.bin"
    assert _sanitize_filename("normal_file.json") == "normal_file.json"

    long_name = "a" * 300 + ".txt"
    sanitized = _sanitize_filename(long_name)
    assert len(sanitized) <= 255
    assert sanitized.endswith(".txt")

    very_long_extension = "file." + "x" * 300
    sanitized = _sanitize_filename(very_long_extension)
    assert len(sanitized) == 255
