"""
Comprehensive tests for the safe_path_ops module.

Tests cover:
- Two-stage containment validation (TRUSTED_ROOT + base_path)
- Path traversal prevention
- All safe_* wrapper functions
- Error handling and edge cases
"""

import asyncio
import os
import shutil
import uuid

import pytest

from core.safe_path_ops import (
    TRUSTED_ROOT,
    PathContainmentError,
    safe_exists,
    safe_get_parent_dirs,
    safe_isdir,
    safe_isfile,
    safe_iterdir,
    safe_listdir,
    safe_open_read,
    safe_path_join,
    safe_read_text,
    safe_resolve_path,
    safe_subprocess_exec,
    safe_subprocess_run,
    safe_write_text,
)

TRUSTED_TEST_ROOT = "/var/fixops/test-scans"


class TestPathContainmentError:
    """Tests for PathContainmentError exception."""

    def test_path_containment_error_is_value_error(self):
        """PathContainmentError should be a subclass of ValueError."""
        assert issubclass(PathContainmentError, ValueError)

    def test_path_containment_error_message(self):
        """PathContainmentError should preserve error message."""
        error = PathContainmentError("test message")
        assert str(error) == "test message"


class TestSafeExists:
    """Tests for safe_exists function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_exists_valid_file(self, temp_dir):
        """Test safe_exists with a valid file."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        assert safe_exists(test_file, temp_dir) is True

    def test_safe_exists_nonexistent_file(self, temp_dir):
        """Test safe_exists with a nonexistent file."""
        test_file = os.path.join(temp_dir, "nonexistent.txt")
        assert safe_exists(test_file, temp_dir) is False

    def test_safe_exists_path_escapes_trusted_root(self, temp_dir):
        """Test safe_exists raises when path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_exists("/tmp/test.txt", "/tmp")
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_safe_exists_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_exists raises when base_path escapes TRUSTED_ROOT."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        with pytest.raises(PathContainmentError) as exc_info:
            safe_exists(test_file, "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_exists_path_escapes_base_directory(self, temp_dir):
        """Test safe_exists raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_exists("/var/fixops/other/test.txt", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeIsfile:
    """Tests for safe_isfile function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_isfile_valid_file(self, temp_dir):
        """Test safe_isfile with a valid file."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        assert safe_isfile(test_file, temp_dir) is True

    def test_safe_isfile_directory(self, temp_dir):
        """Test safe_isfile with a directory returns False."""
        assert safe_isfile(temp_dir, temp_dir) is False

    def test_safe_isfile_path_escapes_trusted_root(self, temp_dir):
        """Test safe_isfile raises when path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_isfile("/tmp/test.txt", "/tmp")
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_safe_isfile_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_isfile raises when base_path escapes TRUSTED_ROOT."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        with pytest.raises(PathContainmentError) as exc_info:
            safe_isfile(test_file, "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_isfile_path_escapes_base_directory(self, temp_dir):
        """Test safe_isfile raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_isfile("/var/fixops/other/test.txt", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeIsdir:
    """Tests for safe_isdir function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_isdir_valid_directory(self, temp_dir):
        """Test safe_isdir with a valid directory."""
        assert safe_isdir(temp_dir, temp_dir) is True

    def test_safe_isdir_file(self, temp_dir):
        """Test safe_isdir with a file returns False."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        assert safe_isdir(test_file, temp_dir) is False

    def test_safe_isdir_path_escapes_trusted_root(self, temp_dir):
        """Test safe_isdir raises when path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_isdir("/tmp/test", "/tmp")
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_safe_isdir_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_isdir raises when base_path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_isdir(temp_dir, "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_isdir_path_escapes_base_directory(self, temp_dir):
        """Test safe_isdir raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_isdir("/var/fixops/other", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeListdir:
    """Tests for safe_listdir function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_listdir_valid_directory(self, temp_dir):
        """Test safe_listdir with a valid directory."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        result = safe_listdir(temp_dir, temp_dir)
        assert "test.txt" in result

    def test_safe_listdir_empty_directory(self, temp_dir):
        """Test safe_listdir with an empty directory."""
        result = safe_listdir(temp_dir, temp_dir)
        assert result == []

    def test_safe_listdir_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_listdir raises when base_path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_listdir("/tmp", "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_listdir_path_escapes_base_directory(self, temp_dir):
        """Test safe_listdir raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_listdir("/var/fixops/other", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeOpenRead:
    """Tests for safe_open_read function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_open_read_valid_file(self, temp_dir):
        """Test safe_open_read with a valid file."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content")
        with safe_open_read(test_file, temp_dir) as f:
            content = f.read()
        assert content == "test content"

    def test_safe_open_read_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_open_read raises when base_path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_open_read("/tmp/test.txt", "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_open_read_path_escapes_base_directory(self, temp_dir):
        """Test safe_open_read raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_open_read("/var/fixops/other/test.txt", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeReadText:
    """Tests for safe_read_text function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_read_text_valid_file(self, temp_dir):
        """Test safe_read_text with a valid file."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content")
        content = safe_read_text(test_file, temp_dir)
        assert content == "test content"

    def test_safe_read_text_with_max_bytes(self, temp_dir):
        """Test safe_read_text with max_bytes limit."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test content that is longer")
        content = safe_read_text(test_file, temp_dir, max_bytes=4)
        assert content == "test"

    def test_safe_read_text_path_escapes_trusted_root(self, temp_dir):
        """Test safe_read_text raises when path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_read_text("/tmp/test.txt", "/tmp")
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_safe_read_text_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_read_text raises when base_path escapes TRUSTED_ROOT."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        with pytest.raises(PathContainmentError) as exc_info:
            safe_read_text(test_file, "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_read_text_path_escapes_base_directory(self, temp_dir):
        """Test safe_read_text raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_read_text("/var/fixops/other/test.txt", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeWriteText:
    """Tests for safe_write_text function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_write_text_valid_file(self, temp_dir):
        """Test safe_write_text with a valid file."""
        test_file = os.path.join(temp_dir, "test.txt")
        safe_write_text(test_file, temp_dir, "test content")
        with open(test_file, "r") as f:
            content = f.read()
        assert content == "test content"

    def test_safe_write_text_path_escapes_trusted_root(self, temp_dir):
        """Test safe_write_text raises when path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_write_text("/tmp/test.txt", "/tmp", "content")
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_safe_write_text_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_write_text raises when base_path escapes TRUSTED_ROOT."""
        test_file = os.path.join(temp_dir, "test.txt")
        with pytest.raises(PathContainmentError) as exc_info:
            safe_write_text(test_file, "/tmp", "content")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_write_text_path_escapes_base_directory(self, temp_dir):
        """Test safe_write_text raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_write_text("/var/fixops/other/test.txt", temp_dir, "content")
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafePathJoin:
    """Tests for safe_path_join function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_path_join_valid_path(self, temp_dir):
        """Test safe_path_join with valid path components."""
        result = safe_path_join(temp_dir, "subdir", "file.txt")
        assert result == os.path.realpath(os.path.join(temp_dir, "subdir", "file.txt"))

    def test_safe_path_join_without_validation(self, temp_dir):
        """Test safe_path_join with validate=False."""
        result = safe_path_join(temp_dir, "..", "other", validate=False)
        assert result is not None

    def test_safe_path_join_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_path_join raises when base_path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_path_join("/tmp", "subdir")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_path_join_path_escapes_base_directory(self, temp_dir):
        """Test safe_path_join raises when joined path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_path_join(temp_dir, "..", "..", "other")
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeResolvePath:
    """Tests for safe_resolve_path function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_resolve_path_relative_path(self, temp_dir):
        """Test safe_resolve_path with a relative path."""
        result = safe_resolve_path("subdir/file.txt", temp_dir)
        assert result == os.path.realpath(os.path.join(temp_dir, "subdir/file.txt"))

    def test_safe_resolve_path_absolute_path_within_base(self, temp_dir):
        """Test safe_resolve_path with an absolute path within base."""
        abs_path = os.path.join(temp_dir, "file.txt")
        result = safe_resolve_path(abs_path, temp_dir)
        assert result == os.path.realpath(abs_path)

    def test_safe_resolve_path_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_resolve_path raises when base_path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_resolve_path("file.txt", "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_resolve_path_path_escapes_base_directory(self, temp_dir):
        """Test safe_resolve_path raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_resolve_path("../../other/file.txt", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)

    def test_safe_resolve_path_absolute_path_outside_base(self, temp_dir):
        """Test safe_resolve_path raises when absolute path is outside base."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_resolve_path("/var/fixops/other/file.txt", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeSubprocessRun:
    """Tests for safe_subprocess_run function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_subprocess_run_valid_command(self, temp_dir):
        """Test safe_subprocess_run with a valid command."""
        result = safe_subprocess_run(["echo", "hello"], temp_dir, temp_dir)
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_safe_subprocess_run_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_subprocess_run raises when base_path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_subprocess_run(["echo", "hello"], "/tmp", "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_subprocess_run_cwd_escapes_base_directory(self, temp_dir):
        """Test safe_subprocess_run raises when cwd escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            safe_subprocess_run(["echo", "hello"], "/var/fixops/other", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeSubprocessExec:
    """Tests for safe_subprocess_exec async function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_safe_subprocess_exec_valid_command(self, temp_dir):
        """Test safe_subprocess_exec with a valid command."""
        stdout, stderr, returncode = await safe_subprocess_exec(
            ["echo", "hello"], temp_dir, temp_dir
        )
        assert returncode == 0
        assert "hello" in stdout

    @pytest.mark.asyncio
    async def test_safe_subprocess_exec_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_subprocess_exec raises when base_path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            await safe_subprocess_exec(["echo", "hello"], "/tmp", "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_safe_subprocess_exec_cwd_escapes_base_directory(self, temp_dir):
        """Test safe_subprocess_exec raises when cwd escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            await safe_subprocess_exec(["echo", "hello"], "/var/fixops/other", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_safe_subprocess_exec_timeout(self, temp_dir):
        """Test safe_subprocess_exec with timeout."""
        with pytest.raises(asyncio.TimeoutError):
            await safe_subprocess_exec(["sleep", "10"], temp_dir, temp_dir, timeout=0.1)


class TestSafeIterdir:
    """Tests for safe_iterdir function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_iterdir_valid_directory(self, temp_dir):
        """Test safe_iterdir with a valid directory."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        result = list(safe_iterdir(temp_dir, temp_dir))
        assert len(result) == 1
        assert test_file in result[0]

    def test_safe_iterdir_empty_directory(self, temp_dir):
        """Test safe_iterdir with an empty directory."""
        result = list(safe_iterdir(temp_dir, temp_dir))
        assert result == []

    def test_safe_iterdir_path_escapes_trusted_root(self, temp_dir):
        """Test safe_iterdir raises when path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            list(safe_iterdir("/tmp", "/tmp"))
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_safe_iterdir_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_iterdir raises when base_path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            list(safe_iterdir(temp_dir, "/tmp"))
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_iterdir_path_escapes_base_directory(self, temp_dir):
        """Test safe_iterdir raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            list(safe_iterdir("/var/fixops/other", temp_dir))
        assert "Path escapes base directory" in str(exc_info.value)


class TestSafeGetParentDirs:
    """Tests for safe_get_parent_dirs function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_get_parent_dirs_valid_path(self, temp_dir):
        """Test safe_get_parent_dirs with a valid path."""
        subdir = os.path.join(temp_dir, "subdir")
        os.makedirs(subdir, exist_ok=True)
        result = list(safe_get_parent_dirs(subdir, temp_dir))
        assert len(result) >= 1
        assert subdir in result

    def test_safe_get_parent_dirs_file_path(self, temp_dir):
        """Test safe_get_parent_dirs with a file path."""
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("test")
        result = list(safe_get_parent_dirs(test_file, temp_dir))
        assert len(result) >= 1
        assert temp_dir in result

    def test_safe_get_parent_dirs_path_escapes_trusted_root(self, temp_dir):
        """Test safe_get_parent_dirs raises when path escapes TRUSTED_ROOT."""
        with pytest.raises(PathContainmentError) as exc_info:
            list(safe_get_parent_dirs("/tmp/subdir", "/tmp"))
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_safe_get_parent_dirs_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_get_parent_dirs raises when base_path escapes TRUSTED_ROOT."""
        subdir = os.path.join(temp_dir, "subdir")
        os.makedirs(subdir, exist_ok=True)
        with pytest.raises(PathContainmentError) as exc_info:
            list(safe_get_parent_dirs(subdir, "/tmp"))
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_get_parent_dirs_path_escapes_base_directory(self, temp_dir):
        """Test safe_get_parent_dirs raises when path escapes base_path."""
        with pytest.raises(PathContainmentError) as exc_info:
            list(safe_get_parent_dirs("/var/fixops/other", temp_dir))
        assert "Path escapes base directory" in str(exc_info.value)


class TestTrustedRootConstant:
    """Tests for TRUSTED_ROOT constant."""

    def test_trusted_root_value(self):
        """Test TRUSTED_ROOT has expected value."""
        assert TRUSTED_ROOT == "/var/fixops"

    def test_trusted_root_is_string(self):
        """Test TRUSTED_ROOT is a string."""
        assert isinstance(TRUSTED_ROOT, str)


class TestSafeMakedirs:
    """Tests for safe_makedirs function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_makedirs_valid_path(self, temp_dir):
        """Test safe_makedirs creates directory under valid base path."""
        from core.safe_path_ops import safe_makedirs

        new_dir = os.path.join(temp_dir, "new_subdir")
        result = safe_makedirs(new_dir, temp_dir)
        assert os.path.isdir(new_dir)
        assert result == os.path.realpath(new_dir)

    def test_safe_makedirs_path_escapes_trusted_root(self, temp_dir):
        """Test safe_makedirs raises when path escapes TRUSTED_ROOT."""
        from core.safe_path_ops import safe_makedirs

        with pytest.raises(PathContainmentError) as exc_info:
            safe_makedirs("/tmp/outside", temp_dir)
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_safe_makedirs_base_path_escapes_trusted_root(self, temp_dir):
        """Test safe_makedirs raises when base_path escapes TRUSTED_ROOT."""
        from core.safe_path_ops import safe_makedirs

        new_dir = os.path.join(temp_dir, "new_subdir")
        with pytest.raises(PathContainmentError) as exc_info:
            safe_makedirs(new_dir, "/tmp")
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_makedirs_path_escapes_base_directory(self, temp_dir):
        """Test safe_makedirs raises when path escapes base_path."""
        from core.safe_path_ops import safe_makedirs

        with pytest.raises(PathContainmentError) as exc_info:
            safe_makedirs("/var/fixops/other", temp_dir)
        assert "Path escapes base directory" in str(exc_info.value)

    def test_safe_makedirs_exist_ok(self, temp_dir):
        """Test safe_makedirs with exist_ok=True."""
        from core.safe_path_ops import safe_makedirs

        # Create directory first
        new_dir = os.path.join(temp_dir, "existing_dir")
        os.makedirs(new_dir, exist_ok=True)
        # Should not raise with exist_ok=True
        result = safe_makedirs(new_dir, temp_dir, exist_ok=True)
        assert os.path.isdir(new_dir)
        assert result == os.path.realpath(new_dir)


class TestSafeTempdir:
    """Tests for safe_tempdir context manager."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    def test_safe_tempdir_valid_base_path(self, temp_dir):
        """Test safe_tempdir creates temp directory under valid base path."""
        from core.safe_path_ops import safe_tempdir

        with safe_tempdir(temp_dir) as temp_path:
            assert os.path.isdir(temp_path)
            assert temp_path.startswith(os.path.realpath(temp_dir))
        # Temp directory should be cleaned up after context exits
        assert not os.path.exists(temp_path)

    def test_safe_tempdir_base_path_escapes_trusted_root(self):
        """Test safe_tempdir raises when base_path escapes TRUSTED_ROOT."""
        from core.safe_path_ops import safe_tempdir

        with pytest.raises(PathContainmentError) as exc_info:
            with safe_tempdir("/tmp"):
                pass
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_safe_tempdir_creates_base_if_not_exists(self, temp_dir):
        """Test safe_tempdir creates base directory if it doesn't exist."""
        from core.safe_path_ops import safe_tempdir

        new_base = os.path.join(temp_dir, "new_base")
        assert not os.path.exists(new_base)
        with safe_tempdir(new_base) as temp_path:
            assert os.path.isdir(temp_path)
            assert os.path.isdir(new_base)
        # Base directory should still exist after context exits
        assert os.path.isdir(new_base)

    def test_safe_tempdir_temp_escapes_base(self, temp_dir):
        """Test safe_tempdir raises when temp directory escapes base."""
        import tempfile
        from unittest.mock import MagicMock, patch

        from core.safe_path_ops import safe_tempdir

        # Mock TemporaryDirectory to return a path outside the base
        mock_temp_dir = MagicMock()
        mock_temp_dir.__enter__ = MagicMock(return_value="/tmp/outside_base")
        mock_temp_dir.__exit__ = MagicMock(return_value=False)

        with patch.object(tempfile, "TemporaryDirectory", return_value=mock_temp_dir):
            with pytest.raises(PathContainmentError) as exc_info:
                with safe_tempdir(temp_dir):
                    pass
            assert "Temp directory escapes base" in str(exc_info.value)
