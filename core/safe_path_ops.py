"""
Safe path operations module with inline sanitization for CodeQL compliance.

This module provides wrapper functions for filesystem and subprocess operations
that include inline path sanitization. CodeQL requires the sanitization pattern
(os.path.realpath + os.path.commonpath) to be in the same function as the sink
to recognize it as a valid security check.

Each function performs a two-stage containment check:
1. Verify base_path is under the TRUSTED_ROOT constant (untaints base_path for CodeQL)
2. Verify candidate path is under base_path
3. Execute the sink operation with the sanitized path

The TRUSTED_ROOT constant anchors all operations to a known-safe directory tree,
which CodeQL recognizes as non-user-controlled.
"""

import os
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Iterator, List, Optional, Union

TRUSTED_ROOT = "/var/fixops"


class PathContainmentError(ValueError):
    """Raised when a path escapes the allowed base directory."""

    pass


def safe_exists(path: Union[str, Path], base_path: str) -> bool:
    """
    Check if a path exists, with three-stage containment validation.

    Stage 1: Verify candidate is under TRUSTED_ROOT (de-taints candidate for CodeQL)
    Stage 2: Verify base_path is under TRUSTED_ROOT
    Stage 3: Verify candidate is under base_path

    Args:
        path: The path to check
        base_path: The base directory that must contain the path

    Returns:
        True if the path exists and is within base_path, False otherwise

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    candidate = os.path.realpath(str(path))
    # Stage 1: candidate must be under trusted_root (de-taints candidate for CodeQL)
    if os.path.commonpath([trusted_root, candidate]) != trusted_root:
        raise PathContainmentError(f"Path escapes trusted root: {path}")
    base = os.path.realpath(base_path)
    # Stage 2: base must be under trusted_root
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Stage 3: candidate must be under base
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    return os.path.exists(candidate)


def safe_isfile(path: Union[str, Path], base_path: str) -> bool:
    """
    Check if a path is a file, with three-stage containment validation.

    Args:
        path: The path to check
        base_path: The base directory that must contain the path

    Returns:
        True if the path is a file within base_path

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    candidate = os.path.realpath(str(path))
    # Stage 1: candidate must be under trusted_root (de-taints candidate for CodeQL)
    if os.path.commonpath([trusted_root, candidate]) != trusted_root:
        raise PathContainmentError(f"Path escapes trusted root: {path}")
    base = os.path.realpath(base_path)
    # Stage 2: base must be under trusted_root
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Stage 3: candidate must be under base
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    return os.path.isfile(candidate)


def safe_isdir(path: Union[str, Path], base_path: str) -> bool:
    """
    Check if a path is a directory, with three-stage containment validation.

    Args:
        path: The path to check
        base_path: The base directory that must contain the path

    Returns:
        True if the path is a directory within base_path

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    candidate = os.path.realpath(str(path))
    # Stage 1: candidate must be under trusted_root (de-taints candidate for CodeQL)
    if os.path.commonpath([trusted_root, candidate]) != trusted_root:
        raise PathContainmentError(f"Path escapes trusted root: {path}")
    base = os.path.realpath(base_path)
    # Stage 2: base must be under trusted_root
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Stage 3: candidate must be under base
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    return os.path.isdir(candidate)


def safe_listdir(path: Union[str, Path], base_path: str) -> List[str]:
    """
    List directory contents, with two-stage containment validation.

    Args:
        path: The directory path to list
        base_path: The base directory that must contain the path

    Returns:
        List of filenames in the directory

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    base = os.path.realpath(base_path)
    candidate = os.path.realpath(str(path))
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    return os.listdir(candidate)


def safe_open_read(
    path: Union[str, Path], base_path: str, errors: str = "strict"
) -> IO[str]:
    """
    Open a file for reading, with two-stage containment validation.

    Args:
        path: The file path to open
        base_path: The base directory that must contain the path
        errors: Error handling mode for decoding

    Returns:
        File handle opened for reading

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    base = os.path.realpath(base_path)
    candidate = os.path.realpath(str(path))
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    return open(candidate, "r", errors=errors)


def safe_read_text(path: Union[str, Path], base_path: str, max_bytes: int = -1) -> str:
    """
    Read text content from a file, with three-stage containment validation.

    Args:
        path: The file path to read
        base_path: The base directory that must contain the path
        max_bytes: Maximum bytes to read (-1 for all)

    Returns:
        File content as string

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    candidate = os.path.realpath(str(path))
    # Stage 1: candidate must be under trusted_root (de-taints candidate for CodeQL)
    if os.path.commonpath([trusted_root, candidate]) != trusted_root:
        raise PathContainmentError(f"Path escapes trusted root: {path}")
    base = os.path.realpath(base_path)
    # Stage 2: base must be under trusted_root
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Stage 3: candidate must be under base
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    with open(candidate, "r", errors="ignore") as f:
        if max_bytes > 0:
            return f.read(max_bytes)
        return f.read()


def safe_write_text(path: Union[str, Path], base_path: str, content: str) -> None:
    """
    Write text content to a file, with three-stage containment validation.

    Args:
        path: The file path to write
        base_path: The base directory that must contain the path
        content: Content to write

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    candidate = os.path.realpath(str(path))
    # Stage 1: candidate must be under trusted_root (de-taints candidate for CodeQL)
    if os.path.commonpath([trusted_root, candidate]) != trusted_root:
        raise PathContainmentError(f"Path escapes trusted root: {path}")
    base = os.path.realpath(base_path)
    # Stage 2: base must be under trusted_root
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Stage 3: candidate must be under base
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    with open(candidate, "w") as f:
        f.write(content)


def safe_path_join(base_path: str, *parts: str, validate: bool = True) -> str:
    """
    Join path components and validate containment with two-stage check.

    Args:
        base_path: The base directory
        *parts: Path components to join
        validate: Whether to validate containment (default True)

    Returns:
        The joined and resolved path

    Raises:
        PathContainmentError: If the resulting path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    base = os.path.realpath(base_path)
    candidate = os.path.realpath(os.path.join(base, *parts))
    if validate:
        if os.path.commonpath([trusted_root, base]) != trusted_root:
            raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
        if os.path.commonpath([base, candidate]) != base:
            raise PathContainmentError(
                f"Path escapes base directory: {os.path.join(*parts)}"
            )
    return candidate


def safe_resolve_path(path: Union[str, Path], base_path: str) -> str:
    """
    Resolve a path and validate containment with two-stage check.

    Args:
        path: The path to resolve (can be relative or absolute)
        base_path: The base directory that must contain the path

    Returns:
        The resolved path as a string

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    base = os.path.realpath(base_path)

    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")

    path_str = str(path)
    if os.path.isabs(path_str):
        candidate = os.path.realpath(path_str)
    else:
        candidate = os.path.realpath(os.path.join(base, path_str))

    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    return candidate


def safe_subprocess_run(
    cmd: List[str],
    cwd: Union[str, Path],
    base_path: str,
    timeout: Optional[float] = None,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """
    Run a subprocess with validated cwd, with two-stage containment validation.

    Args:
        cmd: Command and arguments to run
        cwd: Working directory for the subprocess
        base_path: The base directory that must contain cwd
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr
        text: Whether to decode output as text
        check: Whether to raise on non-zero exit

    Returns:
        CompletedProcess instance

    Raises:
        PathContainmentError: If cwd escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    base = os.path.realpath(base_path)
    candidate = os.path.realpath(str(cwd))
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {cwd}")
    return subprocess.run(
        cmd,
        cwd=candidate,
        timeout=timeout,
        capture_output=capture_output,
        text=text,
        check=check,
    )


async def safe_subprocess_exec(
    cmd: List[str],
    cwd: Union[str, Path],
    base_path: str,
    timeout: Optional[float] = None,
) -> tuple:
    """
    Run an async subprocess with validated cwd, with two-stage containment validation.

    Args:
        cmd: Command and arguments to run
        cwd: Working directory for the subprocess
        base_path: The base directory that must contain cwd
        timeout: Timeout in seconds

    Returns:
        Tuple of (stdout, stderr, return_code)

    Raises:
        PathContainmentError: If cwd escapes allowed directories
        asyncio.TimeoutError: If the command times out
    """
    import asyncio

    trusted_root = os.path.realpath(TRUSTED_ROOT)
    base = os.path.realpath(base_path)
    candidate = os.path.realpath(str(cwd))
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {cwd}")

    process = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=candidate,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return (
            stdout.decode() if stdout else "",
            stderr.decode() if stderr else "",
            process.returncode,
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise


def safe_iterdir(path: Union[str, Path], base_path: str) -> Iterator[str]:
    """
    Iterate over directory contents, yielding validated child paths.

    Args:
        path: The directory path to iterate
        base_path: The base directory that must contain all paths

    Yields:
        Validated child paths as strings

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    candidate = os.path.realpath(str(path))
    # Stage 1: candidate must be under trusted_root (de-taints candidate for CodeQL)
    if os.path.commonpath([trusted_root, candidate]) != trusted_root:
        raise PathContainmentError(f"Path escapes trusted root: {path}")
    base = os.path.realpath(base_path)
    # Stage 2: base must be under trusted_root
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Stage 3: candidate must be under base
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")

    for child_name in os.listdir(candidate):
        child_path = os.path.realpath(os.path.join(candidate, child_name))
        if os.path.commonpath([base, child_path]) == base:
            yield child_path


def safe_get_parent_dirs(path: Union[str, Path], base_path: str) -> Iterator[str]:
    """
    Iterate over parent directories up to base_path.

    Args:
        path: The starting path
        base_path: The base directory (iteration stops here)

    Yields:
        Parent directory paths as strings

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    candidate = os.path.realpath(str(path))
    # Stage 1: candidate must be under trusted_root (de-taints candidate for CodeQL)
    if os.path.commonpath([trusted_root, candidate]) != trusted_root:
        raise PathContainmentError(f"Path escapes trusted root: {path}")
    base = os.path.realpath(base_path)
    # Stage 2: base must be under trusted_root
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Stage 3: candidate must be under base
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")

    current = candidate if os.path.isdir(candidate) else os.path.dirname(candidate)
    while current != os.path.dirname(current):
        if os.path.commonpath([base, current]) != base:
            break
        yield current
        current = os.path.dirname(current)


def safe_makedirs(path: Union[str, Path], base_path: str, exist_ok: bool = True) -> str:
    """
    Create directories with three-stage containment validation.

    Args:
        path: The directory path to create
        base_path: The base directory that must contain the path
        exist_ok: If True, don't raise if directory exists

    Returns:
        The validated path as a string

    Raises:
        PathContainmentError: If the path escapes allowed directories
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    candidate = os.path.realpath(str(path))
    # Stage 1: candidate must be under trusted_root (de-taints candidate for CodeQL)
    if os.path.commonpath([trusted_root, candidate]) != trusted_root:
        raise PathContainmentError(f"Path escapes trusted root: {path}")
    base = os.path.realpath(base_path)
    # Stage 2: base must be under trusted_root
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Stage 3: candidate must be under base
    if os.path.commonpath([base, candidate]) != base:
        raise PathContainmentError(f"Path escapes base directory: {path}")
    os.makedirs(candidate, exist_ok=exist_ok)
    return candidate


@contextmanager
def safe_tempdir(base_path: str):
    """
    Create a temporary directory with three-stage containment validation.

    This is a context manager that creates a temp directory under base_path
    and cleans it up when done. The base_path must be under TRUSTED_ROOT.

    Args:
        base_path: The base directory under which to create the temp dir

    Yields:
        The path to the temporary directory as a string

    Raises:
        PathContainmentError: If base_path escapes TRUSTED_ROOT
    """
    trusted_root = os.path.realpath(TRUSTED_ROOT)
    base = os.path.realpath(base_path)
    # Verify base is under trusted_root (de-taints base for CodeQL)
    if os.path.commonpath([trusted_root, base]) != trusted_root:
        raise PathContainmentError(f"Base path escapes trusted root: {base_path}")
    # Create base directory if it doesn't exist
    os.makedirs(base, exist_ok=True)
    # Create temp directory under the validated base
    with tempfile.TemporaryDirectory(dir=base) as temp_dir:
        # Verify temp_dir is under base (should always be true, but check for safety)
        temp_resolved = os.path.realpath(temp_dir)
        if os.path.commonpath([base, temp_resolved]) != base:
            raise PathContainmentError(f"Temp directory escapes base: {temp_dir}")
        yield temp_resolved
