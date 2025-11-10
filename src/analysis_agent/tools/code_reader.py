"""
Code reading tool for analyzing target agent codebases.
Supports both local filesystem and Docker container access.
"""
import os
import logging
import subprocess
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def read_code(
    file_path: str,
    container_name: Optional[str] = None,
    max_lines: Optional[int] = None,
    line_offset: Optional[int] = None
) -> dict:
    """Read source code file from target agent codebase.

    Can read from local filesystem or Docker container. Use this to analyze
    target agent's implementation, configuration files, and data flows.

    Args:
        file_path: Path to the file to read
        container_name: If provided, read from Docker container instead of local filesystem
        max_lines: Maximum number of lines to read (useful for large files)
        line_offset: Starting line number (0-based, useful with max_lines)

    Returns:
        dict: {
            "success": bool,
            "file_path": str,
            "content": str,           # File contents
            "lines_read": int,        # Number of lines read
            "total_lines": int,       # Total lines in file
            "truncated": bool,        # Whether content was truncated
            "source": str,            # "local" or "docker"
            "message": str
        }

    Example:
        # Read local file
        read_code(file_path="/path/to/target/agent.py")

        # Read from Docker container
        read_code(file_path="/app/agent.py", container_name="target_agent_container")

        # Read first 100 lines
        read_code(file_path="/app/agent.py", max_lines=100)
    """
    try:
        if container_name:
            # Read from Docker container
            return _read_from_docker(file_path, container_name, max_lines, line_offset)
        else:
            # Read from local filesystem
            return _read_from_local(file_path, max_lines, line_offset)

    except Exception as e:
        logger.error(f"Code read error: {e}", exc_info=True)
        return {
            "success": False,
            "file_path": file_path,
            "content": "",
            "lines_read": 0,
            "total_lines": 0,
            "truncated": False,
            "source": "docker" if container_name else "local",
            "message": f"Error: {str(e)}"
        }


def list_directory(
    dir_path: str,
    container_name: Optional[str] = None,
    recursive: bool = False,
    pattern: Optional[str] = None
) -> dict:
    """List directory contents to discover target agent files.

    Args:
        dir_path: Path to directory
        container_name: If provided, list from Docker container
        recursive: If True, list subdirectories recursively
        pattern: Optional glob pattern (e.g., "*.py", "*.yaml")

    Returns:
        dict: {
            "success": bool,
            "dir_path": str,
            "files": List[str],       # List of file names/paths
            "directories": List[str], # List of subdirectories
            "total_files": int,
            "source": str,
            "message": str
        }
    """
    try:
        if container_name:
            return _list_docker_directory(dir_path, container_name, recursive, pattern)
        else:
            return _list_local_directory(dir_path, recursive, pattern)

    except Exception as e:
        logger.error(f"Directory list error: {e}", exc_info=True)
        return {
            "success": False,
            "dir_path": dir_path,
            "files": [],
            "directories": [],
            "total_files": 0,
            "source": "docker" if container_name else "local",
            "message": f"Error: {str(e)}"
        }


def search_code(
    search_pattern: str,
    search_path: str,
    container_name: Optional[str] = None,
    file_pattern: Optional[str] = None,
    max_results: int = 50
) -> dict:
    """Search for patterns in target agent codebase using grep.

    Args:
        search_pattern: Pattern to search for (supports regex)
        search_path: Directory to search in
        container_name: If provided, search in Docker container
        file_pattern: Optional file pattern (e.g., "*.py")
        max_results: Maximum number of results to return

    Returns:
        dict: {
            "success": bool,
            "pattern": str,
            "matches": List[dict],    # [{"file": str, "line": int, "text": str}, ...]
            "total_matches": int,
            "truncated": bool,
            "source": str,
            "message": str
        }
    """
    try:
        if container_name:
            return _search_docker_code(search_pattern, search_path, container_name, file_pattern, max_results)
        else:
            return _search_local_code(search_pattern, search_path, file_pattern, max_results)

    except Exception as e:
        logger.error(f"Code search error: {e}", exc_info=True)
        return {
            "success": False,
            "pattern": search_pattern,
            "matches": [],
            "total_matches": 0,
            "truncated": False,
            "source": "docker" if container_name else "local",
            "message": f"Error: {str(e)}"
        }


# ============================================================================
# Internal helper functions
# ============================================================================

def _read_from_local(file_path: str, max_lines: Optional[int], line_offset: Optional[int]) -> dict:
    """Read file from local filesystem."""
    if not os.path.exists(file_path):
        return {
            "success": False,
            "file_path": file_path,
            "content": "",
            "lines_read": 0,
            "total_lines": 0,
            "truncated": False,
            "source": "local",
            "message": f"File not found: {file_path}"
        }

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    total_lines = len(lines)
    offset = line_offset or 0
    limit = max_lines or total_lines

    # Apply offset and limit
    selected_lines = lines[offset:offset + limit]
    content = ''.join(selected_lines)
    lines_read = len(selected_lines)
    truncated = (offset + lines_read) < total_lines

    return {
        "success": True,
        "file_path": file_path,
        "content": content,
        "lines_read": lines_read,
        "total_lines": total_lines,
        "truncated": truncated,
        "source": "local",
        "message": f"Read {lines_read}/{total_lines} lines from {file_path}"
    }


def _read_from_docker(file_path: str, container_name: str, max_lines: Optional[int], line_offset: Optional[int]) -> dict:
    """Read file from Docker container using docker exec."""
    try:
        # Build command based on parameters
        if max_lines and line_offset:
            # Read specific range: skip first N lines, then read M lines
            cmd = f"tail -n +{line_offset + 1} {file_path} | head -n {max_lines}"
        elif max_lines:
            # Read first N lines
            cmd = f"head -n {max_lines} {file_path}"
        elif line_offset:
            # Skip first N lines, read rest
            cmd = f"tail -n +{line_offset + 1} {file_path}"
        else:
            # Read entire file
            cmd = f"cat {file_path}"

        # Execute in container
        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "success": False,
                "file_path": file_path,
                "content": "",
                "lines_read": 0,
                "total_lines": 0,
                "truncated": False,
                "source": "docker",
                "message": f"Docker exec failed: {result.stderr}"
            }

        content = result.stdout
        lines_read = len(content.splitlines())

        # Get total line count
        total_result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", f"wc -l < {file_path}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        total_lines = int(total_result.stdout.strip()) if total_result.returncode == 0 else lines_read

        truncated = lines_read < total_lines

        return {
            "success": True,
            "file_path": file_path,
            "content": content,
            "lines_read": lines_read,
            "total_lines": total_lines,
            "truncated": truncated,
            "source": "docker",
            "message": f"Read {lines_read}/{total_lines} lines from container:{container_name}:{file_path}"
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "file_path": file_path,
            "content": "",
            "lines_read": 0,
            "total_lines": 0,
            "truncated": False,
            "source": "docker",
            "message": "Command timeout - file may be too large"
        }
    except Exception as e:
        raise


def _list_local_directory(dir_path: str, recursive: bool, pattern: Optional[str]) -> dict:
    """List local directory contents."""
    path = Path(dir_path)

    if not path.exists():
        return {
            "success": False,
            "dir_path": dir_path,
            "files": [],
            "directories": [],
            "total_files": 0,
            "source": "local",
            "message": f"Directory not found: {dir_path}"
        }

    files = []
    directories = []

    if recursive:
        # Recursive listing
        glob_pattern = f"**/{pattern}" if pattern else "**/*"
        for item in path.glob(glob_pattern):
            if item.is_file():
                files.append(str(item.relative_to(path)))
            elif item.is_dir():
                directories.append(str(item.relative_to(path)))
    else:
        # Non-recursive
        for item in path.iterdir():
            if pattern and not item.match(pattern):
                continue
            if item.is_file():
                files.append(item.name)
            elif item.is_dir():
                directories.append(item.name)

    return {
        "success": True,
        "dir_path": dir_path,
        "files": sorted(files),
        "directories": sorted(directories),
        "total_files": len(files),
        "source": "local",
        "message": f"Found {len(files)} files and {len(directories)} directories"
    }


def _list_docker_directory(dir_path: str, container_name: str, recursive: bool, pattern: Optional[str]) -> dict:
    """List Docker container directory contents."""
    try:
        if recursive:
            if pattern:
                cmd = f"find {dir_path} -name '{pattern}' -type f"
            else:
                cmd = f"find {dir_path} -type f"
        else:
            cmd = f"ls -1 {dir_path}"

        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return {
                "success": False,
                "dir_path": dir_path,
                "files": [],
                "directories": [],
                "total_files": 0,
                "source": "docker",
                "message": f"Docker exec failed: {result.stderr}"
            }

        items = [line.strip() for line in result.stdout.splitlines() if line.strip()]

        return {
            "success": True,
            "dir_path": dir_path,
            "files": items,
            "directories": [],  # Simplified for docker
            "total_files": len(items),
            "source": "docker",
            "message": f"Found {len(items)} items in container:{container_name}:{dir_path}"
        }

    except Exception as e:
        raise


def _search_local_code(search_pattern: str, search_path: str, file_pattern: Optional[str], max_results: int) -> dict:
    """Search code in local filesystem using grep."""
    try:
        cmd = ["grep", "-rn", search_pattern, search_path]
        if file_pattern:
            cmd.extend(["--include", file_pattern])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        # grep returns 1 if no matches found
        if result.returncode not in [0, 1]:
            return {
                "success": False,
                "pattern": search_pattern,
                "matches": [],
                "total_matches": 0,
                "truncated": False,
                "source": "local",
                "message": f"Grep failed: {result.stderr}"
            }

        matches = []
        for line in result.stdout.splitlines()[:max_results]:
            parts = line.split(':', 2)
            if len(parts) >= 3:
                matches.append({
                    "file": parts[0],
                    "line": int(parts[1]),
                    "text": parts[2]
                })

        total_matches = len(result.stdout.splitlines())
        truncated = total_matches > max_results

        return {
            "success": True,
            "pattern": search_pattern,
            "matches": matches,
            "total_matches": total_matches,
            "truncated": truncated,
            "source": "local",
            "message": f"Found {len(matches)} matches (showing up to {max_results})"
        }

    except Exception as e:
        raise


def _search_docker_code(search_pattern: str, search_path: str, container_name: str, file_pattern: Optional[str], max_results: int) -> dict:
    """Search code in Docker container using grep."""
    try:
        if file_pattern:
            cmd = f"grep -rn --include '{file_pattern}' '{search_pattern}' {search_path}"
        else:
            cmd = f"grep -rn '{search_pattern}' {search_path}"

        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode not in [0, 1]:
            return {
                "success": False,
                "pattern": search_pattern,
                "matches": [],
                "total_matches": 0,
                "truncated": False,
                "source": "docker",
                "message": f"Docker grep failed: {result.stderr}"
            }

        matches = []
        for line in result.stdout.splitlines()[:max_results]:
            parts = line.split(':', 2)
            if len(parts) >= 3:
                matches.append({
                    "file": parts[0],
                    "line": int(parts[1]),
                    "text": parts[2]
                })

        total_matches = len(result.stdout.splitlines())
        truncated = total_matches > max_results

        return {
            "success": True,
            "pattern": search_pattern,
            "matches": matches,
            "total_matches": total_matches,
            "truncated": truncated,
            "source": "docker",
            "message": f"Found {len(matches)} matches in container (showing up to {max_results})"
        }

    except Exception as e:
        raise


__all__ = ["read_code", "list_directory", "search_code"]
