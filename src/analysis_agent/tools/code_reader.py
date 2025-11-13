"""
Code reading tool for analyzing local agent codebases.
Supports reading files, listing directories, searching code, and extracting imports.

For Docker container access, use execute_docker_command tool separately.
"""
import os
import logging
import subprocess
import re
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


def read_code(
    file_path: str,
    max_lines: Optional[int] = None,
    line_offset: Optional[int] = None
) -> dict:
    """Read source code file from local filesystem.

    Args:
        file_path: Path to the file to read
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
            "message": str
        }

    Example:
        # Read entire file
        read_code(file_path="/path/to/agent.py")

        # Read first 100 lines
        read_code(file_path="/path/to/agent.py", max_lines=100)

        # Read lines 50-150
        read_code(file_path="/path/to/agent.py", line_offset=50, max_lines=100)
    """
    try:
        if not os.path.exists(file_path):
            return {
                "success": False,
                "file_path": file_path,
                "content": "",
                "lines_read": 0,
                "total_lines": 0,
                "truncated": False,
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
            "message": f"Read {lines_read}/{total_lines} lines from {file_path}"
        }

    except Exception as e:
        logger.error(f"Code read error: {e}", exc_info=True)
        return {
            "success": False,
            "file_path": file_path,
            "content": "",
            "lines_read": 0,
            "total_lines": 0,
            "truncated": False,
            "message": f"Error: {str(e)}"
        }


def list_directory(
    dir_path: str,
    recursive: bool = False,
    pattern: Optional[str] = None
) -> dict:
    """List directory contents from local filesystem.

    Args:
        dir_path: Path to directory
        recursive: If True, list subdirectories recursively
        pattern: Optional glob pattern (e.g., "*.py", "*.yaml")

    Returns:
        dict: {
            "success": bool,
            "dir_path": str,
            "files": List[str],       # List of file names/paths
            "directories": List[str], # List of subdirectories
            "total_files": int,
            "message": str
        }

    Example:
        # List all files in directory
        list_directory("/path/to/codebase")

        # List all Python files recursively
        list_directory("/path/to/codebase", recursive=True, pattern="*.py")
    """
    try:
        path = Path(dir_path)

        if not path.exists():
            return {
                "success": False,
                "dir_path": dir_path,
                "files": [],
                "directories": [],
                "total_files": 0,
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
            "message": f"Found {len(files)} files and {len(directories)} directories"
        }

    except Exception as e:
        logger.error(f"Directory list error: {e}", exc_info=True)
        return {
            "success": False,
            "dir_path": dir_path,
            "files": [],
            "directories": [],
            "total_files": 0,
            "message": f"Error: {str(e)}"
        }


def search_code(
    search_pattern: str,
    search_path: str,
    file_pattern: Optional[str] = None,
    max_results: int = 50
) -> dict:
    """Search for patterns in local codebase using grep.

    Args:
        search_pattern: Pattern to search for (supports regex)
        search_path: Directory to search in
        file_pattern: Optional file pattern (e.g., "*.py")
        max_results: Maximum number of results to return

    Returns:
        dict: {
            "success": bool,
            "pattern": str,
            "matches": List[dict],    # [{"file": str, "line": int, "text": str}, ...]
            "total_matches": int,
            "truncated": bool,
            "message": str
        }

    Example:
        # Search for function definitions
        search_code("def.*tool", "/path/to/codebase")

        # Search only in Python files
        search_code("import.*agent", "/path/to/codebase", file_pattern="*.py")
    """
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
            "message": f"Found {len(matches)} matches (showing up to {max_results})"
        }

    except Exception as e:
        logger.error(f"Code search error: {e}", exc_info=True)
        return {
            "success": False,
            "pattern": search_pattern,
            "matches": [],
            "total_matches": 0,
            "truncated": False,
            "message": f"Error: {str(e)}"
        }


def extract_imports(file_path: str) -> dict:
    """Extract import statements and cross-file references from a code file.

    Supports Python, JavaScript/TypeScript, Go, Java, and other common languages.
    Returns both import statements and resolved file paths when possible.

    Args:
        file_path: Path to the file to analyze

    Returns:
        dict: {
            "success": bool,
            "file_path": str,
            "language": str,           # Detected language
            "imports": List[dict],     # [{
            #   "statement": str,       # Original import statement
            #   "module": str,          # Module/package name
            #   "items": List[str],     # Imported items (if applicable)
            #   "line": int             # Line number
            # }]
            "suggested_files": List[str],  # Suggested file paths to explore
            "message": str
        }

    Example:
        extract_imports("/path/to/agent.py")
        # Returns imports like:
        # - "from tools.reader import read_file" -> suggests tools/reader.py
        # - "import os" -> standard library (no suggestion)
    """
    try:
        # Read file content
        read_result = read_code(file_path)
        if not read_result["success"]:
            return {
                "success": False,
                "file_path": file_path,
                "language": "unknown",
                "imports": [],
                "suggested_files": [],
                "message": f"Failed to read file: {read_result['message']}"
            }

        content = read_result["content"]

        # Detect language from extension
        language = _detect_language(file_path)

        # Extract imports based on language
        imports = []
        suggested_files = []

        if language == "python":
            imports, suggested_files = _extract_python_imports(content, file_path)
        elif language in ["javascript", "typescript"]:
            imports, suggested_files = _extract_js_imports(content, file_path)
        elif language == "go":
            imports, suggested_files = _extract_go_imports(content, file_path)
        elif language == "java":
            imports, suggested_files = _extract_java_imports(content, file_path)

        return {
            "success": True,
            "file_path": file_path,
            "language": language,
            "imports": imports,
            "suggested_files": suggested_files,
            "message": f"Found {len(imports)} imports, {len(suggested_files)} suggested files to explore"
        }

    except Exception as e:
        logger.error(f"Import extraction error: {e}", exc_info=True)
        return {
            "success": False,
            "file_path": file_path,
            "language": "unknown",
            "imports": [],
            "suggested_files": [],
            "message": f"Error: {str(e)}"
        }


def read_code_with_references(
    file_path: str,
    include_imports: bool = True,
    max_lines: Optional[int] = None
) -> dict:
    """Read code file and automatically extract cross-file references.

    This is an enhanced version of read_code that also analyzes imports
    and suggests related files to explore.

    Args:
        file_path: Path to the file to read
        include_imports: Whether to extract imports (default: True)
        max_lines: Maximum lines to read

    Returns:
        dict: Combined result of read_code and extract_imports

    Example:
        result = read_code_with_references("/path/to/agent.py")
        # Returns: content + imports + suggested_files

        # Follow suggested files
        for suggested_file in result["suggested_files"]:
            read_code(suggested_file)
    """
    try:
        # Read file content
        read_result = read_code(file_path, max_lines)
        if not read_result["success"]:
            return read_result

        result = read_result.copy()

        # Extract imports if requested
        if include_imports:
            import_result = extract_imports(file_path)
            if import_result["success"]:
                result["language"] = import_result["language"]
                result["imports"] = import_result["imports"]
                result["suggested_files"] = import_result["suggested_files"]
                result["cross_references_found"] = len(import_result["suggested_files"])

                # Enhance message
                if import_result["suggested_files"]:
                    files_preview = ", ".join(import_result["suggested_files"][:3])
                    more = f" and {len(import_result['suggested_files']) - 3} more" if len(import_result["suggested_files"]) > 3 else ""
                    result["message"] += f"\n\nCross-references found ({len(import_result['suggested_files'])}): {files_preview}{more}"
                    result["message"] += "\nUse read_code to explore these files."

        return result

    except Exception as e:
        logger.error(f"Read with references error: {e}", exc_info=True)
        return {
            "success": False,
            "file_path": file_path,
            "message": f"Error: {str(e)}"
        }


# ============================================================================
# Internal helper functions for import extraction
# ============================================================================

def _detect_language(file_path: str) -> str:
    """Detect programming language from file extension."""
    ext = Path(file_path).suffix.lower()

    language_map = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp"
    }

    return language_map.get(ext, "unknown")


def _extract_python_imports(content: str, file_path: str) -> tuple:
    """Extract Python import statements and resolve file paths."""
    imports = []
    suggested_files = []

    # Regex patterns for Python imports
    import_pattern = re.compile(r'^import\s+([a-zA-Z0-9_., ]+)', re.MULTILINE)
    from_import_pattern = re.compile(r'^from\s+([a-zA-Z0-9_.]+)\s+import\s+([a-zA-Z0-9_., *\(\)]+)', re.MULTILINE)

    lines = content.split('\n')
    base_dir = str(Path(file_path).parent)

    # Extract standard imports
    for i, line in enumerate(lines, 1):
        # Match "import module"
        import_match = import_pattern.match(line.strip())
        if import_match:
            modules = [m.strip() for m in import_match.group(1).split(',')]
            for module in modules:
                imports.append({
                    "statement": f"import {module}",
                    "module": module,
                    "items": [],
                    "line": i
                })

                # Try to resolve to file path (for relative imports)
                resolved = _resolve_python_module(module, base_dir)
                if resolved:
                    suggested_files.append(resolved)

        # Match "from module import items"
        from_match = from_import_pattern.match(line.strip())
        if from_match:
            module = from_match.group(1)
            items_str = from_match.group(2)
            items = [item.strip() for item in items_str.replace('(', '').replace(')', '').split(',')]

            imports.append({
                "statement": line.strip(),
                "module": module,
                "items": items,
                "line": i
            })

            # Try to resolve to file path
            resolved = _resolve_python_module(module, base_dir)
            if resolved:
                suggested_files.append(resolved)

    return imports, list(set(suggested_files))  # Remove duplicates


def _resolve_python_module(module: str, base_dir: str) -> Optional[str]:
    """Resolve Python module name to file path."""
    # Skip standard library modules (common ones)
    stdlib_modules = {
        'os', 'sys', 'json', 'logging', 'pathlib', 'subprocess', 're',
        'typing', 'datetime', 'time', 'collections', 'itertools', 'functools',
        'asyncio', 'threading', 'multiprocessing', 'unittest', 'pytest'
    }

    if module.split('.')[0] in stdlib_modules:
        return None

    # Convert module path to file path (e.g., tools.reader -> tools/reader.py)
    module_path = module.replace('.', '/')

    # Try both .py file and __init__.py in directory
    candidates = [
        f"{base_dir}/{module_path}.py",
        f"{base_dir}/{module_path}/__init__.py"
    ]

    # Return first candidate (actual existence check would be done by caller)
    return candidates[0]


def _extract_js_imports(content: str, file_path: str) -> tuple:
    """Extract JavaScript/TypeScript import statements."""
    imports = []
    suggested_files = []

    # Regex patterns for JS/TS imports
    import_pattern = re.compile(r'^import\s+(?:(.+?)\s+from\s+)?[\'"]([^\'"]+)[\'"]', re.MULTILINE)
    require_pattern = re.compile(r'(?:const|let|var)\s+(.+?)\s*=\s*require\([\'"]([^\'"]+)[\'"]\)', re.MULTILINE)

    lines = content.split('\n')
    base_dir = str(Path(file_path).parent)

    for i, line in enumerate(lines, 1):
        # Match ES6 imports
        import_match = import_pattern.match(line.strip())
        if import_match:
            items_str = import_match.group(1) or ""
            module = import_match.group(2)

            imports.append({
                "statement": line.strip(),
                "module": module,
                "items": [items_str] if items_str else [],
                "line": i
            })

            # Resolve relative imports (./path or ../path)
            if module.startswith('.'):
                resolved = f"{base_dir}/{module}"
                # Add common extensions
                for ext in ['.js', '.ts', '.jsx', '.tsx']:
                    suggested_files.append(f"{resolved}{ext}")

        # Match require() statements
        require_match = require_pattern.search(line)
        if require_match:
            module = require_match.group(2)
            imports.append({
                "statement": line.strip(),
                "module": module,
                "items": [require_match.group(1)],
                "line": i
            })

            if module.startswith('.'):
                resolved = f"{base_dir}/{module}.js"
                suggested_files.append(resolved)

    return imports, list(set(suggested_files))


def _extract_go_imports(content: str, file_path: str) -> tuple:
    """Extract Go import statements."""
    imports = []

    # Go import pattern
    single_import = re.compile(r'^import\s+"([^"]+)"', re.MULTILINE)
    multi_import = re.compile(r'import\s*\((.*?)\)', re.DOTALL)

    # Single imports
    for match in single_import.finditer(content):
        imports.append({
            "statement": match.group(0),
            "module": match.group(1),
            "items": [],
            "line": content[:match.start()].count('\n') + 1
        })

    # Multi-line imports
    for match in multi_import.finditer(content):
        import_block = match.group(1)
        for line in import_block.split('\n'):
            line = line.strip()
            if line and line.startswith('"'):
                module = line.strip('"')
                imports.append({
                    "statement": f'import "{module}"',
                    "module": module,
                    "items": [],
                    "line": content[:match.start()].count('\n') + 1
                })

    # Go imports are typically package paths, not file paths
    return imports, []


def _extract_java_imports(content: str, file_path: str) -> tuple:
    """Extract Java import statements."""
    imports = []

    # Java import pattern
    import_pattern = re.compile(r'^import\s+(?:static\s+)?([a-zA-Z0-9_.]+(?:\.\*)?);', re.MULTILINE)

    for match in import_pattern.finditer(content):
        imports.append({
            "statement": match.group(0),
            "module": match.group(1),
            "items": [],
            "line": content[:match.start()].count('\n') + 1
        })

    # Java imports are package paths, not direct file paths
    return imports, []


__all__ = [
    "read_code",
    "list_directory",
    "search_code",
    "extract_imports",
    "read_code_with_references"
]
