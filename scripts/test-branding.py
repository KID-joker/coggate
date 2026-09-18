#!/usr/bin/env python3
"""Check repository paths and text for a retired product name."""

from __future__ import annotations

import argparse
import errno
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


RETIRED_NAME = "agent" + "gate"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_READ_BYTES = 64 * 1024 * 1024
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_DIAGNOSTICS = 10_000
EXIT_CLEAN = 0
EXIT_MATCH = 1
EXIT_ERROR = 2


def display_path(path: Path) -> str:
    return json.dumps(path.as_posix(), ensure_ascii=True)


def repository_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot locate repository root")
    return Path(os.fsdecode(result.stdout.rstrip(b"\n"))).resolve()


def tracked_paths(root: Path) -> list[Path]:
    process = subprocess.Popen(
        ["git", "ls-files", "-z"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        raise RuntimeError("cannot read tracked paths")
    data = process.stdout.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        process.kill()
        process.wait()
        raise RuntimeError("tracked path input limit exceeded")
    if process.wait() != 0:
        raise RuntimeError("cannot enumerate tracked files")
    paths = [Path(os.fsdecode(item)) for item in data.split(b"\0") if item]
    if len(paths) > MAX_ENTRIES:
        raise RuntimeError("tracked path count limit exceeded")
    return paths


def stdin_paths(stream: io.BufferedReader) -> list[Path]:
    """Read NUL-delimited paths, or newline-delimited paths when no NUL exists."""
    data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise RuntimeError("stdin path input limit exceeded")
    chunks = data.split(b"\0") if b"\0" in data else data.splitlines()
    paths = [Path(os.fsdecode(item)) for item in chunks if item]
    if len(paths) > MAX_ENTRIES:
        raise RuntimeError("stdin path count limit exceeded")
    return paths


def normalize_path(root: Path, supplied: Path) -> Path:
    candidate = supplied if supplied.is_absolute() else root / supplied
    candidate = Path(os.path.abspath(candidate))
    try:
        return candidate.relative_to(root)
    except ValueError as error:
        raise ValueError("path is outside the repository") from error


def has_symlink_component(root: Path, relative: Path) -> bool:
    current = root
    for component in relative.parts:
        current = current / component
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                return True
        except OSError:
            return False
    return False


def require_safe_fd_capabilities() -> None:
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not isinstance(getattr(os, name, None), int) or getattr(os, name) == 0 for name in required_flags):
        raise RuntimeError("safe descriptor operations are unavailable")
    if os.open not in getattr(os, "supports_dir_fd", ()):
        raise RuntimeError("safe descriptor operations are unavailable")
    if os.scandir not in getattr(os, "supports_fd", ()):
        raise RuntimeError("safe descriptor operations are unavailable")


def directory_open_flags() -> int:
    require_safe_fd_capabilities()
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def open_directory_beneath(root: Path, relative: Path) -> int:
    directory_fd = os.open(root, directory_open_flags())
    try:
        for component in relative.parts:
            next_fd = os.open(component, directory_open_flags(), dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd
    except BaseException:
        os.close(directory_fd)
        raise


def record_bounded_error(errors: list[str], budget: list[int], diagnostic: str) -> bool:
    if budget[0] > 0:
        errors.append(diagnostic)
        budget[0] -= 1
        return True
    if errors:
        errors[-1] = "error: diagnostic limit exceeded"
    return False


def files_below(
    root: Path,
    relative_dir: Path,
    budget: list[int] | None = None,
    diagnostic_budget: list[int] | None = None,
    errors: list[str] | None = None,
) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    reported_errors = errors if errors is not None else []
    remaining = budget if budget is not None else [MAX_ENTRIES]
    remaining_diagnostics = (
        diagnostic_budget if diagnostic_budget is not None else [MAX_DIAGNOSTICS]
    )
    pending = [relative_dir]
    while pending:
        if remaining[0] <= 0:
            record_bounded_error(
                reported_errors, remaining_diagnostics, "error: entry count limit exceeded"
            )
            return files, reported_errors
        remaining[0] -= 1
        directory = pending.pop()
        try:
            directory_fd = open_directory_beneath(root, directory)
        except FileNotFoundError:
            if directory == relative_dir:
                return files, reported_errors
            if not record_bounded_error(
                reported_errors, remaining_diagnostics, f"error: {display_path(directory)}"
            ):
                return files, reported_errors
            continue
        except OSError as error:
            if error.errno not in (errno.ELOOP, errno.ENOTDIR):
                if not record_bounded_error(
                    reported_errors,
                    remaining_diagnostics,
                    f"error: {display_path(directory)}",
                ):
                    return files, reported_errors
            continue
        try:
            entries = os.scandir(directory_fd)
        except OSError:
            os.close(directory_fd)
            if not record_bounded_error(
                reported_errors, remaining_diagnostics, f"error: {display_path(directory)}"
            ):
                return files, reported_errors
            continue
        try:
            with entries:
                for entry in entries:
                    if remaining[0] <= 0:
                        record_bounded_error(
                            reported_errors,
                            remaining_diagnostics,
                            "error: entry count limit exceeded",
                        )
                        return files, reported_errors
                    remaining[0] -= 1
                    relative = directory / entry.name
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(relative)
                        else:
                            files.append(relative)
                    except OSError as error:
                        if error.errno not in (errno.ELOOP, errno.ENOTDIR):
                            if not record_bounded_error(
                                reported_errors,
                                remaining_diagnostics,
                                f"error: {display_path(relative)}",
                            ):
                                return files, reported_errors
        finally:
            os.close(directory_fd)
    return files, reported_errors


def expand_explicit_paths(
    root: Path,
    supplied: list[Path],
    budget: list[int] | None = None,
    diagnostic_budget: list[int] | None = None,
    errors: list[str] | None = None,
) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    reported_errors = errors if errors is not None else []
    remaining = budget if budget is not None else [MAX_ENTRIES]
    remaining_diagnostics = (
        diagnostic_budget if diagnostic_budget is not None else [MAX_DIAGNOSTICS]
    )
    for item in supplied:
        if remaining[0] <= 0:
            record_bounded_error(
                reported_errors, remaining_diagnostics, "error: entry count limit exceeded"
            )
            return files, reported_errors
        remaining[0] -= 1
        try:
            relative = normalize_path(root, item)
        except ValueError:
            if not record_bounded_error(
                reported_errors, remaining_diagnostics, "error: path outside repository"
            ):
                return files, reported_errors
            continue
        absolute = root / relative
        if has_symlink_component(root, relative):
            files.append(relative)
            continue
        try:
            mode = absolute.lstat().st_mode
        except OSError:
            if not record_bounded_error(
                reported_errors, remaining_diagnostics, f"error: {display_path(relative)}"
            ):
                return files, reported_errors
            continue
        if stat.S_ISREG(mode):
            files.append(relative)
        elif stat.S_ISDIR(mode):
            nested, _ = files_below(
                root,
                relative,
                remaining,
                remaining_diagnostics,
                reported_errors,
            )
            files.extend(nested)
        else:
            files.append(relative)
        if len(files) > MAX_ENTRIES:
            record_bounded_error(
                reported_errors, remaining_diagnostics, "error: entry count limit exceeded"
            )
            return files[:MAX_ENTRIES], reported_errors
    return files, reported_errors


def consume_read_budget(read_budget: list[int], byte_count: int) -> bool:
    if byte_count > read_budget[0]:
        read_budget[0] = 0
        return False
    read_budget[0] -= byte_count
    return True


def read_regular_file(
    root: Path, relative: Path, read_budget: list[int] | None = None
) -> tuple[bytes | None, str | None]:
    remaining = read_budget if read_budget is not None else [MAX_TOTAL_READ_BYTES]
    require_safe_fd_capabilities()
    file_flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = open_directory_beneath(root, Path(*relative.parts[:-1]))
        file_fd = os.open(relative.parts[-1], file_flags, dir_fd=directory_fd)
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            return None, None
        if file_stat.st_size > MAX_FILE_BYTES:
            return None, f"error: {display_path(relative)}: file size limit exceeded"
        if file_stat.st_size > remaining[0]:
            return None, "error: total read byte limit exceeded"
        with os.fdopen(file_fd, "rb", closefd=True) as handle:
            file_fd = None
            data = handle.read(min(MAX_FILE_BYTES, remaining[0]) + 1)
        if not consume_read_budget(remaining, len(data)):
            return None, "error: total read byte limit exceeded"
        if len(data) > MAX_FILE_BYTES:
            return None, f"error: {display_path(relative)}: file size limit exceeded"
        return data, None
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            return None, None
        return None, f"error: {display_path(relative)}"
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def content_lines(
    root: Path,
    relative: Path,
    read_budget: list[int] | None = None,
    match_limit: int = MAX_DIAGNOSTICS,
) -> tuple[list[int], str | None]:
    data, error = read_regular_file(root, relative, read_budget)
    if error or data is None:
        return [], error
    needle = RETIRED_NAME.casefold()

    encoding: str | None = None
    encoding_label: str | None = None
    ambiguous_nul_encoding = False
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encoding = "utf-32"
        encoding_label = "UTF-32"
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
        encoding_label = "UTF-16"
    elif len(data) >= 4 and b"\x00" in data:
        sample = data[: min(len(data), 4096)]
        even = sample[0::2]
        odd = sample[1::2]
        even_nul_ratio = even.count(0) / len(even)
        odd_nul_ratio = odd.count(0) / len(odd)
        if odd_nul_ratio >= 0.6 and even_nul_ratio <= 0.2:
            encoding = "utf-16-le"
            encoding_label = "UTF-16LE"
        elif even_nul_ratio >= 0.6 and odd_nul_ratio <= 0.2:
            encoding = "utf-16-be"
            encoding_label = "UTF-16BE"
        elif max(even_nul_ratio, odd_nul_ratio) >= 0.3:
            ambiguous_nul_encoding = True

    if encoding is None and b"\x00" in data:
        lowered_data = data.lower()
        utf16le_needle = RETIRED_NAME.encode("utf-16-le").lower()
        utf16be_needle = RETIRED_NAME.encode("utf-16-be").lower()

        def has_aligned_needle(candidate: bytes) -> bool:
            offset = lowered_data.find(candidate)
            while offset >= 0:
                if offset % 2 == 0:
                    return True
                offset = lowered_data.find(candidate, offset + 1)
            return False

        has_utf16le_needle = has_aligned_needle(utf16le_needle)
        has_utf16be_needle = has_aligned_needle(utf16be_needle)
        if has_utf16le_needle != has_utf16be_needle:
            encoding = "utf-16-le" if has_utf16le_needle else "utf-16-be"
            encoding_label = "UTF-16LE" if has_utf16le_needle else "UTF-16BE"
        elif has_utf16le_needle or ambiguous_nul_encoding:
            return [], f"error: {display_path(relative)}: ambiguous NUL text encoding"

    if encoding is not None:
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            return [], f"error: {display_path(relative)}: invalid {encoding_label} text"
        lines = text.splitlines()
        line_needle: str | bytes = needle
    else:
        try:
            text = data.decode("utf-8-sig")
            lines = text.splitlines()
            line_needle = needle
        except UnicodeDecodeError:
            if b"\x00" in data:
                return [], f"error: {display_path(relative)}: ambiguous NUL text encoding"
            lines = data.splitlines()
            line_needle = RETIRED_NAME.encode("ascii").lower()

    matches: list[int] = []
    for number, line in enumerate(lines, 1):
        normalized = line.casefold() if isinstance(line, str) else line.lower()
        if line_needle in normalized:
            if len(matches) >= max(0, match_limit):
                return matches, "error: diagnostic limit exceeded"
            matches.append(number)
    return matches, None


def scan(
    root: Path,
    paths: list[Path],
    read_budget: list[int] | None = None,
    diagnostic_limit: int = MAX_DIAGNOSTICS,
) -> tuple[list[str], list[str]]:
    findings: list[str] = []
    errors: list[str] = []
    remaining_bytes = read_budget if read_budget is not None else [MAX_TOTAL_READ_BYTES]
    limit = max(1, diagnostic_limit)
    needle = RETIRED_NAME.casefold()
    seen: set[Path] = set()

    def add_diagnostic(target: list[str], diagnostic: str) -> bool:
        if len(findings) + len(errors) >= limit:
            if findings:
                findings.pop()
            elif errors:
                errors.pop()
            errors.append("error: diagnostic limit exceeded")
            return False
        target.append(diagnostic)
        return True

    for relative in paths:
        if relative in seen:
            continue
        seen.add(relative)
        if needle in relative.as_posix().casefold() or any(
            needle in component.casefold() for component in relative.parts
        ):
            if not add_diagnostic(findings, f"path match: {display_path(relative)}"):
                break
        available_matches = max(0, limit - len(findings) - len(errors))
        lines, error = content_lines(
            root, relative, remaining_bytes, match_limit=available_matches
        )
        for line in lines:
            if not add_diagnostic(findings, f"content match: {display_path(relative)}:{line}"):
                return findings, errors
        if error:
            if not add_diagnostic(errors, error):
                break
            if "total read byte limit exceeded" in error:
                break
    return findings, errors


def run_self_test() -> int:
    def check(condition: bool, message: str) -> None:
        if not condition:
            raise RuntimeError(f"self-test failed: {message}")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        mixed = RETIRED_NAME.swapcase()
        secret = f"do-not-print-{mixed}-payload"
        sample = root / "sample.txt"
        sample.write_text(f"safe\n{secret}\nsafe\n", encoding="utf-8")
        named = Path("nested") / f"pre-{mixed}-post.txt"
        (root / named.parent).mkdir()
        (root / named).write_text("safe\n", encoding="utf-8")

        findings, errors = scan(root, [Path("sample.txt"), named])
        rendered = "\n".join(findings + errors)
        check(not errors, "text fixture produced an error")
        check(f'{display_path(Path("sample.txt"))}:2' in rendered, "line number missing")
        check(f"path match: {display_path(named)}" in rendered, "path match missing")
        check(secret not in rendered, "matching line contents leaked")

        at_limit = root / "at-limit.txt"
        at_limit.write_bytes(b"x" * MAX_FILE_BYTES)
        over_limit = root / "over-limit.txt"
        over_limit.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        check(content_lines(root, Path("at-limit.txt")) == ([], None), "boundary file rejected")
        check(
            "size limit exceeded" in (content_lines(root, Path("over-limit.txt"))[1] or ""),
            "oversized file accepted",
        )

        docs = root / "docs"
        docs.mkdir()
        ignored = docs / "ignored.txt"
        ignored.write_text(mixed, encoding="utf-8")
        collected, collect_errors = files_below(root, Path("docs"))
        check(not collect_errors, "docs collection produced an error")
        check(Path("docs/ignored.txt") in collected, "ignored docs file not collected")
        docs_findings, docs_errors = scan(root, collected)
        check(bool(docs_findings) and not docs_errors, "ignored docs contents not scanned")

        global MAX_ENTRIES
        saved_entry_limit = MAX_ENTRIES
        (docs / "second.txt").write_text("safe", encoding="utf-8")
        try:
            MAX_ENTRIES = 1
            _, limit_errors = files_below(root, Path("docs"))
        finally:
            MAX_ENTRIES = saved_entry_limit
        check("error: entry count limit exceeded" in limit_errors, "entry limit not enforced")

        binary = root / "binary.dat"
        binary.write_bytes(b"\0" + RETIRED_NAME.encode("ascii"))
        check(content_lines(root, Path("binary.dat")) == ([1], None), "binary ASCII match missed")

        utf16 = root / "utf16.txt"
        utf16.write_bytes(b"\xff\xfe" + f"safe\n{mixed}\n".encode("utf-16-le"))
        check(content_lines(root, Path("utf16.txt")) == ([2], None), "UTF-16 match missed")

        utf16le_no_bom = root / "utf16le-no-bom.txt"
        utf16le_no_bom.write_bytes(f"safe\n{mixed}\n".encode("utf-16-le"))
        check(
            content_lines(root, Path("utf16le-no-bom.txt")) == ([2], None),
            "UTF-16LE without BOM match missed",
        )

        utf16be_no_bom = root / "utf16be-no-bom.txt"
        utf16be_no_bom.write_bytes(f"safe\n{mixed}\n".encode("utf-16-be"))
        check(
            content_lines(root, Path("utf16be-no-bom.txt")) == ([2], None),
            "UTF-16BE without BOM match missed",
        )

        utf16le_non_ascii = root / "utf16le-non-ascii.txt"
        utf16le_non_ascii.write_bytes(("汉" * 100 + f"\n{mixed}\n").encode("utf-16-le"))
        check(
            content_lines(root, Path("utf16le-non-ascii.txt")) == ([2], None),
            "UTF-16LE match after non-ASCII text missed",
        )

        utf16be_non_ascii = root / "utf16be-non-ascii.txt"
        utf16be_non_ascii.write_bytes(("汉" * 100 + f"\n{mixed}\n").encode("utf-16-be"))
        check(
            content_lines(root, Path("utf16be-non-ascii.txt")) == ([2], None),
            "UTF-16BE match after non-ASCII text missed",
        )

        utf32 = root / "utf32.txt"
        utf32.write_bytes(f"safe\n{mixed}\n".encode("utf-32"))
        check(content_lines(root, Path("utf32.txt")) == ([2], None), "UTF-32 match missed")

        ambiguous_unicode = root / "ambiguous-unicode.dat"
        ambiguous_unicode.write_bytes(b"A\x00\x00\x00" * 4)
        ambiguous_lines, ambiguous_error = content_lines(
            root, Path("ambiguous-unicode.dat")
        )
        check(not ambiguous_lines, "ambiguous Unicode produced findings")
        check(
            "ambiguous NUL text encoding" in (ambiguous_error or ""),
            "ambiguous Unicode was treated as clean",
        )

        invalid_utf8 = root / "invalid-utf8.txt"
        invalid_utf8.write_bytes(b"\xffsafe\n" + mixed.encode("ascii") + b"\n")
        check(
            content_lines(root, Path("invalid-utf8.txt")) == ([2], None),
            "invalid UTF-8 ASCII match missed",
        )

        link = root / f"link-{mixed}"
        try:
            link.symlink_to(sample)
        except OSError:
            pass
        else:
            link_findings, link_errors = scan(root, [link.relative_to(root)])
            check(not link_errors, "symbolic link produced an error")
            check(len(link_findings) == 1 and link_findings[0].startswith("path match:"), "link target read")

        special_dir = root / "special"
        special_dir.mkdir()
        special_link = special_dir / f"link-{mixed}"
        special_link.symlink_to(sample)
        special_fifo = special_dir / f"fifo-{mixed}"
        os.mkfifo(special_fifo)
        special_paths, special_errors = files_below(root, Path("special"))
        check(not special_errors, "special path collection produced an error")
        check(special_link.relative_to(root) in special_paths, "directory symlink path missed")
        check(special_fifo.relative_to(root) in special_paths, "FIFO path missed")
        special_findings, special_scan_errors = scan(root, special_paths)
        check(not special_scan_errors, "special paths were read")
        check(len(special_findings) == 2, "special path findings missing")
        explicit_special, explicit_special_errors = expand_explicit_paths(
            root, [special_fifo.relative_to(root)]
        )
        check(not explicit_special_errors, "explicit special path produced an error")
        check(special_fifo.relative_to(root) in explicit_special, "explicit FIFO path missed")

        budget_one = root / "budget-one.txt"
        budget_two = root / "budget-two.txt"
        budget_one.write_text("safe", encoding="utf-8")
        budget_two.write_text("safe", encoding="utf-8")
        _, byte_budget_errors = scan(
            root,
            [Path("budget-one.txt"), Path("budget-two.txt")],
            read_budget=[budget_one.stat().st_size],
        )
        check(
            any("total read byte limit exceeded" in item for item in byte_budget_errors),
            "shared read budget not enforced",
        )

        diagnostic_paths: list[Path] = []
        for number in range(3):
            diagnostic = root / f"diagnostic-{number}.txt"
            diagnostic.write_text(mixed, encoding="utf-8")
            diagnostic_paths.append(diagnostic.relative_to(root))
        limited_findings, limited_errors = scan(root, diagnostic_paths, diagnostic_limit=2)
        check(len(limited_findings) + len(limited_errors) <= 2, "diagnostic limit exceeded")
        check(
            "error: diagnostic limit exceeded" in limited_errors,
            "diagnostic limit error missing",
        )
        dense = root / "dense.txt"
        dense.write_text((mixed + "\n") * 4, encoding="utf-8")
        dense_lines, dense_error = content_lines(root, Path("dense.txt"), match_limit=2)
        check(dense_lines == [1, 2], "single-file match limit not enforced")
        check(dense_error == "error: diagnostic limit exceeded", "single-file limit error missing")
        growth_budget = [MAX_FILE_BYTES + 1]
        check(
            consume_read_budget(growth_budget, MAX_FILE_BYTES + 1),
            "post-read byte charge rejected valid budget",
        )
        check(growth_budget == [0], "post-read bytes were not charged")
        bounded_collection_errors: list[str] = []
        _, bounded_collection_errors = expand_explicit_paths(
            root,
            [Path("missing-one"), Path("missing-two")],
            diagnostic_budget=[1],
            errors=bounded_collection_errors,
        )
        check(
            bounded_collection_errors == ["error: diagnostic limit exceeded"],
            "collection diagnostic budget not shared",
        )

        saved_no_follow = getattr(os, "O_NOFOLLOW", None)
        try:
            os.O_NOFOLLOW = 0
            capability_rejected = False
            try:
                directory_open_flags()
            except RuntimeError:
                capability_rejected = True
        finally:
            if saved_no_follow is None:
                del os.O_NOFOLLOW
            else:
                os.O_NOFOLLOW = saved_no_follow
        check(capability_rejected, "unsafe descriptor fallback accepted")

        captured_error = io.StringIO()
        saved_stderr = sys.stderr
        try:
            sys.stderr = captured_error
            type_error_status = report_operational_error(TypeError("unsupported fd API"))
        finally:
            sys.stderr = saved_stderr
        check(type_error_status == EXIT_ERROR, "TypeError exit status is unstable")
        check("Traceback" not in captured_error.getvalue(), "TypeError leaked a traceback")

        outside = root.parent / "outside.txt"
        _, outside_errors = expand_explicit_paths(root, [outside])
        check(outside_errors == ["error: path outside repository"], "outside path error is unstable")
        check(str(outside) not in "\n".join(outside_errors), "outside absolute path leaked")

    print("self-test: ok")
    return EXIT_CLEAN


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="exit status: 0 clean, 1 naming matches, 2 operational error",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--paths", nargs="+", type=Path, help="explicit files or directories")
    source.add_argument(
        "--paths-from-stdin",
        action="store_true",
        help="read NUL-delimited paths from stdin (newline-delimited is accepted when no NUL is present)",
    )
    parser.add_argument(
        "--include-ignored-docs",
        action="store_true",
        help="also scan ordinary files below docs, including ignored and untracked files",
    )
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def report_operational_error(error: OSError | RuntimeError | TypeError) -> int:
    try:
        print(f"error: {error}", file=sys.stderr)
    except OSError:
        pass
    return EXIT_ERROR


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.self_test:
        try:
            return run_self_test()
        except (OSError, RuntimeError, TypeError) as error:
            return report_operational_error(error)
    try:
        root = repository_root()
        collection_errors: list[str] = []
        budget = [MAX_ENTRIES]
        diagnostic_budget = [MAX_DIAGNOSTICS]
        if args.paths is not None:
            paths, _ = expand_explicit_paths(
                root,
                args.paths,
                budget,
                diagnostic_budget,
                collection_errors,
            )
        elif args.paths_from_stdin:
            paths, _ = expand_explicit_paths(
                root,
                stdin_paths(sys.stdin.buffer),
                budget,
                diagnostic_budget,
                collection_errors,
            )
        else:
            paths = tracked_paths(root)
            budget[0] -= len(paths)
        if args.include_ignored_docs:
            docs_paths, _ = files_below(
                root,
                Path("docs"),
                budget,
                diagnostic_budget,
                collection_errors,
            )
            paths.extend(docs_paths)
        if len(paths) > MAX_ENTRIES:
            paths = paths[:MAX_ENTRIES]
            record_bounded_error(
                collection_errors,
                diagnostic_budget,
                "error: entry count limit exceeded",
            )
        if diagnostic_budget[0] > 0:
            findings, scan_errors = scan(
                root, paths, diagnostic_limit=diagnostic_budget[0]
            )
        else:
            findings, scan_errors = [], []
        combined_errors = collection_errors + scan_errors
        if len(findings) + len(combined_errors) > MAX_DIAGNOSTICS:
            available = MAX_DIAGNOSTICS - 1
            findings = findings[:available]
            available -= len(findings)
            combined_errors = combined_errors[:available]
            combined_errors.append("error: diagnostic limit exceeded")
        for diagnostic in findings:
            print(diagnostic)
        for diagnostic in combined_errors:
            print(diagnostic, file=sys.stderr)
        if combined_errors:
            return EXIT_ERROR
        return EXIT_MATCH if findings else EXIT_CLEAN
    except (OSError, RuntimeError, TypeError) as error:
        return report_operational_error(error)


if __name__ == "__main__":
    raise SystemExit(main())
