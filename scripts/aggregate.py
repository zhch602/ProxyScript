#!/usr/bin/env python3

import argparse
import sys
import os
import re
import urllib.request
import urllib.error
from typing import List, Dict, Tuple, Optional, Set
from urllib.parse import urlparse


def parse_rule_yaml(yaml_path: str) -> List[Dict[str, str]]:
    """
    Minimal YAML parser tailored for structure:
    name: <optional>
    desc: <optional>
    rules:
      - url: <string>
        drop: <string>   # optional; tokens separated by comma/space
    Returns list of dicts with keys: 'url' and optional 'drop'.
    """
    rules: List[Dict[str, str]] = []
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        raise SystemExit(f"rule.yml not found at: {yaml_path}")

    in_rules = False
    current: Optional[Dict[str, str]] = None

    for raw in lines:
        line = raw.rstrip('\n')
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if not in_rules:
            if stripped == 'rules:':
                in_rules = True
            continue
        # Now inside rules list
        if stripped.startswith('- '):
            # Start a new item
            if current:
                rules.append(current)
            current = {}
            # Allow inline url on the same line: - url: http...
            m = re.match(r"-\s+url:\s*(.+)", stripped)
            if m:
                current['url'] = m.group(1).strip()
            continue
        if current is None:
            # ignore any garbage until next '- '
            continue
        # Handle indented key: value lines
        m_url = re.match(r"url:\s*(.+)", stripped)
        if m_url:
            current['url'] = m_url.group(1).strip()
            continue
        m_drop = re.match(r"drop:\s*(.+)", stripped)
        if m_drop:
            current['drop'] = m_drop.group(1).strip()
            continue

    if current:
        rules.append(current)

    # Validate
    filtered: List[Dict[str, str]] = []
    for idx, item in enumerate(rules, start=1):
        url = item.get('url')
        if not url:
            print(f"Warning: rule #{idx} is missing 'url', skipped", file=sys.stderr)
            continue
        filtered.append(item)
    return filtered


def parse_meta_yaml(yaml_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse optional top-level name and desc from rule.yml."""
    name: Optional[str] = None
    desc: Optional[str] = None
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.rstrip('\n')
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                # Stop scanning keys when entering rules:
                if stripped == 'rules:':
                    break
                m_name = re.match(r"name:\s*(.+)", stripped)
                if m_name and not name:
                    name = m_name.group(1).strip()
                    continue
                m_desc = re.match(r"desc:\s*(.+)", stripped)
                if m_desc and not desc:
                    desc = m_desc.group(1).strip()
                    continue
    except FileNotFoundError:
        pass
    return name, desc


def fetch_url(url: str, timeout: int = 30) -> Optional[str]:
    # Build headers; some hosts (e.g., whatshub.top) block default browser UA, but allow curl-like UA
    try:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.netloc
    except Exception:
        origin = None
        host = ''

    # Default headers (curl-like UA tends to pass anti-bot on some CDNs)
    headers = {
        'User-Agent': 'curl/8.5.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Connection': 'keep-alive',
    }
    if origin:
        headers['Referer'] = origin + '/'
        headers['Origin'] = origin

    # Special-case tweaks
    if host.endswith('whatshub.top'):
        # Some endpoints require a referer and simple UA
        headers['User-Agent'] = 'curl/8.5.0'
        headers['Referer'] = 'https://whatshub.top/'
        headers['Origin'] = 'https://whatshub.top'

    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return data.decode('utf-8', errors='replace')
                except Exception:
                    return data.decode('latin-1', errors='replace')
    except urllib.error.HTTPError as e:
        print(f"HTTPError fetching {url}: {e}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"URLError fetching {url}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Error fetching {url}: {e}", file=sys.stderr)
    return None


def fetch_url_with_retries(url: str,
                           retries: int = 3,
                           timeout: int = 30,
                           backoff: float = 1.5) -> Tuple[Optional[str], Optional[str]]:
    """Fetch URL with simple retry and exponential backoff. Returns (text, error)."""
    attempt = 0
    last_error: Optional[str] = None
    while attempt <= max(0, retries):
        text = fetch_url(url, timeout=timeout)
        if text is not None:
            return text, None
        attempt += 1
        if attempt > retries:
            break
        # Backoff sleep
        try:
            import time
            sleep_secs = pow(backoff, attempt - 1)
            print(f"  -> retry {attempt}/{retries} in {sleep_secs:.1f}s")
            time.sleep(sleep_secs)
        except Exception:
            pass
    return None, last_error or f"Failed after {retries} retries"


SECTION_HEADER_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
MITM_HOSTNAME_RE = re.compile(r"^\s*hostname\s*=\s*(?P<rest>.+?)\s*$", re.IGNORECASE)
COMMENT_PREFIXES = ("#", "//", ";")


def is_http_url(source: str) -> bool:
    return source.startswith('http://') or source.startswith('https://')


def fetch_source_text(source: str,
                      prefer_local: bool,
                      retries: int,
                      timeout: int,
                      backoff: float) -> Tuple[Optional[str], Optional[str]]:
    """Fetch text from http(s) URL or read from local filesystem if not a URL.

    If prefer_local is True and source is a URL, and a local file exists with the same
    basename as the URL path (e.g., adultraplus.module), prefer the local file.
    Returns (text, error_message).
    """
    if is_http_url(source):
        if prefer_local:
            try:
                parsed = urlparse(source)
                basename = os.path.basename(parsed.path)
            except Exception:
                basename = ''
            if basename:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                candidates = [
                    os.path.join('.', basename),
                    os.path.join(script_dir, '..', basename),
                    os.path.join(script_dir, basename),
                ]
                for local_candidate in candidates:
                    try:
                        if os.path.exists(local_candidate) and os.path.isfile(local_candidate):
                            with open(local_candidate, 'r', encoding='utf-8') as f:
                                return f.read(), None
                    except Exception as e:
                        print(f"Error reading local override {local_candidate}: {e}", file=sys.stderr)
        text, err = fetch_url_with_retries(source, retries=retries, timeout=timeout, backoff=backoff)
        return text, err
    # Treat as local file path (absolute or relative to CWD)
    path = source
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read(), None
    except FileNotFoundError:
        msg = f"Local file not found: {path}"
        print(msg, file=sys.stderr)
        return None, msg
    except Exception as e:
        msg = f"Error reading local file {path}: {e}"
        print(msg, file=sys.stderr)
        return None, msg


def normalize_line(line: str) -> str:
    return line.rstrip('\r\n')


def split_drop_tokens(drop: Optional[str]) -> List[str]:
    if not drop:
        return []
    tokens = re.split(r"[,\s]+", drop)
    return [t for t in (tok.strip() for tok in tokens) if t]


def draw_progress(current: int, total: int, prefix: str = "Progress", width: int = 40) -> None:
    """Draw a simple progress bar on a single line."""
    current = max(0, min(current, total))
    if total <= 0:
        bar = '-' * width
        percent = 0
    else:
        ratio = current / total
        filled = int(width * ratio)
        bar = '#' * filled + '-' * (width - filled)
        percent = int(ratio * 100)
    sys.stdout.write(f"\r{prefix}: [{bar}] {current}/{total} {percent}%")
    sys.stdout.flush()


def parse_and_aggregate(content: str,
                        drop_tokens: List[str],
                        section_order: List[str],
                        non_mitm_lines: Dict[str, List[str]],
                        non_mitm_seen: Set[str],
                        mitm_hosts: List[str],
                        mitm_seen: Set[str]) -> None:
    current_section: Optional[str] = None

    for raw in content.splitlines():
        line = normalize_line(raw).lstrip('\ufeff')
        stripped = line.strip()

        # Skip blank lines and comments globally
        if not stripped or stripped.startswith(COMMENT_PREFIXES):
            continue

        # Section header?
        m_sec = SECTION_HEADER_RE.match(line)
        if m_sec:
            name = m_sec.group('name').strip()
            current_section = name
            if current_section.upper() != 'MITM':
                if current_section not in non_mitm_lines:
                    non_mitm_lines[current_section] = []
                    section_order.append(current_section)
            continue

        # If no section yet, skip content (treat as header metadata)
        if current_section is None:
            continue

        if current_section.upper() == 'MITM':
            # For MITM, only care about hostname lines (ignore drop)
            m_host = MITM_HOSTNAME_RE.match(line)
            if not m_host:
                continue
            rest = m_host.group('rest')
            rest = rest.replace('%APPEND%', '').strip()
            # Split by comma
            for host in [h.strip() for h in rest.split(',')]:
                if not host:
                    continue
                if host not in mitm_seen:
                    mitm_seen.add(host)
                    mitm_hosts.append(host)
            continue

        # Non-MITM sections
        if drop_tokens:
            lower_line = line.lower()
            if any(tok.lower() in lower_line for tok in drop_tokens):
                continue

        if line not in non_mitm_seen:
            non_mitm_seen.add(line)
            non_mitm_lines[current_section].append(line)


def write_merged(output_path: str,
                 section_order: List[str],
                 non_mitm_lines: Dict[str, List[str]],
                 mitm_hosts: List[str],
                 name: Optional[str],
                 desc: Optional[str]) -> None:
    out_lines: List[str] = []

    # Header directives
    if name:
        out_lines.append(f"#!name={name}")
    if desc:
        out_lines.append(f"#!desc={desc}")
    if out_lines:
        out_lines.append('')  # blank line after header

    # Emit sections in first-seen order
    for sec in section_order:
        lines = non_mitm_lines.get(sec)
        if not lines:
            continue
        out_lines.append(f'[{sec}]')
        out_lines.extend(lines)
        out_lines.append('')

    # Emit MITM last, single hostname line
    if mitm_hosts:
        out_lines.append('[MITM]')
        out_lines.append(f"hostname = %APPEND% {', '.join(mitm_hosts)}")
        out_lines.append('')

    while out_lines and out_lines[-1] == '':
        out_lines.pop()

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(out_lines) + "\n")


def aggregate(rule_path: str,
              output_path: str,
              name: Optional[str],
              desc: Optional[str],
              prefer_local: bool = False,
              retries: int = 2,
              timeout: int = 30,
              backoff: float = 1.5) -> Tuple[int, int, int]:
    rules = parse_rule_yaml(rule_path)
    if not rules:
        raise SystemExit('No valid rules found in rule.yml')

    # If not provided via CLI, try to read from YAML
    if not name or not desc:
        yaml_name, yaml_desc = parse_meta_yaml(rule_path)
        name = name or yaml_name or 'Aggregated Module'
        desc = desc or yaml_desc or 'Auto-generated by aggregate.py'

    section_order: List[str] = []
    non_mitm_lines: Dict[str, List[str]] = {}
    non_mitm_seen: Set[str] = set()
    mitm_hosts: List[str] = []
    mitm_seen: Set[str] = set()

    fetched = 0
    total = len(rules)
    draw_progress(0, total, prefix="Downloading")
    failures: List[Tuple[int, str, str]] = []  # (index, url, error)
    for idx, rule in enumerate(rules, start=1):
        url = rule['url']
        drop_tokens = split_drop_tokens(rule.get('drop'))
        print(f"\n[{idx}/{total}] Downloading: {url}")
        text, err = fetch_source_text(url, prefer_local=prefer_local, retries=retries, timeout=timeout, backoff=backoff)
        if text is None:
            print(f"  -> skip (download failed){' - ' + err if err else ''}", file=sys.stderr)
            failures.append((idx, url, err or 'unknown error'))
            draw_progress(idx, total, prefix="Downloading")
            continue
        fetched += 1
        parse_and_aggregate(text, drop_tokens, section_order, non_mitm_lines, non_mitm_seen, mitm_hosts, mitm_seen)
        draw_progress(idx, total, prefix="Downloading")

    # Finish the progress line with newline
    print()
    write_merged(output_path, section_order, non_mitm_lines, mitm_hosts, name, desc)

    total_non_mitm = sum(len(v) for v in non_mitm_lines.values())
    total_mitm = len(mitm_hosts)
    # Summary of failures
    if failures:
        print("Failed sources:")
        for idx, url, msg in failures:
            print(f"  [{idx}] {url} -> {msg}")
    return fetched, total_non_mitm, total_mitm


def main() -> None:
    parser = argparse.ArgumentParser(description='Shadowrocket module aggregator')
    parser.add_argument('-i', '--input', default='rule.yml', help='Path to rule.yml (default: rule.yml)')
    parser.add_argument('-o', '--output', default='merged.sgmodule', help='Output path (default: merged.sgmodule)')
    parser.add_argument('--name', default=None, help='Module display name for header (#!name=...)')
    parser.add_argument('--desc', default=None, help='Module description for header (#!desc=...)')
    parser.add_argument('--prefer-local', action='store_true', help='Prefer local file with same basename over HTTP URL')
    parser.add_argument('--retries', type=int, default=2, help='Retry times for fetching URLs (default: 2)')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds per request (default: 30)')
    parser.add_argument('--backoff', type=float, default=1.5, help='Exponential backoff base between retries (default: 1.5)')
    args = parser.parse_args()

    try:
        fetched, non_mitm_count, mitm_count = aggregate(
            args.input,
            args.output,
            args.name,
            args.desc,
            prefer_local=bool(args.prefer_local),
            retries=int(args.retries),
            timeout=int(args.timeout),
            backoff=float(args.backoff),
        )
        print(f"Done. fetched={fetched}, lines(non-MITM)={non_mitm_count}, hostnames(MITM)={mitm_count}")
        print(f"Output: {os.path.abspath(args.output)}")
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
