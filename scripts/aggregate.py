#!/usr/bin/env python3

import argparse
import sys
import os
import re
import urllib.request
import urllib.error
from typing import List, Dict, Tuple, Optional, Set


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
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/126.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        },
        method='GET'
    )
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


SECTION_HEADER_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
MITM_HOSTNAME_RE = re.compile(r"^\s*hostname\s*=\s*(?P<rest>.+?)\s*$", re.IGNORECASE)
COMMENT_PREFIXES = ("#", "//", ";")


def normalize_line(line: str) -> str:
    return line.rstrip('\r\n')


def split_drop_tokens(drop: Optional[str]) -> List[str]:
    if not drop:
        return []
    tokens = re.split(r"[,\s]+", drop)
    return [t for t in (tok.strip() for tok in tokens) if t]


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


def aggregate(rule_path: str, output_path: str, name: Optional[str], desc: Optional[str]) -> Tuple[int, int, int]:
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
    for idx, rule in enumerate(rules, start=1):
        url = rule['url']
        drop_tokens = split_drop_tokens(rule.get('drop'))
        print(f"[{idx}/{len(rules)}] Downloading: {url}")
        text = fetch_url(url)
        if text is None:
            print(f"  -> skip (download failed)", file=sys.stderr)
            continue
        fetched += 1
        parse_and_aggregate(text, drop_tokens, section_order, non_mitm_lines, non_mitm_seen, mitm_hosts, mitm_seen)

    write_merged(output_path, section_order, non_mitm_lines, mitm_hosts, name, desc)

    total_non_mitm = sum(len(v) for v in non_mitm_lines.values())
    total_mitm = len(mitm_hosts)
    return fetched, total_non_mitm, total_mitm


def main() -> None:
    parser = argparse.ArgumentParser(description='Shadowrocket module aggregator')
    parser.add_argument('-i', '--input', default='rule.yml', help='Path to rule.yml (default: rule.yml)')
    parser.add_argument('-o', '--output', default='merged.sgmodule', help='Output path (default: merged.sgmodule)')
    parser.add_argument('--name', default=None, help='Module display name for header (#!name=...)')
    parser.add_argument('--desc', default=None, help='Module description for header (#!desc=...)')
    args = parser.parse_args()

    try:
        fetched, non_mitm_count, mitm_count = aggregate(args.input, args.output, args.name, args.desc)
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
