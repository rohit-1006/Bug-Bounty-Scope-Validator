#!/usr/bin/env python3
import argparse
import concurrent.futures
import copy
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import sqlite3
import sys
import tempfile
import time
import traceback
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    yaml = None
    HAS_YAML = False


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.1.0"
DB_SCHEMA_VERSION = 3
DB_DIR = Path.home() / ".scope_checker"
DB_PATH = DB_DIR / "scopes.db"
LOG_PATH = DB_DIR / "scope_checker.log"
CONFIG_PATH = DB_DIR / "config.yaml"
BACKUP_DIR = DB_DIR / "backups"

HACKERONE_API_BASE = "<https://api.hackerone.com/v1>"
BUGCROWD_API_BASE = "<https://api.bugcrowd.com>"

SCOPE_STALE_DAYS = 30
MAX_BATCH_WORKERS = 10
API_RATE_LIMIT_DELAY = 1.0
MAX_DOMAIN_LENGTH = 253
MAX_URL_LENGTH = 8192
MAX_ASSET_LENGTH = 8192
MAX_PROGRAM_NAME_LENGTH = 128
MAX_INSTRUCTION_LENGTH = 2000
MAX_BACKUPS = 10

VALID_ASSET_TYPES = frozenset([
    "domain", "wildcard", "ip_range", "cidr", "url",
    "port", "ipv6", "ipv6_cidr", "other",
])

COLORS = {
    "green": "\\033[92m", "red": "\\033[91m", "yellow": "\\033[93m",
    "cyan": "\\033[96m", "bold": "\\033[1m", "reset": "\\033[0m",
    "dim": "\\033[2m", "magenta": "\\033[95m", "white": "\\033[97m",
}

SAMPLE_SCOPE_YAML = """# scope_checker scope definition
# Docs: python scope_checker.py --help
program: my-program
platform: custom

in_scope:
  - "*.example.com"
  - asset: api.example.com
    eligible_for_bounty: true
    max_severity: critical
    instruction: "All API endpoints"
  - asset: "10.0.0.0/24"
  - asset: "2001:db8::/32"

out_of_scope:
  - admin.example.com
  - asset: "*.staging.example.com"
    reason: "Test environment — no bounties"
  - asset: "<https://example.com/health>"
    reason: "Health check endpoint"

ports:
  - 80
  - 443
  - 8080-8090
"""


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> logging.Logger:
    log = logging.getLogger("scope_checker")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.DEBUG if verbose else logging.WARNING)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    log.addHandler(ch)
    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(str(log_file), encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(funcName)s: %(message)s"))
            log.addHandler(fh)
        except (PermissionError, OSError):
            pass
    return log


logger = setup_logging()


def _handle_sigint(signum, frame):
    print("\\nInterrupted.", file=sys.stderr)
    sys.exit(130)


def _handle_sigpipe(signum, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)
if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, _handle_sigpipe)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG MANAGER — credentials never leak to ps aux
# ═══════════════════════════════════════════════════════════════════════════════

class ConfigManager:
    def __init__(self, path: Path = CONFIG_PATH):
        self.path = path
        self._data: dict = {}
        self._load()

    def _load(self):
        if not self.path.exists():
            self._data = {}
            return
        try:
            with open(self.path, "r") as f:
                raw = f.read()
            if HAS_YAML:
                self._data = yaml.safe_load(raw) or {}
            else:
                self._data = json.loads(raw) if raw.strip() else {}
        except Exception:
            self._data = {}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if HAS_YAML:
            with open(self.path, "w") as f:
                yaml.dump(self._data, f, default_flow_style=False, sort_keys=False)
        else:
            with open(self.path, "w") as f:
                json.dump(self._data, f, indent=2)
        os.chmod(str(self.path), 0o600)

    def get(self, key: str, default: str = "") -> str:
        parts = key.split(".")
        node = self._data
        for p in parts:
            if isinstance(node, dict) and p in node:
                node = node[p]
            else:
                return default
        return str(node) if node is not None else default

    def set(self, key: str, value: str):
        parts = key.split(".")
        node = self._data
        for p in parts[:-1]:
            if p not in node or not isinstance(node[p], dict):
                node[p] = {}
            node = node[p]
        node[parts[-1]] = value

    def get_hackerone_user(self) -> str:
        return self.get("hackerone.api_user") or os.environ.get("HACKERONE_API_USER", "")

    def get_hackerone_token(self) -> str:
        return self.get("hackerone.api_token") or os.environ.get("HACKERONE_API_TOKEN", "")

    def get_bugcrowd_token(self) -> str:
        return self.get("bugcrowd.api_token") or os.environ.get("BUGCROWD_API_TOKEN", "")

    def setup_interactive(self):
        print("\\n=== scope_checker configuration ===\\n")
        print(f"Config file: {self.path}")
        print("Credentials stored with 0600 permissions.\\n")
        h1_user = input("HackerOne API username (enter to skip): ").strip()
        if h1_user:
            self.set("hackerone.api_user", h1_user)
            h1_token = input("HackerOne API token: ").strip()
            if h1_token:
                self.set("hackerone.api_token", h1_token)
        bc_token = input("Bugcrowd API token (enter to skip): ").strip()
        if bc_token:
            self.set("bugcrowd.api_token", bc_token)
        self.save()
        print(f"\\n✓ Config saved to {self.path}\\n")


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class ScopeType(Enum):
    IN_SCOPE = "in"
    OUT_OF_SCOPE = "out"


@dataclass
class ScopeEntry:
    asset: str
    asset_type: str
    scope_type: ScopeType
    instruction: str = ""
    eligible_for_bounty: bool = True
    max_severity: str = "critical"

    def __post_init__(self):
        self.asset = self.asset.strip()
        if self.asset_type not in VALID_ASSET_TYPES:
            self.asset_type = "other"
        self.instruction = self.instruction or ""
        self.max_severity = self.max_severity or "critical"

    def to_dict(self) -> dict:
        return {
            "asset": self.asset, "asset_type": self.asset_type,
            "scope_type": self.scope_type.value, "instruction": self.instruction,
            "eligible_for_bounty": self.eligible_for_bounty,
            "max_severity": self.max_severity,
        }

    def key(self) -> str:
        return f"{self.scope_type.value}:{self.asset.lower()}"


@dataclass
class ProgramScope:
    program_name: str
    platform: str
    in_scope: List[ScopeEntry] = field(default_factory=list)
    out_of_scope: List[ScopeEntry] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def all_entries(self) -> List[ScopeEntry]:
        return self.in_scope + self.out_of_scope

    def is_stale(self, days: int = SCOPE_STALE_DAYS) -> bool:
        if not self.updated_at:
            return True
        try:
            updated = datetime.fromisoformat(
                self.updated_at.replace("Z", "").replace("+00:00", "")
            )
            return (datetime.utcnow() - updated) > timedelta(days=days)
        except (ValueError, TypeError):
            return True


@dataclass
class CheckResult:
    target: str
    in_scope: bool
    matched_rule: Optional[str] = None
    match_type: str = ""
    reason: str = ""
    eligible_for_bounty: bool = False

    def to_dict(self) -> dict:
        return {
            "target": self.target, "in_scope": self.in_scope,
            "matched_rule": self.matched_rule, "match_type": self.match_type,
            "reason": self.reason, "eligible_for_bounty": self.eligible_for_bounty,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SCOPE DIFF ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScopeDiff:
    added_in: List[ScopeEntry] = field(default_factory=list)
    removed_in: List[ScopeEntry] = field(default_factory=list)
    added_out: List[ScopeEntry] = field(default_factory=list)
    removed_out: List[ScopeEntry] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added_in or self.removed_in or self.added_out or self.removed_out)

    @property
    def total_changes(self) -> int:
        return len(self.added_in) + len(self.removed_in) + len(self.added_out) + len(self.removed_out)

    @staticmethod
    def compare(old: Optional[ProgramScope], new: ProgramScope) -> "ScopeDiff":
        diff = ScopeDiff()
        if old is None:
            diff.added_in = list(new.in_scope)
            diff.added_out = list(new.out_of_scope)
            return diff
        old_in_keys = {e.asset.lower() for e in old.in_scope}
        new_in_keys = {e.asset.lower() for e in new.in_scope}
        old_out_keys = {e.asset.lower() for e in old.out_of_scope}
        new_out_keys = {e.asset.lower() for e in new.out_of_scope}
        old_in_map = {e.asset.lower(): e for e in old.in_scope}
        new_in_map = {e.asset.lower(): e for e in new.in_scope}
        old_out_map = {e.asset.lower(): e for e in old.out_of_scope}
        new_out_map = {e.asset.lower(): e for e in new.out_of_scope}
        for k in new_in_keys - old_in_keys:
            diff.added_in.append(new_in_map[k])
        for k in old_in_keys - new_in_keys:
            diff.removed_in.append(old_in_map[k])
        for k in new_out_keys - old_out_keys:
            diff.added_out.append(new_out_map[k])
        for k in old_out_keys - new_out_keys:
            diff.removed_out.append(old_out_map[k])
        return diff

    def to_dict(self) -> dict:
        return {
            "added_in_scope": [e.to_dict() for e in self.added_in],
            "removed_in_scope": [e.to_dict() for e in self.removed_in],
            "added_out_of_scope": [e.to_dict() for e in self.added_out],
            "removed_out_of_scope": [e.to_dict() for e in self.removed_out],
            "total_changes": self.total_changes,
        }


def print_diff(diff: ScopeDiff):
    if not diff.has_changes:
        _safe_print(colorize("No scope changes detected.", "dim"))
        return
    _safe_print(colorize(f"\\n  {diff.total_changes} change(s) detected:\\n", "bold"))
    for e in diff.added_in:
        _safe_print(colorize(f"  + [IN]  {e.asset} ({e.asset_type})", "green"))
    for e in diff.removed_in:
        _safe_print(colorize(f"  - [IN]  {e.asset} ({e.asset_type})", "red"))
    for e in diff.added_out:
        _safe_print(colorize(f"  + [OUT] {e.asset} ({e.asset_type})", "yellow"))
    for e in diff.removed_out:
        _safe_print(colorize(f"  - [OUT] {e.asset} ({e.asset_type})", "magenta"))
    _safe_print()


# ═══════════════════════════════════════════════════════════════════════════════
# INPUT SANITIZATION (with IDN/punycode)
# ═══════════════════════════════════════════════════════════════════════════════

class InputSanitizer:
    @staticmethod
    def sanitize_domain(domain: str) -> str:
        if not domain:
            return ""
        domain = domain.strip().lower()
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
        domain = domain.rstrip(".")
        domain = domain.replace("\\x00", "")
        # IDN/punycode: try to encode then decode for normalization
        try:
            domain = domain.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            domain = re.sub(r"[^\\x20-\\x7e]", "", domain)
        domain = domain.strip()
        if len(domain) > MAX_DOMAIN_LENGTH:
            return ""
        return domain

    @staticmethod
    def sanitize_url(url: str) -> str:
        if not url:
            return ""
        url = url.strip().replace("\\x00", "")
        return "" if len(url) > MAX_URL_LENGTH else url

    @staticmethod
    def sanitize_asset(asset: str) -> str:
        if not asset:
            return ""
        asset = asset.strip().replace("\\x00", "")
        return "" if len(asset) > MAX_ASSET_LENGTH else asset

    @staticmethod
    def sanitize_program_name(name: str) -> str:
        if not name:
            return ""
        name = re.sub(r"[^a-zA-Z0-9_\\-\\.]", "_", name.strip())
        return name[:MAX_PROGRAM_NAME_LENGTH].lower()


# ═══════════════════════════════════════════════════════════════════════════════
# ASSET TYPE DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

_RE_CIDR4 = re.compile(r"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$")
_RE_IP4 = re.compile(r"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
_RE_IPRANGE = re.compile(
    r"^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\s*-\\s*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"
)
_RE_DOMAIN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?"
    r"(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*"
    r"\\.[a-zA-Z]{2,63}$"
)
_RE_PORT = re.compile(r"^\\d{1,5}(-\\d{1,5})?$")


def detect_asset_type(asset: str) -> str:
    s = asset.strip()
    if not s:
        return "other"
    if ":" in s and not s.startswith("http"):
        raw = s.split("/")[0]
        try:
            ipaddress.IPv6Address(raw)
            return "ipv6_cidr" if "/" in s else "ipv6"
        except (ipaddress.AddressValueError, ValueError):
            pass
        try:
            ipaddress.IPv6Network(s, strict=False)
            return "ipv6_cidr"
        except (ipaddress.AddressValueError, ValueError):
            pass
    if _RE_CIDR4.match(s):
        try:
            ipaddress.IPv4Network(s, strict=False)
            return "cidr"
        except (ipaddress.AddressValueError, ValueError):
            pass
    if _RE_IP4.match(s):
        try:
            ipaddress.IPv4Address(s)
            return "ip_range"
        except (ipaddress.AddressValueError, ValueError):
            pass
    if _RE_IPRANGE.match(s):
        return "ip_range"
    if s.startswith("*.") or s.startswith("."):
        return "wildcard"
    if re.match(r"^https?://", s, re.IGNORECASE):
        return "url"
    if _RE_DOMAIN.match(s):
        return "domain"
    if _RE_PORT.match(s):
        parts = s.split("-")
        try:
            if all(0 <= int(p) <= 65535 for p in parts):
                return "port"
        except ValueError:
            pass
    return "other"


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

class ScopeDatabase:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._init_tables()
        self._run_migrations()

    def _init_tables(self):
        c = self.conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                platform TEXT DEFAULT 'custom',
                notes TEXT DEFAULT '',
                wildcard_strict INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now')),
                updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS scope_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL,
                asset TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                scope_type TEXT NOT NULL,
                instruction TEXT DEFAULT '',
                eligible_for_bounty INTEGER DEFAULT 1,
                max_severity TEXT DEFAULT 'critical',
                added_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now')),
                FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_se_prog ON scope_entries(program_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_se_asset ON scope_entries(asset)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_se_type ON scope_entries(scope_type)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_prog_name ON programs(name)")
        cur = c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        if cur is None:
            c.execute("INSERT INTO schema_version VALUES (?)", (DB_SCHEMA_VERSION,))
        self.conn.commit()

    def _run_migrations(self):
        c = self.conn.cursor()
        cur = c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] or 1
        if cur < 2:
            for sql in [
                "ALTER TABLE programs ADD COLUMN notes TEXT DEFAULT ''",
                "ALTER TABLE scope_entries ADD COLUMN added_at TEXT DEFAULT ''",
            ]:
                try:
                    c.execute(sql)
                except sqlite3.OperationalError:
                    pass
            c.execute("INSERT OR REPLACE INTO schema_version VALUES (2)")
            self.conn.commit()
        if cur < 3:
            try:
                c.execute("ALTER TABLE programs ADD COLUMN wildcard_strict INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            c.execute("INSERT OR REPLACE INTO schema_version VALUES (3)")
            self.conn.commit()

    def backup(self) -> Optional[Path]:
        if not self.db_path.exists():
            return None
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        dest = BACKUP_DIR / f"scopes_{ts}.db"
        shutil.copy2(str(self.db_path), str(dest))
        # prune old backups
        backups = sorted(BACKUP_DIR.glob("scopes_*.db"), key=lambda p: p.stat().st_mtime)
        while len(backups) > MAX_BACKUPS:
            backups.pop(0).unlink()
        logger.info("Backup created: %s", dest)
        return dest

    def save_program(self, scope: ProgramScope, wildcard_strict: bool = False) -> int:
        c = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        name = InputSanitizer.sanitize_program_name(scope.program_name)
        if not name:
            raise ValueError("Empty program name after sanitization")
        c.execute("""
            INSERT INTO programs (name, platform, wildcard_strict, created_at, updated_at)
            VALUES (?,?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET
                platform=excluded.platform,
                wildcard_strict=excluded.wildcard_strict,
                updated_at=excluded.updated_at
        """, (name, scope.platform, int(wildcard_strict), now, now))
        pid = c.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone()["id"]
        c.execute("DELETE FROM scope_entries WHERE program_id=?", (pid,))
        for entry in scope.all_entries():
            asset = InputSanitizer.sanitize_asset(entry.asset)
            if not asset:
                continue
            c.execute("""
                INSERT INTO scope_entries
                (program_id,asset,asset_type,scope_type,instruction,eligible_for_bounty,max_severity)
                VALUES (?,?,?,?,?,?,?)
            """, (pid, asset, entry.asset_type, entry.scope_type.value,
                  (entry.instruction or "")[:MAX_INSTRUCTION_LENGTH],
                  int(entry.eligible_for_bounty), entry.max_severity or "critical"))
        self.conn.commit()
        return pid

    def add_entry(self, program_name: str, entry: ScopeEntry) -> bool:
        c = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        name = InputSanitizer.sanitize_program_name(program_name)
        if not name:
            raise ValueError("Empty program name")
        c.execute("""
            INSERT INTO programs (name, platform, created_at, updated_at)
            VALUES (?,'custom',?,?)
            ON CONFLICT(name) DO UPDATE SET updated_at=excluded.updated_at
        """, (name, now, now))
        pid = c.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone()["id"]
        dup = c.execute(
            "SELECT id FROM scope_entries WHERE program_id=? AND asset=? AND scope_type=?",
            (pid, entry.asset, entry.scope_type.value),
        ).fetchone()
        if dup:
            return False
        c.execute("""
            INSERT INTO scope_entries
            (program_id,asset,asset_type,scope_type,instruction,eligible_for_bounty,max_severity)
            VALUES (?,?,?,?,?,?,?)
        """, (pid, entry.asset, entry.asset_type, entry.scope_type.value,
              (entry.instruction or "")[:MAX_INSTRUCTION_LENGTH],
              int(entry.eligible_for_bounty), entry.max_severity or "critical"))
        self.conn.commit()
        return True

    def remove_entry(self, program_name: str, asset: str) -> bool:
        c = self.conn.cursor()
        name = InputSanitizer.sanitize_program_name(program_name)
        prog = c.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone()
        if not prog:
            return False
        res = c.execute("DELETE FROM scope_entries WHERE program_id=? AND asset=?", (prog["id"], asset))
        self.conn.commit()
        return res.rowcount > 0

    def load_program(self, program_name: str) -> Optional[ProgramScope]:
        c = self.conn.cursor()
        name = InputSanitizer.sanitize_program_name(program_name)
        prog = c.execute("SELECT * FROM programs WHERE name=?", (name,)).fetchone()
        if not prog:
            return None
        rows = c.execute(
            "SELECT * FROM scope_entries WHERE program_id=? ORDER BY scope_type,asset",
            (prog["id"],),
        ).fetchall()
        scope = ProgramScope(
            program_name=prog["name"], platform=prog["platform"],
            created_at=prog["created_at"] or "", updated_at=prog["updated_at"] or "",
        )
        for r in rows:
            se = ScopeEntry(
                asset=r["asset"], asset_type=r["asset_type"],
                scope_type=ScopeType(r["scope_type"]),
                instruction=r["instruction"] or "",
                eligible_for_bounty=bool(r["eligible_for_bounty"]),
                max_severity=r["max_severity"] or "critical",
            )
            (scope.in_scope if se.scope_type == ScopeType.IN_SCOPE else scope.out_of_scope).append(se)
        return scope

    def get_wildcard_strict(self, program_name: str) -> bool:
        c = self.conn.cursor()
        name = InputSanitizer.sanitize_program_name(program_name)
        row = c.execute("SELECT wildcard_strict FROM programs WHERE name=?", (name,)).fetchone()
        return bool(row["wildcard_strict"]) if row else False

    def set_wildcard_strict(self, program_name: str, strict: bool):
        c = self.conn.cursor()
        name = InputSanitizer.sanitize_program_name(program_name)
        c.execute("UPDATE programs SET wildcard_strict=? WHERE name=?", (int(strict), name))
        self.conn.commit()

    def list_programs(self) -> List[dict]:
        return [dict(r) for r in self.conn.execute("""
            SELECT p.name, p.platform, p.updated_at, p.wildcard_strict,
                   COUNT(CASE WHEN s.scope_type='in' THEN 1 END) AS in_count,
                   COUNT(CASE WHEN s.scope_type='out' THEN 1 END) AS out_count
            FROM programs p LEFT JOIN scope_entries s ON p.id=s.program_id
            GROUP BY p.id ORDER BY p.updated_at DESC
        """).fetchall()]

    def search_programs(self, query: str) -> List[dict]:
        return [dict(r) for r in self.conn.execute("""
            SELECT p.name, p.platform, p.updated_at,
                   COUNT(CASE WHEN s.scope_type='in' THEN 1 END) AS in_count,
                   COUNT(CASE WHEN s.scope_type='out' THEN 1 END) AS out_count
            FROM programs p LEFT JOIN scope_entries s ON p.id=s.program_id
            WHERE p.name LIKE ? GROUP BY p.id ORDER BY p.updated_at DESC
        """, (f"%{query}%",)).fetchall()]

    def delete_program(self, program_name: str) -> bool:
        c = self.conn.cursor()
        name = InputSanitizer.sanitize_program_name(program_name)
        prog = c.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone()
        if not prog:
            return False
        c.execute("DELETE FROM scope_entries WHERE program_id=?", (prog["id"],))
        c.execute("DELETE FROM programs WHERE id=?", (prog["id"],))
        self.conn.commit()
        return True

    def get_stats(self) -> dict:
        c = self.conn.cursor()
        return {
            "programs": c.execute("SELECT COUNT(*) FROM programs").fetchone()[0],
            "total_entries": c.execute("SELECT COUNT(*) FROM scope_entries").fetchone()[0],
            "in_scope_entries": c.execute("SELECT COUNT(*) FROM scope_entries WHERE scope_type='in'").fetchone()[0],
            "out_of_scope_entries": c.execute("SELECT COUNT(*) FROM scope_entries WHERE scope_type='out'").fetchone()[0],
            "db_path": str(self.db_path),
            "db_size_bytes": self.db_path.stat().st_size if self.db_path.exists() else 0,
            "schema_version": c.execute("SELECT MAX(version) FROM schema_version").fetchone()[0],
        }

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# PARSERS
# ═══════════════════════════════════════════════════════════════════════════════

class HackerOneParser:
    @staticmethod
    def fetch_scope(program_handle: str, api_user: str = "", api_token: str = "") -> ProgramScope:
        if not HAS_REQUESTS:
            raise ImportError("pip install requests")
        if not api_user or not api_token:
            raise ValueError(
                "HackerOne credentials required.\\n"
                "  Run: python scope_checker.py --config\\n"
                "  Or:  export HACKERONE_API_USER=... HACKERONE_API_TOKEN=..."
            )
        url = f"{HACKERONE_API_BASE}/hackers/programs/{program_handle}"
        try:
            resp = requests.get(url, auth=(api_user, api_token),
                                headers={"Accept": "application/json"}, timeout=30)
        except requests.exceptions.ConnectionError as e:
            raise ValueError(f"Cannot connect to HackerOne: {e}") from e
        except requests.exceptions.Timeout as e:
            raise ValueError("HackerOne API timed out") from e
        if resp.status_code == 401:
            raise ValueError("Invalid HackerOne credentials (401)")
        if resp.status_code == 404:
            raise ValueError(f"Program not found: {program_handle}")
        if resp.status_code == 429:
            raise ValueError("Rate-limited — wait and retry")
        resp.raise_for_status()
        data = resp.json()
        rels = data.get("data", data).get("relationships", data.get("relationships", {}))
        scope = ProgramScope(program_name=program_handle, platform="hackerone")
        for item in rels.get("structured_scopes", {}).get("data", []):
            attrs = item.get("attributes", {})
            ident = (attrs.get("asset_identifier") or "").strip()
            if not ident:
                continue
            raw_type = (attrs.get("asset_type") or "OTHER").upper()
            eligible = bool(attrs.get("eligible_for_bounty", False))
            submittable = bool(attrs.get("eligible_for_submission", True))
            instruction = (attrs.get("instruction") or "")[:MAX_INSTRUCTION_LENGTH]
            max_sev = attrs.get("max_severity_rating") or "critical"
            atype = detect_asset_type(ident)
            if raw_type == "URL":
                atype = "url"
            elif raw_type == "CIDR":
                atype = "cidr"
            is_in = submittable
            entry = ScopeEntry(asset=ident, asset_type=atype,
                               scope_type=ScopeType.IN_SCOPE if is_in else ScopeType.OUT_OF_SCOPE,
                               instruction=instruction, eligible_for_bounty=eligible,
                               max_severity=max_sev)
            (scope.in_scope if is_in else scope.out_of_scope).append(entry)
        return scope


class BugcrowdParser:
    @staticmethod
    def fetch_scope(program_slug: str, api_token: str = "") -> ProgramScope:
        if not HAS_REQUESTS:
            raise ImportError("pip install requests")
        if not api_token:
            raise ValueError(
                "Bugcrowd token required.\\n"
                "  Run: python scope_checker.py --config\\n"
                "  Or:  export BUGCROWD_API_TOKEN=..."
            )
        headers = {"Accept": "application/vnd.bugcrowd.v4+json",
                    "Authorization": f"Token {api_token}"}
        url = f"{BUGCROWD_API_BASE}/programs/{program_slug}"
        try:
            resp = requests.get(url, headers=headers, timeout=30)
        except requests.exceptions.ConnectionError as e:
            raise ValueError(f"Cannot connect to Bugcrowd: {e}") from e
        except requests.exceptions.Timeout as e:
            raise ValueError("Bugcrowd API timed out") from e
        if resp.status_code == 401:
            raise ValueError("Invalid Bugcrowd token (401)")
        if resp.status_code == 404:
            raise ValueError(f"Program not found: {program_slug}")
        if resp.status_code == 429:
            raise ValueError("Rate-limited — wait and retry")
        resp.raise_for_status()
        data = resp.json()
        scope = ProgramScope(program_name=program_slug, platform="bugcrowd")
        tg = data.get("data", {}).get("relationships", {}).get("target_groups", {}).get("data", [])
        for group in tg:
            gid = group.get("id", "")
            if not gid:
                continue
            time.sleep(API_RATE_LIMIT_DELAY)
            try:
                tr = requests.get(f"{BUGCROWD_API_BASE}/target_groups/{gid}/targets",
                                  headers=headers, timeout=30)
                if tr.status_code != 200:
                    continue
            except requests.exceptions.RequestException:
                continue
            for tgt in tr.json().get("data", []):
                ta = tgt.get("attributes", {})
                asset = (ta.get("uri") or ta.get("name") or "").strip()
                if not asset:
                    continue
                in_flag = bool(ta.get("in_scope", True))
                entry = ScopeEntry(asset=asset, asset_type=detect_asset_type(asset),
                                   scope_type=ScopeType.IN_SCOPE if in_flag else ScopeType.OUT_OF_SCOPE,
                                   instruction=(ta.get("description") or "")[:MAX_INSTRUCTION_LENGTH])
                (scope.in_scope if in_flag else scope.out_of_scope).append(entry)
        return scope


class YAMLParser:
    @staticmethod
    def parse_file(filepath: str) -> ProgramScope:
        if not HAS_YAML:
            raise ImportError("pip install pyyaml")
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as fh:
            try:
                data = yaml.safe_load(fh)
            except yaml.YAMLError as e:
                raise ValueError(f"Bad YAML: {e}") from e
        if not isinstance(data, dict):
            raise ValueError("YAML root must be a mapping")
        name = str(data.get("program", data.get("name", Path(filepath).stem)))
        scope = ProgramScope(program_name=name, platform=str(data.get("platform", "custom")))
        for item in data.get("in_scope", []):
            if isinstance(item, str):
                a, inst, elig, sev = item, "", True, "critical"
            elif isinstance(item, dict):
                a = str(item.get("asset", item.get("target", item.get("domain", ""))))
                inst = str(item.get("instruction", item.get("note", "")))
                elig = bool(item.get("eligible_for_bounty", item.get("bounty", True)))
                sev = str(item.get("max_severity", "critical"))
            else:
                continue
            if a:
                scope.in_scope.append(ScopeEntry(asset=a, asset_type=detect_asset_type(a),
                                                  scope_type=ScopeType.IN_SCOPE, instruction=inst,
                                                  eligible_for_bounty=elig, max_severity=sev))
        for item in data.get("out_of_scope", data.get("out_scope", [])):
            if isinstance(item, str):
                a, inst = item, ""
            elif isinstance(item, dict):
                a = str(item.get("asset", item.get("target", item.get("domain", ""))))
                inst = str(item.get("instruction", item.get("note", item.get("reason", ""))))
            else:
                continue
            if a:
                scope.out_of_scope.append(ScopeEntry(asset=a, asset_type=detect_asset_type(a),
                                                      scope_type=ScopeType.OUT_OF_SCOPE,
                                                      instruction=inst, eligible_for_bounty=False))
        for ci in data.get("ip_ranges", data.get("cidrs", [])):
            if isinstance(ci, str):
                scope.in_scope.append(ScopeEntry(asset=ci, asset_type="cidr", scope_type=ScopeType.IN_SCOPE))
            elif isinstance(ci, dict):
                val = str(ci.get("range", ci.get("cidr", "")))
                if val:
                    excl = bool(ci.get("exclude", False))
                    st = ScopeType.OUT_OF_SCOPE if excl else ScopeType.IN_SCOPE
                    (scope.out_of_scope if excl else scope.in_scope).append(
                        ScopeEntry(asset=val, asset_type="cidr", scope_type=st))
        for ps in data.get("ports", []):
            scope.in_scope.append(ScopeEntry(asset=str(ps), asset_type="port", scope_type=ScopeType.IN_SCOPE))
        return scope


class JSONParser:
    @staticmethod
    def parse_file(filepath: str) -> ProgramScope:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Not found: {filepath}")
        with open(filepath, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as e:
                raise ValueError(f"Bad JSON: {e}") from e
        if not isinstance(data, dict):
            raise ValueError("JSON root must be an object")
        name = str(data.get("program", data.get("name", Path(filepath).stem)))
        scope = ProgramScope(program_name=name, platform=str(data.get("platform", "custom")))
        for item in data.get("in_scope", []):
            a = item if isinstance(item, str) else str(item.get("asset", item.get("target", "")))
            inst = "" if isinstance(item, str) else str(item.get("instruction", ""))
            elig = True if isinstance(item, str) else bool(item.get("eligible_for_bounty", True))
            if a:
                scope.in_scope.append(ScopeEntry(asset=a, asset_type=detect_asset_type(a),
                                                  scope_type=ScopeType.IN_SCOPE, instruction=inst,
                                                  eligible_for_bounty=elig))
        for item in data.get("out_of_scope", []):
            a = item if isinstance(item, str) else str(item.get("asset", item.get("target", "")))
            inst = "" if isinstance(item, str) else str(item.get("instruction", ""))
            if a:
                scope.out_of_scope.append(ScopeEntry(asset=a, asset_type=detect_asset_type(a),
                                                      scope_type=ScopeType.OUT_OF_SCOPE, instruction=inst,
                                                      eligible_for_bounty=False))
        return scope


class TextParser:
    IN_MARKERS = ("in-scope:", "in_scope:", "in scope:", "[in-scope]", "[in_scope]",
                  "[in scope]", "## in scope", "## in-scope", "### in scope")
    OUT_MARKERS = ("out-of-scope:", "out_of_scope:", "out of scope:", "[out-of-scope]",
                   "[out_of_scope]", "[out of scope]", "## out of scope", "## out-of-scope",
                   "### out of scope", "exclusions:", "excluded:")

    @staticmethod
    def parse_file(filepath: str, program_name: str = "") -> ProgramScope:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Not found: {filepath}")
        if not program_name:
            program_name = Path(filepath).stem
        scope = ProgramScope(program_name=program_name, platform="custom")
        section = "in"
        with open(filepath, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                if line.startswith("#") or line.startswith("//"):
                    low = line.lower()
                    if "out" in low and "scope" in low:
                        section = "out"
                    elif "in" in low and "scope" in low:
                        section = "in"
                    continue
                low = line.lower()
                if low in TextParser.IN_MARKERS or any(low.startswith(m) for m in TextParser.IN_MARKERS):
                    section = "in"
                    continue
                if low in TextParser.OUT_MARKERS or any(low.startswith(m) for m in TextParser.OUT_MARKERS):
                    section = "out"
                    continue
                asset = line.lstrip("-•*> \\t").split()[0].strip(",;") if line.lstrip("-•*> \\t").split() else ""
                if not asset or len(asset) < 3:
                    continue
                st = ScopeType.IN_SCOPE if section == "in" else ScopeType.OUT_OF_SCOPE
                entry = ScopeEntry(asset=asset, asset_type=detect_asset_type(asset), scope_type=st)
                (scope.in_scope if st == ScopeType.IN_SCOPE else scope.out_of_scope).append(entry)
        return scope


# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATOR ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ScopeValidator:
    def __init__(self, scope: ProgramScope, wildcard_strict: bool = False):
        self.scope = scope
        self.wildcard_strict = wildcard_strict
        self._in_domains: List[str] = []
        self._in_wildcards: List[str] = []
        self._in_cidrs: List[ipaddress.IPv4Network] = []
        self._in_ipv6_cidrs: List[ipaddress.IPv6Network] = []
        self._in_ips: List[ipaddress.IPv4Address] = []
        self._in_ipv6s: List[ipaddress.IPv6Address] = []
        self._in_ip_ranges: List[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
        self._in_urls: List[str] = []
        self._in_ports: List[Tuple[int, int]] = []
        self._out_domains: List[str] = []
        self._out_wildcards: List[str] = []
        self._out_cidrs: List[ipaddress.IPv4Network] = []
        self._out_ipv6_cidrs: List[ipaddress.IPv6Network] = []
        self._out_ips: List[ipaddress.IPv4Address] = []
        self._out_ipv6s: List[ipaddress.IPv6Address] = []
        self._out_urls: List[str] = []
        self._bounty: Dict[str, bool] = {}
        self._compile()

    def _compile(self):
        for e in self.scope.in_scope:
            self._bounty[e.asset.lower()] = e.eligible_for_bounty
            self._classify(e, True)
        for e in self.scope.out_of_scope:
            self._classify(e, False)

    def _classify(self, entry: ScopeEntry, is_in: bool):
        a = entry.asset.strip().lower()
        t = entry.asset_type
        if t == "wildcard" or a.startswith("*.") or a.startswith("."):
            cleaned = a.lstrip("*").lstrip(".")
            (self._in_wildcards if is_in else self._out_wildcards).append(cleaned)
        elif t == "cidr":
            try:
                n = ipaddress.IPv4Network(a, strict=False)
                (self._in_cidrs if is_in else self._out_cidrs).append(n)
            except (ipaddress.AddressValueError, ValueError):
                pass
        elif t in ("ipv6", "ipv6_cidr"):
            if "/" in a:
                try:
                    n = ipaddress.IPv6Network(a, strict=False)
                    (self._in_ipv6_cidrs if is_in else self._out_ipv6_cidrs).append(n)
                except (ipaddress.AddressValueError, ValueError):
                    pass
            else:
                try:
                    addr = ipaddress.IPv6Address(a)
                    (self._in_ipv6s if is_in else self._out_ipv6s).append(addr)
                except (ipaddress.AddressValueError, ValueError):
                    pass
        elif t == "ip_range":
            if "-" in a and "/" not in a:
                halves = a.split("-", 1)
                try:
                    s = ipaddress.IPv4Address(halves[0].strip())
                    e = ipaddress.IPv4Address(halves[1].strip())
                    if int(s) > int(e):
                        s, e = e, s
                    if is_in:
                        self._in_ip_ranges.append((s, e))
                except (ipaddress.AddressValueError, ValueError):
                    pass
            else:
                try:
                    ip = ipaddress.IPv4Address(a)
                    (self._in_ips if is_in else self._out_ips).append(ip)
                except (ipaddress.AddressValueError, ValueError):
                    pass
        elif t == "url":
            (self._in_urls if is_in else self._out_urls).append(a)
        elif t == "port" and is_in:
            if "-" in a:
                parts = a.split("-", 1)
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                    if lo > hi:
                        lo, hi = hi, lo
                    if 0 <= lo <= 65535 and 0 <= hi <= 65535:
                        self._in_ports.append((lo, hi))
                except ValueError:
                    pass
            else:
                try:
                    p = int(a)
                    if 0 <= p <= 65535:
                        self._in_ports.append((p, p))
                except ValueError:
                    pass
        elif t == "domain":
            (self._in_domains if is_in else self._out_domains).append(a)
        else:
            (self._in_domains if is_in else self._out_domains).append(a)

    def _wc_matches(self, domain: str, wc: str) -> bool:
        if self.wildcard_strict:
            return domain.endswith("." + wc) and domain != wc
        return domain == wc or domain.endswith("." + wc)

    def check_domain(self, domain: str) -> CheckResult:
        domain = InputSanitizer.sanitize_domain(domain)
        if not domain:
            return CheckResult(target=domain, in_scope=False, reason="Empty/invalid domain")
        for od in self._out_domains:
            if domain == od:
                return CheckResult(target=domain, in_scope=False, matched_rule=od,
                                   match_type="exact_exclusion",
                                   reason=f"Explicitly excluded: {od}")
        for ow in self._out_wildcards:
            if self._wc_matches(domain, ow):
                rule = f"*.{ow}"
                return CheckResult(target=domain, in_scope=False, matched_rule=rule,
                                   match_type="wildcard_exclusion",
                                   reason=f"Excluded by wildcard: {rule}")
        for ind in self._in_domains:
            if domain == ind:
                return CheckResult(target=domain, in_scope=True, matched_rule=ind,
                                   match_type="exact_match",
                                   reason=f"Exact match: {ind}",
                                   eligible_for_bounty=self._bounty.get(ind, False))
        for iw in self._in_wildcards:
            if self._wc_matches(domain, iw):
                rule = f"*.{iw}"
                return CheckResult(target=domain, in_scope=True, matched_rule=rule,
                                   match_type="wildcard_match",
                                   reason=f"Matched wildcard: {rule}",
                                   eligible_for_bounty=self._bounty.get(rule, self._bounty.get(f".{iw}", False)))
        return CheckResult(target=domain, in_scope=False, reason="No matching rule")

    def check_ip(self, ip_str: str) -> CheckResult:
        ip_str = ip_str.strip()
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return self._check_v4(ip_str, ip)
        except (ipaddress.AddressValueError, ValueError):
            pass
        try:
            ip = ipaddress.IPv6Address(ip_str)
            return self._check_v6(ip_str, ip)
        except (ipaddress.AddressValueError, ValueError):
            return CheckResult(target=ip_str, in_scope=False, reason=f"Invalid IP: {ip_str}")

    def _check_v4(self, ip_str: str, ip: ipaddress.IPv4Address) -> CheckResult:
        for oc in self._out_cidrs:
            if ip in oc:
                return CheckResult(target=ip_str, in_scope=False, matched_rule=str(oc),
                                   match_type="cidr_exclusion", reason=f"Excluded CIDR: {oc}")
        for oip in self._out_ips:
            if ip == oip:
                return CheckResult(target=ip_str, in_scope=False, matched_rule=str(oip),
                                   match_type="ip_exclusion", reason=f"Excluded IP: {oip}")
        for ic in self._in_cidrs:
            if ip in ic:
                return CheckResult(target=ip_str, in_scope=True, matched_rule=str(ic),
                                   match_type="cidr_match", reason=f"In CIDR: {ic}",
                                   eligible_for_bounty=self._bounty.get(str(ic), False))
        for iip in self._in_ips:
            if ip == iip:
                return CheckResult(target=ip_str, in_scope=True, matched_rule=str(iip),
                                   match_type="ip_match", reason=f"Exact IP: {iip}",
                                   eligible_for_bounty=self._bounty.get(str(iip), False))
        for s, e in self._in_ip_ranges:
            if int(s) <= int(ip) <= int(e):
                rule = f"{s}-{e}"
                return CheckResult(target=ip_str, in_scope=True, matched_rule=rule,
                                   match_type="ip_range_match", reason=f"In range: {rule}")
        return CheckResult(target=ip_str, in_scope=False, reason="No matching IP rule")

    def _check_v6(self, ip_str: str, ip: ipaddress.IPv6Address) -> CheckResult:
        for oc in self._out_ipv6_cidrs:
            if ip in oc:
                return CheckResult(target=ip_str, in_scope=False, matched_rule=str(oc),
                                   match_type="ipv6_cidr_exclusion", reason=f"Excluded IPv6 CIDR: {oc}")
        for oip in self._out_ipv6s:
            if ip == oip:
                return CheckResult(target=ip_str, in_scope=False, matched_rule=str(oip),
                                   match_type="ipv6_exclusion", reason=f"Excluded IPv6: {oip}")
        for ic in self._in_ipv6_cidrs:
            if ip in ic:
                return CheckResult(target=ip_str, in_scope=True, matched_rule=str(ic),
                                   match_type="ipv6_cidr_match", reason=f"In IPv6 CIDR: {ic}",
                                   eligible_for_bounty=self._bounty.get(str(ic), False))
        for iip in self._in_ipv6s:
            if ip == iip:
                return CheckResult(target=ip_str, in_scope=True, matched_rule=str(iip),
                                   match_type="ipv6_match", reason=f"Exact IPv6: {iip}")
        return CheckResult(target=ip_str, in_scope=False, reason="No matching IPv6 rule")

    def check_url(self, url: str) -> CheckResult:
        clean = InputSanitizer.sanitize_url(url)
        if not clean:
            return CheckResult(target=url, in_scope=False, reason="Invalid URL")
        low = clean.lower()
        try:
            parsed = urllib.parse.urlparse(low if "://" in low else f"https://{low}")
        except Exception:
            return CheckResult(target=url, in_scope=False, reason="Cannot parse URL")
        hostname = parsed.hostname or ""
        port = parsed.port
        path = parsed.path or "/"
        for ou in self._out_urls:
            try:
                op = urllib.parse.urlparse(ou if "://" in ou else f"https://{ou}")
                if hostname == (op.hostname or "") and path.startswith(op.path or "/"):
                    return CheckResult(target=url, in_scope=False, matched_rule=ou,
                                       match_type="url_exclusion", reason=f"Excluded URL: {ou}")
            except Exception:
                continue
        dom_r = self.check_domain(hostname)
        if not dom_r.in_scope:
            ip_r = self.check_ip(hostname)
            if ip_r.in_scope:
                if port is not None and self._in_ports:
                    pr = self.check_port(port)
                    if not pr.in_scope:
                        return CheckResult(target=url, in_scope=False,
                                           reason=f"IP in scope but port {port} excluded")
                return CheckResult(target=url, in_scope=True, matched_rule=ip_r.matched_rule,
                                   match_type="ip_url_match",
                                   reason=f"Host IP in scope: {ip_r.reason}",
                                   eligible_for_bounty=ip_r.eligible_for_bounty)
            return CheckResult(target=url, in_scope=False,
                               reason=f"Host not in scope: {dom_r.reason}")
        if port is not None and self._in_ports:
            pr = self.check_port(port)
            if not pr.in_scope:
                return CheckResult(target=url, in_scope=False,
                                   reason=f"Host in scope but port {port} excluded")
        for iu in self._in_urls:
            try:
                ip2 = urllib.parse.urlparse(iu if "://" in iu else f"https://{iu}")
                if hostname == (ip2.hostname or "") and path.startswith(ip2.path or "/"):
                    return CheckResult(target=url, in_scope=True, matched_rule=iu,
                                       match_type="url_match", reason=f"Matched URL: {iu}",
                                       eligible_for_bounty=self._bounty.get(iu, dom_r.eligible_for_bounty))
            except Exception:
                continue
        return CheckResult(target=url, in_scope=True, matched_rule=dom_r.matched_rule,
                           match_type="domain_url_match",
                           reason=f"Host in scope: {dom_r.reason}",
                           eligible_for_bounty=dom_r.eligible_for_bounty)

    def check_port(self, port: int) -> CheckResult:
        if not self._in_ports:
            return CheckResult(target=str(port), in_scope=True, reason="No port restrictions")
        if not (0 <= port <= 65535):
            return CheckResult(target=str(port), in_scope=False, reason=f"Invalid port: {port}")
        for lo, hi in self._in_ports:
            if lo <= port <= hi:
                rule = str(lo) if lo == hi else f"{lo}-{hi}"
                return CheckResult(target=str(port), in_scope=True, matched_rule=rule,
                                   match_type="port_match", reason=f"Port in range: {rule}")
        return CheckResult(target=str(port), in_scope=False,
                           reason=f"Port {port} not in allowed ranges")

    def check_target(self, target: str) -> CheckResult:
        target = target.strip()
        if not target:
            return CheckResult(target="", in_scope=False, reason="Empty target")
        if re.match(r"^https?://", target, re.IGNORECASE):
            return self.check_url(target)
        for try_fn in (
            lambda: (ipaddress.IPv4Address(target), self.check_ip(target)),
            lambda: (ipaddress.IPv6Address(target), self.check_ip(target)),
        ):
            try:
                _, result = try_fn()
                return result
            except (ipaddress.AddressValueError, ValueError):
                pass
        if ":" in target and not target.startswith("["):
            halves = target.rsplit(":", 1)
            if len(halves) == 2:
                try:
                    pnum = int(halves[1])
                    if 0 <= pnum <= 65535:
                        dr = self.check_domain(halves[0])
                        if not dr.in_scope:
                            return CheckResult(target=target, in_scope=False,
                                               reason=f"Host not in scope: {dr.reason}")
                        pr = self.check_port(pnum)
                        if pr.in_scope:
                            return CheckResult(target=target, in_scope=True,
                                               matched_rule=dr.matched_rule,
                                               match_type="host_port_match",
                                               reason="Host and port in scope",
                                               eligible_for_bounty=dr.eligible_for_bounty)
                        return CheckResult(target=target, in_scope=False,
                                           reason=f"Port {pnum} out of scope")
                except ValueError:
                    pass
        return self.check_domain(target)

    def check_batch(self, targets: List[str], workers: int = 4) -> List[CheckResult]:
        workers = max(1, min(workers, MAX_BATCH_WORKERS, len(targets)))
        results: List[CheckResult] = []
        order = {t: i for i, t in enumerate(targets)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            fmap = {pool.submit(self.check_target, t): t for t in targets}
            for fut in concurrent.futures.as_completed(fmap):
                try:
                    results.append(fut.result(timeout=10))
                except Exception as exc:
                    results.append(CheckResult(target=fmap[fut], in_scope=False, reason=f"Error: {exc}"))
        results.sort(key=lambda r: order.get(r.target, len(targets)))
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

def colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def _safe_print(*a, **kw):
    try:
        print(*a, **kw)
    except BrokenPipeError:
        sys.exit(0)


def print_result(result: CheckResult, verbose: bool = False):
    if result.in_scope:
        s = colorize("[IN SCOPE]", "green")
        b = colorize(" 💰", "yellow") if result.eligible_for_bounty else ""
    else:
        s = colorize("[OUT OF SCOPE]", "red")
        b = ""
    _safe_print(f"{s} {result.target}{b}")
    if verbose:
        if result.matched_rule:
            _safe_print(f"  Rule:   {result.matched_rule}")
        if result.match_type:
            _safe_print(f"  Type:   {result.match_type}")
        _safe_print(f"  Reason: {result.reason}\\n")


def print_scope(scope: ProgramScope):
    _safe_print(f"\\nProgram: {colorize(scope.program_name, 'bold')} ({scope.platform})")
    _safe_print("=" * 60)
    if scope.updated_at:
        _safe_print(f"Updated: {scope.updated_at}")
    if scope.is_stale():
        _safe_print(colorize(f"⚠  Stale (>{SCOPE_STALE_DAYS}d). Refresh with --update.", "yellow"))
    _safe_print(colorize(f"\\nIN SCOPE ({len(scope.in_scope)}):", "green"))
    _safe_print("-" * 50)
    for e in scope.in_scope:
        b = " 💰" if e.eligible_for_bounty else ""
        sv = f" [{e.max_severity}]" if e.max_severity != "critical" else ""
        _safe_print(f"  {colorize(e.asset, 'cyan')} ({e.asset_type}){b}{sv}")
        if e.instruction:
            _safe_print(f"    {colorize(e.instruction[:120], 'dim')}")
    _safe_print(colorize(f"\\nOUT OF SCOPE ({len(scope.out_of_scope)}):", "red"))
    _safe_print("-" * 50)
    for e in scope.out_of_scope:
        _safe_print(f"  {colorize(e.asset, 'yellow')} ({e.asset_type})")
        if e.instruction:
            _safe_print(f"    {colorize(e.instruction[:120], 'dim')}")
    _safe_print()


def print_programs(programs: List[dict]):
    if not programs:
        _safe_print("No programs stored.")
        return
    _safe_print(f"\\n{'Program':<32} {'Platform':<12} {'In':>4} {'Out':>4}  Updated")
    _safe_print("-" * 78)
    for p in programs:
        _safe_print(f"{p['name']:<32} {p['platform']:<12} {p['in_count']:>4} {p['out_count']:>4}  {p['updated_at']}")
    _safe_print(f"\\n{len(programs)} program(s)\\n")


def export_yaml(scope: ProgramScope, path: str):
    if not HAS_YAML:
        raise ImportError("pip install pyyaml")
    with open(path, "w") as f:
        yaml.dump({"program": scope.program_name, "platform": scope.platform,
                    "in_scope": [e.to_dict() for e in scope.in_scope],
                    "out_of_scope": [e.to_dict() for e in scope.out_of_scope]},
                   f, default_flow_style=False, sort_keys=False)
    _safe_print(f"Exported to {path}")


def export_json(scope: ProgramScope, path: str):
    with open(path, "w") as f:
        json.dump({"program": scope.program_name, "platform": scope.platform,
                    "in_scope": [e.to_dict() for e in scope.in_scope],
                    "out_of_scope": [e.to_dict() for e in scope.out_of_scope]}, f, indent=2)
    _safe_print(f"Exported to {path}")


def export_txt(scope: ProgramScope, path: str):
    with open(path, "w") as f:
        for e in scope.in_scope:
            f.write(e.asset + "\\n")
    _safe_print(f"Exported {len(scope.in_scope)} assets to {path}")


# ═══════════════════════════════════════════════════════════════════════════════
# SELF-TEST (120+ assertions)
# ═══════════════════════════════════════════════════════════════════════════════

class SelfTest:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors: List[str] = []
        self._sec = ""

    def eq(self, n: str, a: Any, e: Any):
        ok = a == e
        self.passed += ok
        self.failed += (not ok)
        if not ok:
            self.errors.append(f"  FAIL [{self._sec}] {n}: expected {e!r}, got {a!r}")

    def true(self, n: str, v: bool):
        self.eq(n, v, True)

    def false(self, n: str, v: bool):
        self.eq(n, v, False)

    def _fixture(self) -> ProgramScope:
        s = ProgramScope(program_name="test_fixture", platform="test")
        s.in_scope = [
            ScopeEntry("*.example.com", "wildcard", ScopeType.IN_SCOPE, eligible_for_bounty=True),
            ScopeEntry("specific.target.com", "domain", ScopeType.IN_SCOPE, eligible_for_bounty=True),
            ScopeEntry("no.bounty.com", "domain", ScopeType.IN_SCOPE, eligible_for_bounty=False),
            ScopeEntry("192.168.1.0/24", "cidr", ScopeType.IN_SCOPE),
            ScopeEntry("10.0.0.1", "ip_range", ScopeType.IN_SCOPE),
            ScopeEntry("10.0.0.50-10.0.0.100", "ip_range", ScopeType.IN_SCOPE),
            ScopeEntry("172.16.0.1-172.16.0.10", "ip_range", ScopeType.IN_SCOPE),
            ScopeEntry("<https://api.example.com/v1>", "url", ScopeType.IN_SCOPE, eligible_for_bounty=True),
            ScopeEntry("80", "port", ScopeType.IN_SCOPE),
            ScopeEntry("443", "port", ScopeType.IN_SCOPE),
            ScopeEntry("8080-8090", "port", ScopeType.IN_SCOPE),
            ScopeEntry("2001:db8::/32", "ipv6_cidr", ScopeType.IN_SCOPE),
            ScopeEntry("fd00::1", "ipv6", ScopeType.IN_SCOPE),
        ]
        s.out_of_scope = [
            ScopeEntry("admin.example.com", "domain", ScopeType.OUT_OF_SCOPE),
            ScopeEntry("*.staging.example.com", "wildcard", ScopeType.OUT_OF_SCOPE),
            ScopeEntry("*.dev.internal.example.com", "wildcard", ScopeType.OUT_OF_SCOPE),
            ScopeEntry("192.168.1.1", "ip_range", ScopeType.OUT_OF_SCOPE),
            ScopeEntry("10.99.0.0/16", "cidr", ScopeType.OUT_OF_SCOPE),
            ScopeEntry("<https://api.example.com/v1/health>", "url", ScopeType.OUT_OF_SCOPE),
            ScopeEntry("2001:db8:dead::/48", "ipv6_cidr", ScopeType.OUT_OF_SCOPE),
            ScopeEntry("fd00::99", "ipv6", ScopeType.OUT_OF_SCOPE),
        ]
        return s

    def run_all(self) -> bool:
        _safe_print(colorize("\\n══════════ SCOPE CHECKER v2.1 SELF-TEST ══════════\\n", "bold"))
        self.test_asset_detection()
        self.test_sanitizer()
        self.test_domain_exact()
        self.test_domain_nomatch()
        self.test_wildcard()
        self.test_wildcard_deep()
        self.test_wildcard_apex_default()
        self.test_wildcard_apex_strict()
        self.test_exclusion_over_wildcard()
        self.test_wildcard_exclusion()
        self.test_nested_wc_exclusion()
        self.test_non_excluded_ok()
        self.test_ipv4_exact()
        self.test_ipv4_cidr()
        self.test_ipv4_cidr_exclusion()
        self.test_ipv4_excluded_in_cidr()
        self.test_ipv4_range()
        self.test_ipv4_range_bounds()
        self.test_ipv4_range_outside()
        self.test_ipv4_invalid()
        self.test_ipv6_cidr()
        self.test_ipv6_cidr_exclusion()
        self.test_ipv6_exact()
        self.test_ipv6_excluded()
        self.test_ipv6_nomatch()
        self.test_url_in()
        self.test_url_excluded_host()
        self.test_url_path_exclusion()
        self.test_url_path_match()
        self.test_url_ip_host()
        self.test_url_port()
        self.test_port_match()
        self.test_port_range()
        self.test_port_outside()
        self.test_port_no_restrict()
        self.test_port_invalid()
        self.test_host_port_in()
        self.test_host_port_port_out()
        self.test_host_port_host_out()
        self.test_autodetect()
        self.test_empty_whitespace()
        self.test_case_insensitive()
        self.test_trailing_dot()
        self.test_empty_scope()
        self.test_batch()
        self.test_bounty()
        self.test_url_query_fragment()
        self.test_multi_ip_ranges()
        self.test_diff_engine()
        self.test_diff_no_change()
        self.test_diff_from_none()
        self.test_db_roundtrip()
        self.test_db_duplicate()
        self.test_db_remove()
        self.test_db_delete()
        self.test_db_search()
        self.test_db_stats()
        self.test_db_wildcard_strict_flag()
        self.test_db_backup()
        self.test_yaml_parser()
        self.test_json_parser()
        self.test_text_parser()
        self.test_staleness()
        self.test_entry_validation()
        self.test_config_manager()
        self.test_idn_domain()
        _safe_print()
        for e in self.errors:
            _safe_print(colorize(e, "red"))
        if self.errors:
            _safe_print()
        total = self.passed + self.failed
        if self.failed == 0:
            _safe_print(colorize(f"✓ ALL {total} TESTS PASSED\\n", "green"))
        else:
            _safe_print(colorize(f"✗ {self.failed}/{total} FAILED\\n", "red"))
        return self.failed == 0

    def test_asset_detection(self):
        self._sec = "detect"
        self.eq("domain", detect_asset_type("example.com"), "domain")
        self.eq("sub", detect_asset_type("a.b.example.com"), "domain")
        self.eq("wc", detect_asset_type("*.example.com"), "wildcard")
        self.eq("dot_wc", detect_asset_type(".example.com"), "wildcard")
        self.eq("cidr", detect_asset_type("192.168.1.0/24"), "cidr")
        self.eq("ip", detect_asset_type("10.0.0.1"), "ip_range")
        self.eq("ip_range", detect_asset_type("10.0.0.1-10.0.0.255"), "ip_range")
        self.eq("url_http", detect_asset_type("<http://x.com>"), "url")
        self.eq("url_https", detect_asset_type("<https://x.com/api>"), "url")
        self.eq("port", detect_asset_type("443"), "port")
        self.eq("port_range", detect_asset_type("8080-8090"), "port")
        self.eq("ipv6", detect_asset_type("2001:db8::1"), "ipv6")
        self.eq("ipv6_cidr", detect_asset_type("2001:db8::/32"), "ipv6_cidr")
        self.eq("empty", detect_asset_type(""), "other")
        self.eq("garbage", detect_asset_type("!@#$"), "other")

    def test_sanitizer(self):
        self._sec = "sanitize"
        self.eq("lower", InputSanitizer.sanitize_domain("EXAMPLE.COM"), "example.com")
        self.eq("strip_proto", InputSanitizer.sanitize_domain("<https://x.com/p>"), "x.com")
        self.eq("strip_port", InputSanitizer.sanitize_domain("x.com:8080"), "x.com")
        self.eq("strip_query", InputSanitizer.sanitize_domain("x.com?a=1"), "x.com")
        self.eq("trail_dot", InputSanitizer.sanitize_domain("x.com."), "x.com")
        self.eq("null", InputSanitizer.sanitize_domain("x\\x00.com"), "x.com")
        self.eq("empty", InputSanitizer.sanitize_domain(""), "")
        self.eq("prog_special", InputSanitizer.sanitize_program_name("a b!@#"), "a_b___")
        self.eq("prog_long", len(InputSanitizer.sanitize_program_name("a" * 200)), MAX_PROGRAM_NAME_LENGTH)

    def test_domain_exact(self):
        self._sec = "dom_exact"
        v = ScopeValidator(self._fixture())
        r = v.check_domain("specific.target.com")
        self.true("in", r.in_scope)
        self.eq("type", r.match_type, "exact_match")

    def test_domain_nomatch(self):
        self._sec = "dom_no"
        self.false("out", ScopeValidator(self._fixture()).check_domain("random.org").in_scope)

    def test_wildcard(self):
        self._sec = "wc"
        r = ScopeValidator(self._fixture()).check_domain("dev.example.com")
        self.true("in", r.in_scope)
        self.eq("type", r.match_type, "wildcard_match")

    def test_wildcard_deep(self):
        self._sec = "wc_deep"
        self.true("deep", ScopeValidator(self._fixture()).check_domain("a.b.c.example.com").in_scope)

    def test_wildcard_apex_default(self):
        self._sec = "wc_apex_default"
        v = ScopeValidator(self._fixture(), wildcard_strict=False)
        self.true("apex matches default", v.check_domain("example.com").in_scope)

    def test_wildcard_apex_strict(self):
        self._sec = "wc_apex_strict"
        v = ScopeValidator(self._fixture(), wildcard_strict=True)
        self.false("apex blocked strict", v.check_domain("example.com").in_scope)
        self.true("sub still ok", v.check_domain("dev.example.com").in_scope)

    def test_exclusion_over_wildcard(self):
        self._sec = "excl_wc"
        r = ScopeValidator(self._fixture()).check_domain("admin.example.com")
        self.false("excluded", r.in_scope)
        self.eq("type", r.match_type, "exact_exclusion")

    def test_wildcard_exclusion(self):
        self._sec = "wc_excl"
        v = ScopeValidator(self._fixture())
        self.false("staging sub", v.check_domain("test.staging.example.com").in_scope)
        self.false("staging itself", v.check_domain("staging.example.com").in_scope)

    def test_nested_wc_exclusion(self):
        self._sec = "nested_wc"
        v = ScopeValidator(self._fixture())
        self.false("nested", v.check_domain("foo.dev.internal.example.com").in_scope)
        self.false("deep nested", v.check_domain("a.b.dev.internal.example.com").in_scope)

    def test_non_excluded_ok(self):
        self._sec = "non_excl"
        self.true("shop ok", ScopeValidator(self._fixture()).check_domain("shop.example.com").in_scope)

    def test_ipv4_exact(self):
        self._sec = "ipv4_ex"
        v = ScopeValidator(self._fixture())
        self.true("match", v.check_ip("10.0.0.1").in_scope)
        self.false("no match", v.check_ip("10.0.0.2").in_scope)

    def test_ipv4_cidr(self):
        self._sec = "ipv4_cidr"
        v = ScopeValidator(self._fixture())
        self.true("in", v.check_ip("192.168.1.50").in_scope)
        self.false("out", v.check_ip("192.168.2.1").in_scope)

    def test_ipv4_cidr_exclusion(self):
        self._sec = "ipv4_cidr_x"
        r = ScopeValidator(self._fixture()).check_ip("10.99.5.5")
        self.false("excluded", r.in_scope)
        self.eq("type", r.match_type, "cidr_exclusion")

    def test_ipv4_excluded_in_cidr(self):
        self._sec = "ipv4_x_in_cidr"
        r = ScopeValidator(self._fixture()).check_ip("192.168.1.1")
        self.false("excluded", r.in_scope)
        self.eq("type", r.match_type, "ip_exclusion")

    def test_ipv4_range(self):
        self._sec = "ipv4_rng"
        r = ScopeValidator(self._fixture()).check_ip("10.0.0.75")
        self.true("mid", r.in_scope)
        self.eq("type", r.match_type, "ip_range_match")

    def test_ipv4_range_bounds(self):
        self._sec = "ipv4_rng_b"
        v = ScopeValidator(self._fixture())
        self.true("start", v.check_ip("10.0.0.50").in_scope)
        self.true("end", v.check_ip("10.0.0.100").in_scope)
        self.true("r2_start", v.check_ip("172.16.0.1").in_scope)
        self.true("r2_end", v.check_ip("172.16.0.10").in_scope)

    def test_ipv4_range_outside(self):
        self._sec = "ipv4_rng_out"
        v = ScopeValidator(self._fixture())
        self.false("before", v.check_ip("10.0.0.49").in_scope)
        self.false("after", v.check_ip("10.0.0.101").in_scope)

    def test_ipv4_invalid(self):
        self._sec = "ipv4_inv"
        r = ScopeValidator(self._fixture()).check_ip("garbage")
        self.false("invalid", r.in_scope)

    def test_ipv6_cidr(self):
        self._sec = "ipv6_c"
        r = ScopeValidator(self._fixture()).check_ip("2001:db8::1")
        self.true("in", r.in_scope)
        self.eq("type", r.match_type, "ipv6_cidr_match")

    def test_ipv6_cidr_exclusion(self):
        self._sec = "ipv6_cx"
        r = ScopeValidator(self._fixture()).check_ip("2001:db8:dead::1")
        self.false("excluded", r.in_scope)

    def test_ipv6_exact(self):
        self._sec = "ipv6_e"
        self.true("match", ScopeValidator(self._fixture()).check_ip("fd00::1").in_scope)

    def test_ipv6_excluded(self):
        self._sec = "ipv6_x"
        self.false("excl", ScopeValidator(self._fixture()).check_ip("fd00::99").in_scope)

    def test_ipv6_nomatch(self):
        self._sec = "ipv6_no"
        self.false("no", ScopeValidator(self._fixture()).check_ip("2001:db9::1").in_scope)

    def test_url_in(self):
        self._sec = "url_in"
        self.true("in", ScopeValidator(self._fixture()).check_url("<https://dev.example.com/x>").in_scope)

    def test_url_excluded_host(self):
        self._sec = "url_xh"
        self.false("out", ScopeValidator(self._fixture()).check_url("<https://admin.example.com/x>").in_scope)

    def test_url_path_exclusion(self):
        self._sec = "url_xp"
        r = ScopeValidator(self._fixture()).check_url("<https://api.example.com/v1/health>")
        self.false("path excl", r.in_scope)
        self.eq("type", r.match_type, "url_exclusion")

    def test_url_path_match(self):
        self._sec = "url_pm"
        self.true("path ok", ScopeValidator(self._fixture()).check_url("<https://api.example.com/v1/users>").in_scope)

    def test_url_ip_host(self):
        self._sec = "url_ip"
        v = ScopeValidator(self._fixture())
        self.true("ip in cidr", v.check_url("<http://192.168.1.50:80/x>").in_scope)
        self.false("ip excl cidr", v.check_url("<http://10.99.5.5/x>").in_scope)

    def test_url_port(self):
        self._sec = "url_port"
        v = ScopeValidator(self._fixture())
        self.true("443 ok", v.check_url("<https://dev.example.com:443/x>").in_scope)
        self.false("9999 no", v.check_url("<https://dev.example.com:9999/x>").in_scope)
        self.true("8085 range", v.check_url("<https://dev.example.com:8085/x>").in_scope)

    def test_port_match(self):
        self._sec = "port"
        v = ScopeValidator(self._fixture())
        self.true("80", v.check_port(80).in_scope)
        self.true("443", v.check_port(443).in_scope)

    def test_port_range(self):
        self._sec = "port_rng"
        v = ScopeValidator(self._fixture())
        self.true("8080", v.check_port(8080).in_scope)
        self.true("8085", v.check_port(8085).in_scope)
        self.true("8090", v.check_port(8090).in_scope)

    def test_port_outside(self):
        self._sec = "port_out"
        v = ScopeValidator(self._fixture())
        self.false("22", v.check_port(22).in_scope)
        self.false("8091", v.check_port(8091).in_scope)

    def test_port_no_restrict(self):
        self._sec = "port_nr"
        s = ProgramScope(program_name="np", platform="test")
        s.in_scope = [ScopeEntry("*.x.com", "wildcard", ScopeType.IN_SCOPE)]
        self.true("any", ScopeValidator(s).check_port(12345).in_scope)

    def test_port_invalid(self):
        self._sec = "port_inv"
        v = ScopeValidator(self._fixture())
        self.false("neg", v.check_port(-1).in_scope)
        self.false("high", v.check_port(99999).in_scope)

    def test_host_port_in(self):
        self._sec = "hp_in"
        r = ScopeValidator(self._fixture()).check_target("dev.example.com:443")
        self.true("in", r.in_scope)
        self.eq("type", r.match_type, "host_port_match")

    def test_host_port_port_out(self):
        self._sec = "hp_po"
        self.false("out", ScopeValidator(self._fixture()).check_target("dev.example.com:22").in_scope)

    def test_host_port_host_out(self):
        self._sec = "hp_ho"
        self.false("out", ScopeValidator(self._fixture()).check_target("admin.example.com:443").in_scope)

    def test_autodetect(self):
        self._sec = "auto"
        v = ScopeValidator(self._fixture())
        self.true("domain", v.check_target("dev.example.com").in_scope)
        self.true("url", v.check_target("<https://dev.example.com>").in_scope)
        self.true("ipv4", v.check_target("192.168.1.50").in_scope)
        self.true("ipv6", v.check_target("2001:db8::1").in_scope)

    def test_empty_whitespace(self):
        self._sec = "empty"
        v = ScopeValidator(self._fixture())
        self.false("empty", v.check_target("").in_scope)
        self.false("ws", v.check_target("   ").in_scope)

    def test_case_insensitive(self):
        self._sec = "case"
        v = ScopeValidator(self._fixture())
        self.true("upper", v.check_domain("DEV.EXAMPLE.COM").in_scope)
        self.false("upper excl", v.check_domain("ADMIN.EXAMPLE.COM").in_scope)

    def test_trailing_dot(self):
        self._sec = "trail"
        v = ScopeValidator(self._fixture())
        self.true("in", v.check_domain("dev.example.com.").in_scope)
        self.false("excl", v.check_domain("admin.example.com.").in_scope)

    def test_empty_scope(self):
        self._sec = "empty_s"
        v = ScopeValidator(ProgramScope(program_name="e", platform="t"))
        self.false("dom", v.check_domain("x.com").in_scope)
        self.true("port", v.check_port(80).in_scope)

    def test_batch(self):
        self._sec = "batch"
        v = ScopeValidator(self._fixture())
        results = v.check_batch(["dev.example.com", "admin.example.com", "192.168.1.50", "random.org"], workers=2)
        self.eq("count", len(results), 4)
        rm = {r.target: r.in_scope for r in results}
        self.true("dev", rm.get("dev.example.com", False))
        self.false("admin", rm.get("admin.example.com", True))
        self.true("ip", rm.get("192.168.1.50", False))
        self.false("rand", rm.get("random.org", True))

    def test_bounty(self):
        self._sec = "bounty"
        v = ScopeValidator(self._fixture())
        self.true("specific", v.check_domain("specific.target.com").eligible_for_bounty)
        self.false("no_bounty", v.check_domain("no.bounty.com").eligible_for_bounty)
        self.true("wc", v.check_domain("dev.example.com").eligible_for_bounty)

    def test_url_query_fragment(self):
        self._sec = "url_qf"
        v = ScopeValidator(self._fixture())
        self.true("query", v.check_url("<https://dev.example.com/p?id=1>").in_scope)
        self.true("frag", v.check_url("<https://dev.example.com/p#s>").in_scope)

    def test_multi_ip_ranges(self):
        self._sec = "multi_rng"
        v = ScopeValidator(self._fixture())
        self.true("r1", v.check_ip("10.0.0.60").in_scope)
        self.true("r2", v.check_ip("172.16.0.5").in_scope)
        self.false("gap", v.check_ip("172.16.0.20").in_scope)

    def test_diff_engine(self):
        self._sec = "diff"
        old = self._fixture()
        new = copy.deepcopy(old)
        new.in_scope.append(ScopeEntry("new.example.com", "domain", ScopeType.IN_SCOPE))
        new.in_scope = [e for e in new.in_scope if e.asset != "specific.target.com"]
        new.out_of_scope.append(ScopeEntry("blocked.example.com", "domain", ScopeType.OUT_OF_SCOPE))
        diff = ScopeDiff.compare(old, new)
        self.true("has changes", diff.has_changes)
        self.eq("added_in", len(diff.added_in), 1)
        self.eq("removed_in", len(diff.removed_in), 1)
        self.eq("added_out", len(diff.added_out), 1)
        self.eq("removed_out", len(diff.removed_out), 0)
        self.eq("added_in_asset", diff.added_in[0].asset, "new.example.com")
        self.eq("removed_in_asset", diff.removed_in[0].asset, "specific.target.com")

    def test_diff_no_change(self):
        self._sec = "diff_nc"
        s = self._fixture()
        diff = ScopeDiff.compare(s, copy.deepcopy(s))
        self.false("no changes", diff.has_changes)
        self.eq("total", diff.total_changes, 0)

    def test_diff_from_none(self):
        self._sec = "diff_none"
        s = self._fixture()
        diff = ScopeDiff.compare(None, s)
        self.true("has changes", diff.has_changes)
        self.eq("all in added", len(diff.added_in), len(s.in_scope))
        self.eq("all out added", len(diff.added_out), len(s.out_of_scope))

    def test_db_roundtrip(self):
        self._sec = "db_rt"
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            db = ScopeDatabase(tmp)
            s = self._fixture()
            db.save_program(s)
            loaded = db.load_program("test_fixture")
            self.true("loaded", loaded is not None)
            self.eq("name", loaded.program_name, "test_fixture")
            self.eq("in", len(loaded.in_scope), len(s.in_scope))
            self.eq("out", len(loaded.out_of_scope), len(s.out_of_scope))
            v = ScopeValidator(loaded)
            self.true("works", v.check_domain("dev.example.com").in_scope)
            self.false("excl works", v.check_domain("admin.example.com").in_scope)
            db.close()
        finally:
            tmp.unlink(missing_ok=True)

    def test_db_duplicate(self):
        self._sec = "db_dup"
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            db = ScopeDatabase(tmp)
            e = ScopeEntry("t.com", "domain", ScopeType.IN_SCOPE)
            self.true("first", db.add_entry("dup_test", e))
            self.false("second", db.add_entry("dup_test", e))
            db.close()
        finally:
            tmp.unlink(missing_ok=True)

    def test_db_remove(self):
        self._sec = "db_rm"
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            db = ScopeDatabase(tmp)
            db.add_entry("rm", ScopeEntry("a.com", "domain", ScopeType.IN_SCOPE))
            db.add_entry("rm", ScopeEntry("b.com", "domain", ScopeType.IN_SCOPE))
            self.true("remove", db.remove_entry("rm", "a.com"))
            self.false("remove gone", db.remove_entry("rm", "z.com"))
            self.eq("remaining", len(db.load_program("rm").in_scope), 1)
            db.close()
        finally:
            tmp.unlink(missing_ok=True)

    def test_db_delete(self):
        self._sec = "db_del"
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            db = ScopeDatabase(tmp)
            db.add_entry("d", ScopeEntry("x.com", "domain", ScopeType.IN_SCOPE))
            self.true("del", db.delete_program("d"))
            self.false("del again", db.delete_program("d"))
            self.true("gone", db.load_program("d") is None)
            db.close()
        finally:
            tmp.unlink(missing_ok=True)

    def test_db_search(self):
        self._sec = "db_search"
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            db = ScopeDatabase(tmp)
            db.add_entry("shopify_prod", ScopeEntry("a.com", "domain", ScopeType.IN_SCOPE))
            db.add_entry("google_vrp", ScopeEntry("b.com", "domain", ScopeType.IN_SCOPE))
            db.add_entry("shopify_staging", ScopeEntry("c.com", "domain", ScopeType.IN_SCOPE))
            self.eq("shopify", len(db.search_programs("shopify")), 2)
            self.eq("google", len(db.search_programs("google")), 1)
            self.eq("none", len(db.search_programs("nonexistent")), 0)
            db.close()
        finally:
            tmp.unlink(missing_ok=True)

    def test_db_stats(self):
        self._sec = "db_stats"
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            db = ScopeDatabase(tmp)
            s = self._fixture()
            db.save_program(s)
            stats = db.get_stats()
            self.eq("progs", stats["programs"], 1)
            self.eq("total", stats["total_entries"], len(s.in_scope) + len(s.out_of_scope))
            self.true("size", stats["db_size_bytes"] > 0)
            db.close()
        finally:
            tmp.unlink(missing_ok=True)

    def test_db_wildcard_strict_flag(self):
        self._sec = "db_wcs"
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            db = ScopeDatabase(tmp)
            s = self._fixture()
            db.save_program(s, wildcard_strict=True)
            self.true("strict on", db.get_wildcard_strict("test_fixture"))
            db.set_wildcard_strict("test_fixture", False)
            self.false("strict off", db.get_wildcard_strict("test_fixture"))
            db.close()
        finally:
            tmp.unlink(missing_ok=True)

    def test_db_backup(self):
        self._sec = "db_backup"
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            db = ScopeDatabase(tmp)
            db.add_entry("bk", ScopeEntry("x.com", "domain", ScopeType.IN_SCOPE))
            backup_path = db.backup()
            self.true("backup exists", backup_path is not None and backup_path.exists())
            if backup_path and backup_path.exists():
                backup_path.unlink()
            db.close()
        finally:
            tmp.unlink(missing_ok=True)

    def test_yaml_parser(self):
        self._sec = "yaml"
        if not HAS_YAML:
            self.true("skip", True)
            return
        content = (
            "program: yt\\nplatform: custom\\nin_scope:\\n"
            "  - '*.yt.com'\\n  - asset: api.yt.com\\n    eligible_for_bounty: true\\n"
            "out_of_scope:\\n  - admin.yt.com\\n"
            "ip_ranges:\\n  - '10.10.0.0/16'\\n  - range: '172.20.0.0/16'\\n    exclude: true\\n"
            "ports:\\n  - 443\\n"
        )
        fd, path = tempfile.mkstemp(suffix=".yaml")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            s = YAMLParser.parse_file(path)
            self.eq("name", s.program_name, "yt")
            v = ScopeValidator(s)
            self.true("wc", v.check_domain("dev.yt.com").in_scope)
            self.false("excl", v.check_domain("admin.yt.com").in_scope)
            self.true("cidr", v.check_ip("10.10.5.5").in_scope)
            self.false("excl cidr", v.check_ip("172.20.1.1").in_scope)
        finally:
            os.unlink(path)

    def test_json_parser(self):
        self._sec = "json"
        data = {"program": "jt", "in_scope": ["*.jt.com"], "out_of_scope": ["admin.jt.com"]}
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
            s = JSONParser.parse_file(path)
            self.eq("name", s.program_name, "jt")
            v = ScopeValidator(s)
            self.true("wc", v.check_domain("dev.jt.com").in_scope)
            self.false("excl", v.check_domain("admin.jt.com").in_scope)
        finally:
            os.unlink(path)

    def test_text_parser(self):
        self._sec = "text"
        content = "in-scope:\\n*.tt.com\\napi.tt.com\\nout-of-scope:\\nadmin.tt.com\\n"
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            s = TextParser.parse_file(path, "tt")
            self.true("in", len(s.in_scope) >= 2)
            self.true("out", len(s.out_of_scope) >= 1)
        finally:
            os.unlink(path)

    def test_staleness(self):
        self._sec = "stale"
        s = ProgramScope(program_name="s", platform="t")
        s.updated_at = (datetime.utcnow() - timedelta(days=31)).isoformat()
        self.true("stale", s.is_stale())
        s.updated_at = datetime.utcnow().isoformat()
        self.false("fresh", s.is_stale())
        s.updated_at = ""
        self.true("empty", s.is_stale())
        s.updated_at = "not-a-date"
        self.true("bad", s.is_stale())

    def test_entry_validation(self):
        self._sec = "entry"
        e = ScopeEntry("t.com", "bogus_type", ScopeType.IN_SCOPE)
        self.eq("norm type", e.asset_type, "other")
        e2 = ScopeEntry("  sp.com  ", "domain", ScopeType.IN_SCOPE)
        self.eq("strip", e2.asset, "sp.com")
        e3 = ScopeEntry("t.com", "domain", ScopeType.IN_SCOPE, instruction=None, max_severity=None)
        self.eq("none inst", e3.instruction, "")
        self.eq("none sev", e3.max_severity, "critical")

    def test_config_manager(self):
        self._sec = "config"
        fd, path = tempfile.mkstemp(suffix=".yaml" if HAS_YAML else ".json")
        os.close(fd)
        os.unlink(path)
        try:
            cfg = ConfigManager(Path(path))
            cfg.set("hackerone.api_user", "testuser")
            cfg.set("hackerone.api_token", "testtoken")
            cfg.save()
            cfg2 = ConfigManager(Path(path))
            self.eq("user", cfg2.get("hackerone.api_user"), "testuser")
            self.eq("token", cfg2.get("hackerone.api_token"), "testtoken")
            self.eq("missing", cfg2.get("nonexistent.key", "default"), "default")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_idn_domain(self):
        self._sec = "idn"
        # IDN domains get converted to punycode by sanitizer
        result = InputSanitizer.sanitize_domain("münchen.de")
        # Should either produce xn--mnchen-3ya.de (punycode) or strip non-ascii
        self.true("idn handled", len(result) > 0 and "\\x00" not in result)
        # ASCII domains pass through unchanged
        self.eq("ascii ok", InputSanitizer.sanitize_domain("example.com"), "example.com")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="scope_checker — Production Bug Bounty Scope Validator v2.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --self-test                              # verify everything works
  %(prog)s --config                                 # store API credentials securely
  %(prog)s --init my-scope.yaml                     # create sample scope file
  %(prog)s --import-yaml scope.yaml                 # import scope
  %(prog)s -p myprogram -c dev.example.com          # check target
  %(prog)s -p myprogram --check-file targets.txt    # check file
  subfinder -d x.com | %(prog)s --filter -p prog    # pipe filter
  %(prog)s -p prog --update                         # re-fetch from API
  %(prog)s -p prog --diff                           # show what changed
  %(prog)s -p prog --wildcard-strict                # *.x.com won't match x.com
        """,
    )
    gi = p.add_argument_group("Import")
    gi.add_argument("--import-scope", choices=["hackerone", "bugcrowd"])
    gi.add_argument("--import-yaml", metavar="FILE")
    gi.add_argument("--import-json", metavar="FILE")
    gi.add_argument("--import-txt", metavar="FILE")
    gi.add_argument("--api-user", help=argparse.SUPPRESS)  # hidden — use --config
    gi.add_argument("--api-token", help=argparse.SUPPRESS)

    gm = p.add_argument_group("Manage")
    gm.add_argument("--program", "-p")
    gm.add_argument("--add-in", metavar="ASSET")
    gm.add_argument("--add-out", metavar="ASSET")
    gm.add_argument("--remove-asset", metavar="ASSET")
    gm.add_argument("--delete-program", action="store_true")
    gm.add_argument("--wildcard-strict", action="store_true",
                    help="*.x.com does NOT match x.com itself")
    gm.add_argument("--update", action="store_true", help="Re-fetch scope from API")

    gc = p.add_argument_group("Check")
    gc.add_argument("--check", "-c", metavar="TARGET")
    gc.add_argument("--check-ip", metavar="IP")
    gc.add_argument("--check-url", metavar="URL")
    gc.add_argument("--check-port", metavar="PORT", type=int)
    gc.add_argument("--check-file", metavar="FILE")

    gf = p.add_argument_group("Filter")
    gf.add_argument("--filter", "-f", action="store_true")
    gf.add_argument("--filter-out", action="store_true")

    gd = p.add_argument_group("Display")
    gd.add_argument("--show-scope", "-s", action="store_true")
    gd.add_argument("--list-programs", "-l", action="store_true")
    gd.add_argument("--search", metavar="Q")
    gd.add_argument("--stats", action="store_true")
    gd.add_argument("--diff", action="store_true", help="Show scope changes since last import")
    gd.add_argument("--verbose", "-v", action="store_true")
    gd.add_argument("--json-output", action="store_true")
    gd.add_argument("--quiet", "-q", action="store_true")
    gd.add_argument("--version", action="version", version=f"scope_checker {VERSION}")

    ge = p.add_argument_group("Export")
    ge.add_argument("--export-yaml", metavar="FILE")
    ge.add_argument("--export-json", metavar="FILE")
    ge.add_argument("--export-txt", metavar="FILE")

    gx = p.add_argument_group("Setup")
    gx.add_argument("--self-test", action="store_true")
    gx.add_argument("--config", action="store_true", help="Configure API credentials")
    gx.add_argument("--init", metavar="FILE", help="Create sample scope YAML")
    gx.add_argument("--backup", action="store_true", help="Backup database")

    return p


def _require_program(args):
    if not args.program:
        _safe_print(colorize("Error: --program/-p required", "red"), file=sys.stderr)
        sys.exit(1)


def _load_or_die(db: ScopeDatabase, name: str) -> ProgramScope:
    scope = db.load_program(name)
    if not scope:
        _safe_print(colorize(f"Program not found: {name}", "red"), file=sys.stderr)
        sys.exit(1)
    return scope


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if SelfTest().run_all() else 1)

    if args.init:
        p = Path(args.init)
        if p.exists():
            _safe_print(colorize(f"File exists: {p}", "red"), file=sys.stderr)
            sys.exit(1)
        p.write_text(SAMPLE_SCOPE_YAML)
        _safe_print(colorize(f"✓ Created sample scope: {p}", "green"))
        _safe_print(f"  Edit it, then: python scope_checker.py --import-yaml {p}")
        return

    if args.config:
        ConfigManager().setup_interactive()
        return

    if len(sys.argv) == 1 and sys.stdin.isatty():
        parser.print_help()
        sys.exit(0)

    global logger
    if args.verbose:
        logger = setup_logging(verbose=True, log_file=LOG_PATH)

    cfg = ConfigManager()
    db = ScopeDatabase()

    try:
        if args.backup:
            bp = db.backup()
            _safe_print(colorize(f"✓ Backup: {bp}", "green") if bp else "Nothing to backup.")
            return

        if args.list_programs:
            p = db.list_programs()
            _safe_print(json.dumps(p, indent=2)) if args.json_output else print_programs(p)
            return

        if args.search:
            p = db.search_programs(args.search)
            _safe_print(json.dumps(p, indent=2)) if args.json_output else print_programs(p)
            return

        if args.stats:
            s = db.get_stats()
            if args.json_output:
                _safe_print(json.dumps(s, indent=2))
            else:
                _safe_print(f"\\nDB:      {s['db_path']}")
                _safe_print(f"Schema:  v{s['schema_version']}")
                _safe_print(f"Programs:{s['programs']}  Entries:{s['total_entries']} "
                            f"(in:{s['in_scope_entries']} out:{s['out_of_scope_entries']})")
                _safe_print(f"Size:    {s['db_size_bytes']/1024:.1f}KB\\n")
            return

        # ── IMPORT ──
        if args.import_scope or args.update:
            _require_program(args)
            platform = args.import_scope
            if args.update:
                existing = db.load_program(args.program)
                if not existing:
                    _safe_print(colorize(f"Not found: {args.program}", "red"), file=sys.stderr)
                    sys.exit(1)
                platform = existing.platform
                if platform not in ("hackerone", "bugcrowd"):
                    _safe_print(colorize(f"Cannot update: platform '{platform}' has no API", "red"),
                                file=sys.stderr)
                    sys.exit(1)
            try:
                old_scope = db.load_program(args.program)
                h_user = args.api_user or cfg.get_hackerone_user()
                h_token = args.api_token or cfg.get_hackerone_token()
                b_token = args.api_token or cfg.get_bugcrowd_token()
                if platform == "hackerone":
                    new_scope = HackerOneParser.fetch_scope(args.program, h_user, h_token)
                elif platform == "bugcrowd":
                    new_scope = BugcrowdParser.fetch_scope(args.program, b_token)
                else:
                    _safe_print(colorize(f"Unknown platform: {platform}", "red"), file=sys.stderr)
                    sys.exit(1)
                diff = ScopeDiff.compare(old_scope, new_scope)
                db.backup()
                db.save_program(new_scope, wildcard_strict=args.wildcard_strict)
                _safe_print(colorize(f"✓ {'Updated' if args.update else 'Imported'} {args.program}", "green"))
                _safe_print(f"  In: {len(new_scope.in_scope)}  Out: {len(new_scope.out_of_scope)}")
                print_diff(diff)
            except (ValueError, ImportError) as exc:
                _safe_print(colorize(f"Error: {exc}", "red"), file=sys.stderr)
                sys.exit(1)
            return

        if args.import_yaml or args.import_json or args.import_txt:
            try:
                if args.import_yaml:
                    new_scope = YAMLParser.parse_file(args.import_yaml)
                elif args.import_json:
                    new_scope = JSONParser.parse_file(args.import_json)
                else:
                    new_scope = TextParser.parse_file(args.import_txt, program_name=args.program or "")
                if args.program:
                    new_scope.program_name = args.program
                old_scope = db.load_program(new_scope.program_name)
                diff = ScopeDiff.compare(old_scope, new_scope)
                if old_scope:
                    db.backup()
                db.save_program(new_scope, wildcard_strict=args.wildcard_strict)
                _safe_print(colorize(f"✓ Imported {new_scope.program_name}", "green"))
                _safe_print(f"  In: {len(new_scope.in_scope)}  Out: {len(new_scope.out_of_scope)}")
                print_diff(diff)
            except (FileNotFoundError, ValueError, ImportError) as exc:
                _safe_print(colorize(f"Error: {exc}", "red"), file=sys.stderr)
                sys.exit(1)
            return

        # ── MANAGE ──
        if args.add_in:
            _require_program(args)
            e = ScopeEntry(asset=args.add_in, asset_type=detect_asset_type(args.add_in),
                           scope_type=ScopeType.IN_SCOPE)
            r = db.add_entry(args.program, e)
            _safe_print(colorize(f"✓ Added in-scope: {args.add_in} ({e.asset_type})", "green") if r
                        else colorize(f"⚠ Already exists: {args.add_in}", "yellow"))
            return

        if args.add_out:
            _require_program(args)
            e = ScopeEntry(asset=args.add_out, asset_type=detect_asset_type(args.add_out),
                           scope_type=ScopeType.OUT_OF_SCOPE, eligible_for_bounty=False)
            r = db.add_entry(args.program, e)
            _safe_print(colorize(f"✓ Added out-of-scope: {args.add_out}", "yellow") if r
                        else colorize(f"⚠ Already exists: {args.add_out}", "yellow"))
            return

        if args.remove_asset:
            _require_program(args)
            if db.remove_entry(args.program, args.remove_asset):
                _safe_print(colorize(f"✓ Removed: {args.remove_asset}", "yellow"))
            else:
                _safe_print(colorize(f"Not found: {args.remove_asset}", "red"), file=sys.stderr)
                sys.exit(1)
            return

        if args.wildcard_strict and args.program and not any([
            args.import_scope, args.import_yaml, args.import_json, args.import_txt,
            args.check, args.check_file, args.filter, args.update
        ]):
            db.set_wildcard_strict(args.program, True)
            _safe_print(colorize(f"✓ Wildcard strict mode enabled for {args.program}", "green"))
            return

        if args.delete_program:
            _require_program(args)
            db.backup()
            if db.delete_program(args.program):
                _safe_print(colorize(f"✓ Deleted: {args.program}", "yellow"))
            else:
                _safe_print(colorize(f"Not found: {args.program}", "red"), file=sys.stderr)
                sys.exit(1)
            return

        # ── SHOW / DIFF / EXPORT ──
        if args.show_scope:
            _require_program(args)
            scope = _load_or_die(db, args.program)
            if args.json_output:
                _safe_print(json.dumps({
                    "program": scope.program_name, "platform": scope.platform,
                    "is_stale": scope.is_stale(),
                    "in_scope": [e.to_dict() for e in scope.in_scope],
                    "out_of_scope": [e.to_dict() for e in scope.out_of_scope],
                }, indent=2))
            else:
                print_scope(scope)
            return

        if args.diff:
            _require_program(args)
            _safe_print(colorize("Diff shows changes from last import. Re-import to see new diff.", "dim"))
            return

        if args.export_yaml or args.export_json or args.export_txt:
            _require_program(args)
            scope = _load_or_die(db, args.program)
            if args.export_yaml:
                export_yaml(scope, args.export_yaml)
            if args.export_json:
                export_json(scope, args.export_json)
            if args.export_txt:
                export_txt(scope, args.export_txt)
            return

        # ── CHECK ──
        if args.check or args.check_ip or args.check_url or args.check_port is not None:
            _require_program(args)
            scope = _load_or_die(db, args.program)
            wcs = args.wildcard_strict or db.get_wildcard_strict(args.program)
            if scope.is_stale() and not args.quiet:
                _safe_print(colorize(f"⚠ Stale scope (>{SCOPE_STALE_DAYS}d)", "yellow"), file=sys.stderr)
            v = ScopeValidator(scope, wildcard_strict=wcs)
            if args.check:
                result = v.check_target(args.check)
            elif args.check_ip:
                result = v.check_ip(args.check_ip)
            elif args.check_url:
                result = v.check_url(args.check_url)
            else:
                result = v.check_port(args.check_port)
            if args.quiet:
                sys.exit(0 if result.in_scope else 1)
            _safe_print(json.dumps(result.to_dict(), indent=2)) if args.json_output else print_result(result, args.verbose)
            sys.exit(0 if result.in_scope else 1)

        if args.check_file:
            _require_program(args)
            scope = _load_or_die(db, args.program)
            wcs = args.wildcard_strict or db.get_wildcard_strict(args.program)
            v = ScopeValidator(scope, wildcard_strict=wcs)
            targets = []
            try:
                with open(args.check_file) as fh:
                    targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
            except FileNotFoundError:
                _safe_print(colorize(f"Not found: {args.check_file}", "red"), file=sys.stderr)
                sys.exit(1)
            results = v.check_batch(targets, workers=max(1, min(4, len(targets))))
            ic = sum(1 for r in results if r.in_scope)
            oc = len(results) - ic
            if args.json_output:
                _safe_print(json.dumps({"results": [r.to_dict() for r in results],
                                         "summary": {"in": ic, "out": oc}}, indent=2))
            else:
                for r in results:
                    print_result(r, args.verbose)
                _safe_print(f"\\n{colorize('Summary:', 'bold')} "
                            f"{colorize(str(ic), 'green')} in, {colorize(str(oc), 'red')} out")
            return

        # ── FILTER ──
        if args.filter or args.filter_out or not sys.stdin.isatty():
            _require_program(args)
            scope = _load_or_die(db, args.program)
            wcs = args.wildcard_strict or db.get_wildcard_strict(args.program)
            v = ScopeValidator(scope, wildcard_strict=wcs)
            ic = oc = total = 0
            try:
                for line in sys.stdin:
                    t = line.strip()
                    if not t:
                        continue
                    total += 1
                    r = v.check_target(t)
                    if r.in_scope:
                        ic += 1
                        if not args.filter_out:
                            _safe_print(json.dumps({"target": r.target, "in_scope": True, "rule": r.matched_rule})
                                        if args.json_output else r.target)
                    else:
                        oc += 1
                        if args.filter_out:
                            _safe_print(json.dumps({"target": r.target, "in_scope": False, "reason": r.reason})
                                        if args.json_output else r.target)
            except KeyboardInterrupt:
                pass
            if args.verbose and sys.stderr.isatty():
                print(f"\\n[scope_checker] {total} processed: {ic} in, {oc} out", file=sys.stderr)
            return

        parser.print_help()

    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        print("\\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        _safe_print(colorize(f"Fatal: {exc}", "red"), file=sys.stderr)
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
