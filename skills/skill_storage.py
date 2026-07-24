"""
Skill Storage Module
Production-grade skill persistence and storage

Author: Solidify Security Team
Version: 2.0.0
"""

from __future__ import annotations

import json
import sqlite3
import logging
import hashlib
import shutil
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from datetime import datetime, timedelta
from threading import Lock

from .skill_registry import Skill, SkillResult

logger = logging.getLogger(__name__)


class StorageBackend(Enum):
    MEMORY = "memory"
    FILE = "file"
    SQLITE = "sqlite"


@dataclass
class SkillStorageConfig:
    """Configuration for skill storage"""

    backend: StorageBackend = StorageBackend.MEMORY
    db_path: str = "./data/skills.db"
    file_dir: str = "./data/skills"
    cache_enabled: bool = True
    max_cache_size: int = 1000


@dataclass
class StorageMetrics:
    """Track I/O statistics for storage"""
    reads: int = 0
    writes: int = 0
    deletes: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    db_queries: int = 0
    total_read_bytes: int = 0
    total_write_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reads": self.reads,
            "writes": self.writes,
            "deletes": self.deletes,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "db_queries": self.db_queries,
        }

    def reset(self) -> None:
        self.reads = 0
        self.writes = 0
        self.deletes = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.db_queries = 0
        self.total_read_bytes = 0
        self.total_write_bytes = 0


class StorageIndex:
    """Fast lookup index for storage"""

    def __init__(self) -> None:
        self._by_category: Dict[str, Set[str]] = {}
        self._by_severity: Dict[str, Set[str]] = {}
        self._by_name: Dict[str, str] = {}

    def add(self, skill: Skill) -> None:
        self._by_name[skill.name] = skill.category
        self._by_category.setdefault(skill.category, set()).add(skill.name)
        self._by_severity.setdefault(skill.severity, set()).add(skill.name)

    def remove(self, skill_name: str) -> None:
        category = self._by_name.pop(skill_name, None)
        if category:
            self._by_category.get(category, set()).discard(skill_name)
        for sev_names in self._by_severity.values():
            sev_names.discard(skill_name)

    def get_by_category(self, category: str) -> Set[str]:
        return set(self._by_category.get(category, set()))

    def get_by_severity(self, severity: str) -> Set[str]:
        return set(self._by_severity.get(severity, set()))

    def get_category(self, skill_name: str) -> Optional[str]:
        return self._by_name.get(skill_name)

    def clear(self) -> None:
        self._by_category.clear()
        self._by_severity.clear()
        self._by_name.clear()


class StorageMigration:
    """Manage database schema versioning"""

    CURRENT_VERSION = 2

    def __init__(self, db_conn: sqlite3.Connection) -> None:
        self._conn = db_conn

    def get_version(self) -> int:
        try:
            cursor = self._conn.execute(
                "SELECT version FROM schema_version LIMIT 1"
            )
            row = cursor.fetchone()
            return row[0] if row else 1
        except sqlite3.OperationalError:
            return 1

    def set_version(self, version: int) -> None:
        self._conn.execute("DELETE FROM schema_version")
        self._conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        self._conn.commit()

    def migrate(self) -> bool:
        current = self.get_version()
        if current >= self.CURRENT_VERSION:
            return True

        try:
            if current < 2:
                self._migrate_to_v2()
            self.set_version(self.CURRENT_VERSION)
            logger.info(f"Database migrated from v{current} to v{self.CURRENT_VERSION}")
            return True
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            return False

    def _migrate_to_v2(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_skill_name
            ON results(skill_name)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_created_at
            ON results(created_at)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_skills_category
            ON skills(category)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_skills_severity
            ON skills(severity)
        """)
        self._conn.commit()


class StorageBackup:
    """Backup and restore storage"""

    def __init__(self, config: SkillStorageConfig) -> None:
        self._config = config

    def backup(self, backup_path: str) -> bool:
        try:
            dest = Path(backup_path)
            dest.mkdir(parents=True, exist_ok=True)

            if self._config.backend == StorageBackend.SQLITE:
                src = Path(self._config.db_path)
                if src.exists():
                    shutil.copy2(src, dest / "skills.db")

            elif self._config.backend == StorageBackend.FILE:
                src = Path(self._config.file_dir)
                if src.exists():
                    shutil.copytree(src, dest / "skills_files", dirs_exist_ok=True)

            logger.info(f"Backup created at {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False

    def restore(self, backup_path: str) -> bool:
        try:
            src = Path(backup_path)

            if self._config.backend == StorageBackend.SQLITE:
                db_file = src / "skills.db"
                if db_file.exists():
                    shutil.copy2(db_file, self._config.db_path)
                    logger.info(f"Restored SQLite from {backup_path}")
                    return True

            elif self._config.backend == StorageBackend.FILE:
                files_dir = src / "skills_files"
                if files_dir.exists():
                    dest = Path(self._config.file_dir)
                    shutil.copytree(files_dir, dest, dirs_exist_ok=True)
                    logger.info(f"Restored files from {backup_path}")
                    return True

            return False
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False


class CompressedStorage:
    """Handle large result sets with compression"""

    def __init__(self, max_uncompressed: int = 100) -> None:
        self._max_uncompressed = max_uncompressed

    def should_compress(self, data: List[Any]) -> bool:
        return len(data) > self._max_uncompressed

    def compress_findings(self, findings: List[Dict]) -> str:
        import gzip
        json_bytes = json.dumps(findings).encode("utf-8")
        return gzip.compress(json_bytes).hex()

    def decompress_findings(self, hex_data: str) -> List[Dict]:
        import gzip
        compressed = bytes.fromhex(hex_data)
        return json.loads(gzip.decompress(compressed))


class SkillStorage:
    """Store and retrieve skills and results"""

    def __init__(self, config: SkillStorageConfig = None):
        self.config = config or SkillStorageConfig()
        self._cache: Dict[str, Skill] = {}
        self._results: Dict[str, List[SkillResult]] = {}
        self._db_conn = None
        self._lock = Lock()
        self._index = StorageIndex()
        self._metrics = StorageMetrics()
        self._migration: Optional[StorageMigration] = None

        if self.config.cache_enabled:
            self._init_cache()

        if self.config.backend == StorageBackend.SQLITE:
            self._init_sqlite()

    def _init_cache(self) -> None:
        """Initialize in-memory cache"""
        logger.info(f"Initialized skill cache (max: {self.config.max_cache_size})")

    def _init_sqlite(self) -> None:
        """Initialize SQLite database with indexes and transactions"""
        Path(self.config.db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self._db_conn = sqlite3.connect(self.config.db_path)
            self._db_conn.execute("PRAGMA journal_mode=WAL")
            self._db_conn.execute("PRAGMA synchronous=NORMAL")

            self._db_conn.execute("""
                CREATE TABLE IF NOT EXISTS skills (
                    name TEXT PRIMARY KEY,
                    category TEXT,
                    severity TEXT,
                    data TEXT,
                    updated_at TEXT
                )
            """)
            self._db_conn.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_name TEXT,
                    success INTEGER,
                    findings TEXT,
                    execution_time_ms REAL,
                    error TEXT,
                    created_at TEXT
                )
            """)
            self._db_conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER
                )
            """)
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_results_skill_name
                ON results(skill_name)
            """)
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_results_created_at
                ON results(created_at)
            """)
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_skills_category
                ON skills(category)
            """)
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_skills_severity
                ON skills(severity)
            """)
            self._db_conn.commit()

            self._migration = StorageMigration(self._db_conn)
            self._migration.migrate()

            logger.info(f"Initialized SQLite: {self.config.db_path}")
        except Exception as e:
            logger.error(f"SQLite init failed: {e}")

    def save_skill(self, skill: Skill) -> bool:
        """Save a skill"""
        try:
            with self._lock:
                if (
                    self.config.cache_enabled
                    and len(self._cache) < self.config.max_cache_size
                ):
                    self._cache[skill.name] = skill

                self._index.add(skill)

                if self._db_conn:
                    self._db_conn.execute(
                        "INSERT OR REPLACE INTO skills VALUES (?, ?, ?, ?, ?)",
                        (
                            skill.name,
                            skill.category,
                            skill.severity,
                            json.dumps(skill.to_dict()),
                            datetime.now().isoformat(),
                        ),
                    )
                    self._db_conn.commit()
                    self._metrics.db_queries += 1

                self._metrics.writes += 1
            return True

        except Exception as e:
            logger.error(f"Failed to save skill: {e}")
            return False

    def load_skill(self, name: str) -> Optional[Skill]:
        """Load a skill"""
        if name in self._cache:
            self._metrics.cache_hits += 1
            self._metrics.reads += 1
            return self._cache[name]

        self._metrics.cache_misses += 1

        if self._db_conn:
            cursor = self._db_conn.execute(
                "SELECT data FROM skills WHERE name = ?", (name,)
            )
            row = cursor.fetchone()
            self._metrics.db_queries += 1
            self._metrics.reads += 1
            if row:
                skill = Skill(**json.loads(row[0]))
                if self.config.cache_enabled:
                    self._cache[name] = skill
                return skill

        return None

    def delete_skill(self, name: str) -> bool:
        """Delete a skill"""
        self._cache.pop(name, None)
        self._index.remove(name)

        if self._db_conn:
            self._db_conn.execute("DELETE FROM skills WHERE name = ?", (name,))
            self._db_conn.commit()
            self._metrics.db_queries += 1

        self._metrics.deletes += 1
        return True

    def save_result(self, skill_name: str, result: SkillResult) -> bool:
        """Save skill execution result"""
        if skill_name not in self._results:
            self._results[skill_name] = []

        self._results[skill_name].append(result)

        if self._db_conn:
            self._db_conn.execute(
                "INSERT INTO results VALUES (?, ?, ?, ?, ?, ?)",
                (
                    skill_name,
                    int(result.success),
                    json.dumps(result.findings),
                    result.execution_time_ms,
                    result.error,
                    datetime.now().isoformat(),
                ),
            )
            self._db_conn.commit()
            self._metrics.db_queries += 1

        self._metrics.writes += 1
        return True

    def get_results(
        self, skill_name: str = None, limit: int = 0, offset: int = 0
    ) -> List[SkillResult]:
        """Get skill execution results with optional pagination"""
        if skill_name:
            results = self._results.get(skill_name, [])
        else:
            results = []
            for res_list in self._results.values():
                results.extend(res_list)

        if offset > 0:
            results = results[offset:]
        if limit > 0:
            results = results[:limit]

        self._metrics.reads += 1
        return results

    def get_result_history(
        self, skill_name: str, limit: int = 10, offset: int = 0
    ) -> List[SkillResult]:
        """Get paginated result history for a skill"""
        results = self._results.get(skill_name, [])
        total = len(results)
        start = max(0, total - offset - limit)
        end = total - offset
        if start >= end:
            return []
        return list(reversed(results[start:end]))

    def get_recent_results(self, hours: int = 24) -> List[SkillResult]:
        """Get results from the last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent = []
        for results_list in self._results.values():
            for r in results_list:
                if hasattr(r, "created_at"):
                    try:
                        if r.created_at >= cutoff:
                            recent.append(r)
                    except (AttributeError, TypeError):
                        recent.append(r)
                else:
                    recent.append(r)
        return recent

    def get_top_findings(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get most common finding types"""
        finding_counts: Dict[str, int] = {}
        for results_list in self._results.values():
            for r in results_list:
                for finding in r.findings:
                    ftype = finding.get("type", "unknown")
                    finding_counts[ftype] = finding_counts.get(ftype, 0) + 1

        sorted_findings = sorted(
            finding_counts.items(), key=lambda x: x[1], reverse=True
        )
        return sorted_findings[:limit]

    def purge_old_results(self, max_age_days: int = 30) -> int:
        """Remove results older than max_age_days"""
        cutoff = datetime.now() - timedelta(days=max_age_days)
        purged = 0
        with self._lock:
            for skill_name in list(self._results.keys()):
                original_len = len(self._results[skill_name])
                self._results[skill_name] = [
                    r for r in self._results[skill_name]
                    if not hasattr(r, "created_at") or r.created_at >= cutoff
                ]
                purged += original_len - len(self._results[skill_name])
                if not self._results[skill_name]:
                    del self._results[skill_name]

        if self._db_conn:
            cutoff_str = cutoff.isoformat()
            cursor = self._db_conn.execute(
                "DELETE FROM results WHERE created_at < ?", (cutoff_str,)
            )
            self._db_conn.commit()
            purged += cursor.rowcount

        logger.info(f"Purged {purged} old results")
        return purged

    def export_to_json(self, filepath: str) -> bool:
        """Export all skills and results to JSON"""
        try:
            data = {
                "exported_at": datetime.now().isoformat(),
                "skills": {},
                "results": {},
            }

            for name, skill in self._cache.items():
                data["skills"][name] = skill.to_dict()

            for name, results in self._results.items():
                data["results"][name] = [r.to_dict() for r in results]

            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)

            logger.info(f"Exported to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False

    def import_from_json(self, filepath: str) -> int:
        """Import skills and results from JSON"""
        try:
            with open(filepath) as f:
                data = json.load(f)

            count = 0
            for name, skill_data in data.get("skills", {}).items():
                try:
                    tags = set(skill_data.get("tags", []))
                    skill_data["tags"] = tags
                    skill = Skill(**skill_data)
                    self.save_skill(skill)
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to import skill {name}: {e}")

            for name, results_data in data.get("results", {}).items():
                for r_data in results_data:
                    try:
                        result = SkillResult(**r_data)
                        self.save_result(name, result)
                    except Exception as e:
                        logger.error(f"Failed to import result: {e}")

            logger.info(f"Imported {count} skills from {filepath}")
            return count
        except Exception as e:
            logger.error(f"Import failed: {e}")
            return 0

    def backup(self, backup_path: str) -> bool:
        """Create a backup of storage"""
        return StorageBackup(self.config).backup(backup_path)

    def restore(self, backup_path: str) -> bool:
        """Restore from a backup"""
        return StorageBackup(self.config).restore(backup_path)

    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        return {
            "cached_skills": len(self._cache),
            "total_results": sum(len(r) for r in self._results.values()),
            "indexed_skills": len(self._index._by_name),
            "metrics": self._metrics.to_dict(),
        }

    def get_index(self) -> StorageIndex:
        """Get the storage index"""
        return self._index

    def get_metrics(self) -> Dict[str, Any]:
        """Get I/O metrics"""
        return self._metrics.to_dict()

    def clear_metrics(self) -> None:
        """Reset I/O metrics"""
        self._metrics.reset()

    def close(self) -> None:
        """Close storage connections"""
        if self._db_conn:
            self._db_conn.close()
            self._db_conn = None


# Type alias for import compatibility
Set = set  # noqa: used in StorageIndex type hints

__all__ = [
    "SkillStorage",
    "SkillStorageConfig",
    "StorageBackend",
    "StorageMetrics",
    "StorageIndex",
    "StorageBackup",
    "StorageMigration",
    "CompressedStorage",
]
