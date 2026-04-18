"""
Skill Storage Module
Production-grade skill persistence and storage

Author: Solidify Security Team
Version: 1.0.0
"""

import json
import sqlite3
import logging
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from datetime import datetime

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


class SkillStorage:
    """Store and retrieve skills and results"""

    def __init__(self, config: SkillStorageConfig = None):
        self.config = config or SkillStorageConfig()
        self._cache: Dict[str, Skill] = {}
        self._results: Dict[str, List[SkillResult]] = {}
        self._db_conn = None

        if self.config.cache_enabled:
            self._init_cache()

        if self.config.backend == StorageBackend.SQLITE:
            self._init_sqlite()

    def _init_cache(self) -> None:
        """Initialize in-memory cache"""
        logger.info(f"Initialized skill cache (max: {self.config.max_cache_size})")

    def _init_sqlite(self) -> None:
        """Initialize SQLite database"""
        Path(self.config.db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self._db_conn = sqlite3.connect(self.config.db_path)
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
            self._db_conn.commit()
            logger.info(f"Initialized SQLite: {self.config.db_path}")
        except Exception as e:
            logger.error(f"SQLite init failed: {e}")

    def save_skill(self, skill: Skill) -> bool:
        """Save a skill"""
        try:
            if (
                self.config.cache_enabled
                and len(self._cache) < self.config.max_cache_size
            ):
                self._cache[skill.name] = skill

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

            return True

        except Exception as e:
            logger.error(f"Failed to save skill: {e}")
            return False

    def load_skill(self, name: str) -> Optional[Skill]:
        """Load a skill"""
        if name in self._cache:
            return self._cache[name]

        if self._db_conn:
            cursor = self._db_conn.execute(
                "SELECT data FROM skills WHERE name = ?", (name,)
            )
            row = cursor.fetchone()
            if row:
                return Skill(**json.loads(row[0]))

        return None

    def delete_skill(self, name: str) -> bool:
        """Delete a skill"""
        self._cache.pop(name, None)

        if self._db_conn:
            self._db_conn.execute("DELETE FROM skills WHERE name = ?", (name,))
            self._db_conn.commit()

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

        return True

    def get_results(self, skill_name: str = None) -> List[SkillResult]:
        """Get skill execution results"""
        if skill_name:
            return self._results.get(skill_name, [])

        all_results = []
        for results in self._results.values():
            all_results.extend(results)

        return all_results

    def get_stats(self) -> Dict[str, int]:
        """Get storage statistics"""
        return {
            "cached_skills": len(self._cache),
            "total_results": sum(len(r) for r in self._results.values()),
        }

    def close(self) -> None:
        """Close storage connections"""
        if self._db_conn:
            self._db_conn.close()
            self._db_conn = None


__all__ = [
    "SkillStorage",
    "SkillStorageConfig",
    "StorageBackend",
]
