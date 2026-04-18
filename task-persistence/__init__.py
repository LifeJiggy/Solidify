"""
Task Persistence Package

Production-grade task persistence for Solidify security audits.
Exports: TaskPersistence, TaskMetadata, TaskStatus, persistence backends

Author: Solidify Security Team
Version: 1.0.0
"""

import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Re-export from task-persistence module
try:
    from .task_persistence import TaskPersistence, TaskStatus, PersistenceBackend
    from .task_saver import TaskSaver
    from .task_loader import TaskLoader
    from .task_restore import TaskRestore
    from .task_serializer import TaskSerializer
    from .task_backup import TaskBackup
    from .persistence_factory import PersistenceFactory
    from .persistence_manager import PersistenceManager

    __all__ = [
        "TaskPersistence",
        "TaskMetadata",
        "TaskStatus",
        "PersistenceBackend",
        "TaskSaver",
        "TaskLoader",
        "TaskRestore",
        "TaskSerializer",
        "TaskBackup",
        "PersistenceFactory",
        "PersistenceManager",
    ]

except ImportError as e:
    logger.warning(f"Task persistence modules not fully available: {e}")
    __all__ = []

logger.info(f"✅ TaskPersistence package loaded: {len(__all__)} exports")
