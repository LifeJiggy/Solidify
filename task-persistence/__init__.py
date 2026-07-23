"""
Task Persistence Package

Production-grade task persistence for Solidify security audits.
Exports: TaskPersistenceManager, TaskStatus, StorageBackend, persistence backends

Author: Solidify Security Team
Version: 1.0.0
"""

import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Re-export from task_persistence modules
try:
    from .task_persistence import TaskPersistenceManager, TaskStatus, StorageBackend
    from .task_saver import TaskSaver
    from .task_loader import TaskLoader, TaskStatus
    from .task_restore import TaskRestorer
    from .task_serializer import TaskSerializer

    __all__ = [
        "TaskPersistenceManager",
        "TaskStatus",
        "StorageBackend",
        "TaskSaver",
        "TaskLoader",
        "TaskRestorer",
        "TaskSerializer",
    ]

except ImportError as e:
    logger.warning(f"Task persistence modules not fully available: {e}")
    __all__ = []

logger.info(f"TaskPersistence package loaded: {len(__all__)} exports")
