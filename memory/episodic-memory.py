"""
Solidify Episodic Memory
Episodic memory for storing security analysis sessions

Author: Peace Stephen (Tech Lead)
Description: Episodic memory for storing analysis events over time
"""

import re
import logging
import json
import time
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque, defaultdict
from dataclasses import dataclass

class EpisodeStatus(Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"


@dataclass
class Episode:
    episode_id: str
    session_id: str
    events: List[Dict[str, Any]] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: EpisodeStatus = EpisodeStatus.ACTIVE
    summary: str = ""


class EpisodicMemoryStore:
    def __init__(self, max_episodes: int = 1000):
        self.max_episodes = max_episodes
        self.episodes: Dict[str, Episode] = {}
        self.timeline: deque = deque(maxlen=max_episodes)
        self.session_episodes: Dict[str, List[str]] = defaultdict(list)
        
    def create_episode(self, session_id: str) -> Episode:
        episode_id = f"ep_{session_id}_{int(time.time() * 1000)}"
        
        episode = Episode(
            episode_id=episode_id,
            session_id=session_id
        )
        
        self.episodes[episode_id] = episode
        self.timeline.append(episode_id)
        self.session_episodes[session_id].append(episode_id)
        
        return episode
    
    def add_event(self, episode_id: str, event: Dict[str, Any]) -> bool:
        if episode_id not in self.episodes:
            return False
            
        episode = self.episodes[episode_id]
        event["timestamp"] = datetime.now().isoformat()
        episode.events.append(event)
        
        return True
    
    def complete_episode(self, episode_id: str, summary: str = "") -> bool:
        if episode_id not in self.episodes:
            return False
            
        episode = self.episodes[episode_id]
        episode.status = EpisodeStatus.COMPLETED
        episode.end_time = datetime.now()
        episode.summary = summary
        
        return True
    
    def get_episode(self, episode_id: str) -> Optional[Episode]:
        return self.episodes.get(episode_id)
    
    def get_session_episodes(self, session_id: str) -> List[Episode]:
        episode_ids = self.session_episodes.get(session_id, [])
        return [self.episodes[eid] for eid in episode_ids if eid in self.episodes]
    
    def get_recent_episodes(self, count: int = 10) -> List[Episode]:
        recent_ids = list(self.timeline)[-count:]
        return [self.episodes[eid] for eid in reversed(recent_ids) if eid in self.episodes]
    
    def search_events(self, query: str) -> List[Dict[str, Any]]:
        results = []
        query_lower = query.lower()
        
        for episode in self.episodes.values():
            for event in episode.events:
                event_str = json.dumps(event).lower()
                if query_lower in event_str:
                    results.append(event)
                    
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_episodes": len(self.episodes),
            "active_episodes": len([e for e in self.episodes.values() if e.status == EpisodeStatus.ACTIVE]),
            "completed_episodes": len([e for e in self.episodes.values() if e.status == EpisodeStatus.COMPLETED]),
        }


_default_episodic_store: Optional[EpisodicMemoryStore] = None


def get_default_episodic_store() -> EpisodicMemoryStore:
    global _default_episodic_store
    
    if _default_episodic_store is None:
        _default_episodic_store = EpisodicMemoryStore()
        
    return _default_episodic_store


def create_episode(session_id: str) -> Episode:
    return get_default_episodic_store().create_episode(session_id)


def add_event_to_episode(episode_id: str, event: Dict[str, Any]) -> bool:
    return get_default_episodic_store().add_event(episode_id, event)


def complete_episode(episode_id: str, summary: str = "") -> bool:
    return get_default_episodic_store().complete_episode(episode_id, summary)


def get_episode_stats() -> Dict[str, Any]:
    return get_default_episodic_store().get_stats()