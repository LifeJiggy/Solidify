"""
Solidify Semantic Memory
Semantic memory with embeddings and clustering

Author: Peace Stephen (Tech Lead)
Description: Semantic memory implementation with embeddings
"""

import re
import logging
import json
import hashlib
import numpy as np
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import threading

logger = logging.getLogger(__name__)


class EmbeddingAlgorithm(Enum):
    TF_IDF = "tf_idf"
    WORD2VEC = "word2vec"
    BERT = "bert"
    CUSTOM = "custom"


class SimilarityMetric(Enum):
    COSINE = "cosine"
    EUCLIDEAN = "euclidean"
    MANHATTAN = "manhattan"


@dataclass
class EmbeddingVector:
    vector_id: str
    text: str
    embedding: List[float]
    algorithm: EmbeddingAlgorithm
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SemanticCluster:
    cluster_id: str
    centroid: List[float]
    members: List[str] = field(default_factory=list)
    name: str = ""
    topic: str = ""


class BaseEmbeddingModel(ABC):
    @abstractmethod
    def embed(self, text: str) -> List[float]:
        pass
    
    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        pass


class SimpleEmbeddingModel(BaseEmbeddingModel):
    def __init__(self, dimension: int = 384):
        self.dimension = dimension
        self.vocab: Dict[str, int] = {}
        
    def embed(self, text: str) -> List[float]:
        words = text.lower().split()
        vector = [0.0] * self.dimension
        
        for i, word in enumerate(words[:self.dimension]):
            if word not in self.vocab:
                self.vocab[word] = len(self.vocab) % self.dimension
            idx = self.vocab[word]
            vector[idx] += 1.0
            
        magnitude = sum(v * v for v in vector) ** 0.5
        if magnitude > 0:
            vector = [v / magnitude for v in vector]
            
        return vector
    
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(text) for text in texts]


class SemanticMemoryStore:
    def __init__(self, dimension: int = 384):
        self.dimension = dimension
        self.model = SimpleEmbeddingModel(dimension)
        self.embeddings: Dict[str, EmbeddingVector] = {}
        self.clusters: Dict[str, SemanticCluster] = {}
        self.text_to_id: Dict[str, str] = {}
        self.lock = threading.Lock()
        
    def add_embedding(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        with self.lock:
            text_hash = hashlib.md5(text.encode()).hexdigest()
            vector_id = f"emb_{text_hash}"
            
            if vector_id in self.embeddings:
                return vector_id
                
            embedding = self.model.embed(text)
            
            emb_vector = EmbeddingVector(
                vector_id=vector_id,
                text=text,
                embedding=embedding,
                algorithm=EmbeddingAlgorithm.TF_IDF,
                metadata=metadata or {}
            )
            
            self.embeddings[vector_id] = emb_vector
            self.text_to_id[text] = vector_id
            
            return vector_id
    
    def get_embedding(self, vector_id: str) -> Optional[EmbeddingVector]:
        return self.embeddings.get(vector_id)
    
    def get_embedding_for_text(self, text: str) -> Optional[EmbeddingVector]:
        text_hash = hashlib.md5(text.encode()).hexdigest()
        vector_id = f"emb_{text_hash}"
        return self.embeddings.get(vector_id)
    
    def search_similar(self, query: str, top_k: int = 5) -> List[Tuple[str, float]]:
        query_emb = self.model.embed(query)
        
        similarities = []
        
        for vector_id, emb_vector in self.embeddings.items():
            sim = self._cosine_similarity(query_emb, emb_vector.embedding)
            similarities.append((vector_id, sim))
            
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]
    
    def create_cluster(self, name: str, topic: str) -> str:
        cluster_id = f"cluster_{len(self.clusters)}"
        
        cluster = SemanticCluster(
            cluster_id=cluster_id,
            centroid=[0.0] * self.dimension,
            name=name,
            topic=topic
        )
        
        self.clusters[cluster_id] = cluster
        return cluster_id
    
    def add_to_cluster(self, vector_id: str, cluster_id: str) -> bool:
        if cluster_id not in self.clusters or vector_id not in self.embeddings:
            return False
            
        cluster = self.clusters[cluster_id]
        cluster.members.append(vector_id)
        
        return True
    
    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        dot = sum(a * b for a, b in zip(vec1, vec2))
        mag1 = sum(a * a for a in vec1) ** 0.5
        mag2 = sum(b * b for b in vec2) ** 0.5
        
        if mag1 == 0 or mag2 == 0:
            return 0.0
            
        return dot / (mag1 * mag2)
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_embeddings": len(self.embeddings),
            "total_clusters": len(self.clusters),
            "dimension": self.dimension
        }


class SemanticRetriever:
    def __init__(self, store: SemanticMemoryStore):
        self.store = store
        
    def retrieve(self, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        results = self.store.search_similar(query, top_k=10)
        
        retrieved = []
        for vector_id, score in results:
            emb = self.store.get_embedding(vector_id)
            if emb:
                result = {
                    "text": emb.text,
                    "score": score,
                    "metadata": emb.metadata,
                    "algorithm": emb.algorithm.value
                }
                retrieved.append(result)
                
        if filters:
            retrieved = [r for r in retrieved if self._matches_filters(r, filters)]
            
        return retrieved
    
    def retrieve_by_cluster(self, cluster_id: str) -> List[Dict[str, Any]]:
        if cluster_id not in self.store.clusters:
            return []
            
        cluster = self.store.clusters[cluster_id]
        
        results = []
        for member_id in cluster.members:
            emb = self.store.get_embedding(member_id)
            if emb:
                results.append({
                    "text": emb.text,
                    "metadata": emb.metadata
                })
                
        return results
    
    def _matches_filters(self, result: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        for key, value in filters.items():
            if key in result and result[key] != value:
                return False
        return True


def create_semantic_store(dimension: int = 384) -> SemanticMemoryStore:
    return SemanticMemoryStore(dimension)


_default_semantic_store: Optional[SemanticMemoryStore] = None
_default_semantic_retriever: Optional[SemanticRetriever] = None


def get_default_semantic_store() -> SemanticMemoryStore:
    global _default_semantic_store
    
    if _default_semantic_store is None:
        _default_semantic_store = create_semantic_store()
        
    return _default_semantic_store


def get_default_semantic_retriever() -> SemanticRetriever:
    global _default_semantic_retriever
    
    if _default_semantic_retriever is None:
        _default_semantic_retriever = SemanticRetriever(get_default_semantic_store())
        
    return _default_semantic_retriever


def embed_text(text: str, metadata: Optional[Dict[str, Any]] = None) -> str:
    return get_default_semantic_store().add_embedding(text, metadata)


def search_semantic(query: str) -> List[Dict[str, Any]]:
    return get_default_semantic_retriever().retrieve(query)


def get_semantic_stats() -> Dict[str, Any]:
    return get_default_semantic_store().get_stats()