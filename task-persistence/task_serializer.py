"""
Task Serializer Module

This module provides comprehensive serialization and deserialization capabilities for task data
in the Solidify security auditing framework.

Author: Solidify Security Team
Version: 1.0.0
"""

import re
import json
import time
import pickle
import base64
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import logging
import zlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SerializationFormat(Enum):
    JSON = "json"
    PICKLE = "pickle"
    MSG_PACK = "msgpack"
    CBOR = "cbor"
    PROTOBUF = "protobuf"


class CompressionType(Enum):
    NONE = "none"
    GZIP = "gzip"
    ZLIB = "zlib"
    LZ4 = "lz4"
    BROTLI = "brotli"


class SerializationStrategy(Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DELTA = "delta"
    COMPRESSED = "compressed"


@dataclass
class SerializedTask:
    task_id: str
    format: SerializationFormat
    compression: CompressionType
    data: bytes
    checksum: str
    version: int
    timestamp: float
    
    def get_size(self) -> int:
        return len(self.data)
    
    def verify_checksum(self) -> bool:
        calculated = hashlib.sha256(self.data).hexdigest()
        return calculated == self.checksum
    
    def decompress(self) -> bytes:
        if self.compression == CompressionType.GZIP:
            return zlib.decompress(self.data)
        elif self.compression == CompressionType.ZLIB:
            return zlib.decompress(self.data)
        return self.data
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'task_id': self.task_id,
            'format': self.format.value,
            'compression': self.compression.value,
            'data_size': self.get_size(),
            'checksum': self.checksum,
            'version': self.version,
            'timestamp': self.timestamp
        }


class SerializerBase(ABC):
    @abstractmethod
    def serialize(self, data: Dict[str, Any]) -> bytes:
        pass
    
    @abstractmethod
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def get_format(self) -> SerializationFormat:
        pass


class JSONSerializer(SerializerBase):
    def __init__(self, pretty: bool = False, indent: int = 2):
        self.pretty = pretty
        self.indent = indent
    
    def serialize(self, data: Dict[str, Any]) -> bytes:
        if self.pretty:
            json_str = json.dumps(data, indent=self.indent, sort_keys=True)
        else:
            json_str = json.dumps(data, separators=(',', ':'))
        
        return json_str.encode('utf-8')
    
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        return json.loads(data.decode('utf-8'))
    
    def get_format(self) -> SerializationFormat:
        return SerializationFormat.JSON


class PickleSerializer(SerializerBase):
    def __init__(self, protocol: int = pickle.HIGHEST_PROTOCOL):
        self.protocol = protocol
    
    def serialize(self, data: Dict[str, Any]) -> bytes:
        return pickle.dumps(data, protocol=self.protocol)
    
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        return pickle.loads(data)
    
    def get_format(self) -> SerializationFormat:
        return SerializationFormat.PICKLE


class CBORSerializer(SerializerBase):
    def serialize(self, data: Dict[str, Any]) -> bytes:
        try:
            import cbor
            return cbor.dumps(data)
        except ImportError:
            logger.warning("cbor not available, falling back to JSON")
            json_serializer = JSONSerializer()
            return json_serializer.serialize(data)
    
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        try:
            import cbor
            return cbor.loads(data)
        except ImportError:
            json_serializer = JSONSerializer()
            return json_serializer.deserialize(data)
    
    def get_format(self) -> SerializationFormat:
        return SerializationFormat.CBOR


class CompressionWrapper:
    def __init__(self, compression_type: CompressionType = CompressionType.ZLIB):
        self.compression_type = compression_type
    
    def compress(self, data: bytes) -> bytes:
        if self.compression_type == CompressionType.NONE:
            return data
        elif self.compression_type in [CompressionType.GZIP, CompressionType.ZLIB]:
            return zlib.compress(data, level=9)
        return data
    
    def decompress(self, data: bytes) -> bytes:
        if self.compression_type == CompressionType.NONE:
            return data
        elif self.compression_type in [CompressionType.GZIP, CompressionType.ZLIB]:
            return zlib.decompress(data)
        return data


class TaskSerializer:
    def __init__(self):
        self.serializers: Dict[SerializationFormat, SerializerBase] = {}
        self.compression = CompressionWrapper(CompressionType.ZLIB)
        self.register_default_serializers()
        self.default_format = SerializationFormat.JSON
    
    def register_default_serializers(self):
        self.serializers[SerializationFormat.JSON] = JSONSerializer(pretty=True)
        self.serializers[SerializationFormat.PICKLE] = PickleSerializer()
        
        try:
            self.serializers[SerializationFormat.CBOR] = CBORSerializer()
        except:
            pass
    
    def register_serializer(self, format_type: SerializationFormat, 
                        serializer: SerializerBase):
        self.serializers[format_type] = serializer
        logger.info(f"Registered serializer: {format_type.value}")
    
    def set_default_format(self, format_type: SerializationFormat):
        self.default_format = format_type
    
    def set_compression(self, compression_type: CompressionType):
        self.compression = CompressionWrapper(compression_type)
        logger.info(f"Compression set to: {compression_type.value}")
    
    def serialize(self, data: Dict[str, Any], 
               format_type: Optional[SerializationFormat] = None,
               use_compression: bool = True) -> SerializedTask:
        
        if format_type is None:
            format_type = self.default_format
        
        serializer = self.serializers.get(format_type)
        
        if not serializer:
            serializer = self.serializers[SerializationFormat.JSON]
        
        serialized = serializer.serialize(data)
        
        if use_compression:
            serialized = self.compression.compress(serialized)
        
        checksum = hashlib.sha256(serialized).hexdigest()
        
        return SerializedTask(
            task_id=data.get('task_id', 'unknown'),
            format=format_type,
            compression=self.compression.compression_type if use_compression else CompressionType.NONE,
            data=serialized,
            checksum=checksum,
            version=1,
            timestamp=time.time()
        )
    
    def deserialize(self, serialized_task: SerializedTask) -> Dict[str, Any]:
        data = serialized_task.data
        
        if serialized_task.compression != CompressionType.NONE:
            data = self.compression.decompress(data)
        
        serializer = self.serializers.get(serialized_task.format)
        
        if not serializer:
            serializer = self.serializers[SerializationFormat.JSON]
        
        return serializer.deserialize(data)
    
    def serialize_to_string(self, data: Dict[str, Any],
                       format_type: Optional[SerializationFormat] = None) -> str:
        
        serialized = self.serialize(data, format_type)
        
        return base64.b64encode(serialized.data).decode('utf-8')
    
    def deserialize_from_string(self, serialized_string: str,
                          format_type: Optional[SerializationFormat] = None) -> Dict[str, Any]:
        
        data = base64.b64decode(serialized_string.encode('utf-8'))
        
        if format_type is None:
            format_type = self.default_format
        
        serializer = self.serializers.get(format_type)
        
        if not serializer:
            serializer = self.serializers[SerializationFormat.JSON]
        
        return serializer.deserialize(data)
    
    def serialize_batch(self, tasks: List[Dict[str, Any]],
                    format_type: Optional[SerializationFormat] = None) -> List[SerializedTask]:
        
        return [self.serialize(task, format_type) for task in tasks]
    
    def deserialize_batch(self, serialized_tasks: List[SerializedTask]) -> List[Dict[str, Any]]:
        
        return [self.deserialize(task) for task in serialized_tasks]
    
    def create_checkpoint(self, tasks: List[Dict[str, Any]],
                     filepath: str,
                     format_type: Optional[SerializationFormat] = None) -> bool:
        
        serialized = self.serialize_batch(tasks, format_type)
        
        with open(filepath, 'wb') as f:
            for task in serialized:
                task_data = json.dumps(task.to_dict()).encode('utf-8')
                length = len(task_data)
                f.write(length.to_bytes(4, 'big'))
                f.write(task_data)
        
        logger.info(f"Checkpoint created: {filepath}")
        return True
    
    def load_checkpoint(self, filepath: str) -> List[Dict[str, Any]]:
        
        tasks = []
        
        with open(filepath, 'rb') as f:
            while True:
                length_bytes = f.read(4)
                
                if not length_bytes:
                    break
                
                length = int.from_bytes(length_bytes, 'big')
                task_data = f.read(length)
                
                task_dict = json.loads(task_data.decode('utf-8'))
                tasks.append(task_dict)
        
        return tasks
    
    def get_supported_formats(self) -> List[str]:
        return [f.value for f in self.serializers.keys()]


class DeltaSerializer:
    def __init__(self, base_data: Dict[str, Any], full_serializer: TaskSerializer):
        self.base_data = base_data
        self.full_serializer = full_serializer
    
    def create_delta(self, new_data: Dict[str, Any]) -> Dict[str, Any]:
        delta = {}
        
        all_keys = set(self.base_data.keys()) | set(new_data.keys())
        
        for key in all_keys:
            base_value = self.base_data.get(key)
            new_value = new_data.get(key)
            
            if base_value != new_value:
                delta[key] = new_value
        
        return delta
    
    def apply_delta(self, delta: Dict[str, Any]) -> Dict[str, Any]:
        result = self.base_data.copy()
        result.update(delta)
        
        return result
    
    def serialize_delta(self, new_data: Dict[str, Any]) -> SerializedTask:
        delta = self.create_delta(new_data)
        
        return self.full_serializer.serialize(delta)
    
    def deserialize_delta(self, serialized_delta: SerializedTask) -> Dict[str, Any]:
        delta = self.full_serializer.deserialize(serialized_delta)
        
        return self.apply_delta(delta)


def serialize_task(task: Dict[str, Any], format_type: str = "json") -> str:
    try:
        format_enum = SerializationFormat(format_type)
    except:
        format_enum = SerializationFormat.JSON
    
    serializer = TaskSerializer()
    return serializer.serialize_to_string(task, format_enum)


def deserialize_task(serialized: str, format_type: str = "json") -> Dict[str, Any]:
    try:
        format_enum = SerializationFormat(format_type)
    except:
        format_enum = SerializationFormat.JSON
    
    serializer = TaskSerializer()
    return serializer.deserialize_from_string(serialized, format_enum)


if __name__ == '__main__':
    task_data = {
        'task_id': 'test_001',
        'task_name': 'Security Scan',
        'task_type': 'scan',
        'state': 'pending',
        'payload': {
            'contract': '0x1234567890123456789012345678901234567890',
            'scan_type': 'full',
            'depth': 3
        }
    }
    
    serializer = TaskSerializer()
    
    serialized = serializer.serialize(task_data)
    print(f"Serialized size: {serialized.get_size()} bytes")
    
    deserialized = serializer.deserialize(serialized)
    print(f"Task ID: {deserialized['task_id']}")
    
    serialized_str = serializer.serialize_to_string(task_data)
    print(f"Serialized string length: {len(serialized_str)}")