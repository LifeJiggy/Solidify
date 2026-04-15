"""
SoliGuard Auth Hooks
Authentication and authorization hooks for security analysis pipeline

Author: Peace Stephen (Tech Lead)
Description: Auth hooks for access control and permissions
"""

import re
import logging
import json
import hashlib
import hmac
import secrets
from typing import Dict, Any, List, Optional, Set, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class AuthLevel(Enum):
    NONE = "none"
    BASIC = "basic"
    STANDARD = "standard"
    ELEVATED = "elevated"
    ADMIN = "admin"


class AuthStatus(Enum):
    PENDING = "pending"
    AUTHENTICATED = "authenticated"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    EXPIRED = "expired"


class PermissionType(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"
    AUDIT = "audit"
    REPORT = "report"
    DELETE = "delete"


@dataclass
class AuthCredentials:
    user_id: str
    token: str
    level: AuthLevel
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthContext:
    user_id: str
    session_id: str
    auth_level: AuthLevel
    permissions: Set[PermissionType] = field(default_factory=set)
    status: AuthStatus = AuthStatus.PENDING
    authenticated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


@dataclass
class AuthResult:
    status: AuthStatus
    message: str
    context: Optional[AuthContext] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAuthHook(ABC):
    def __init__(self, name: str, permission: PermissionType):
        self.name = name
        self.permission = permission
        self.enabled = True
        self.execution_count = 0
        self.success_count = 0
        self.failure_count = 0
        
    @abstractmethod
    def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        pass
    
    @abstractmethod
    def authorize(self, context: AuthContext, action: str) -> AuthResult:
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "permission": self.permission.value,
            "execution_count": self.execution_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count
        }


class TokenAuthHook(BaseAuthHook):
    def __init__(self, name: str = "token_auth", permission: PermissionType = PermissionType.READ):
        super().__init__(name, permission)
        self.tokens: Dict[str, AuthCredentials] = {}
        self.sessions: Dict[str, AuthContext] = {}
        
    def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        self.execution_count += 1
        
        if credentials.user_id not in self.tokens:
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.UNAUTHORIZED,
                message="User not found"
            )
            
        stored = self.tokens[credentials.user_id]
        
        if stored.token != credentials.token:
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.UNAUTHORIZED,
                message="Invalid token"
            )
            
        if credentials.expires_at and credentials.expires_at < datetime.now():
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.EXPIRED,
                message="Token expired"
            )
            
        session_id = secrets.token_urlsafe(16)
        context = AuthContext(
            user_id=credentials.user_id,
            session_id=session_id,
            auth_level=credentials.level,
            permissions=self._get_permissions(credentials.level),
            status=AuthStatus.AUTHENTICATED,
            authenticated_at=datetime.now(),
            expires_at=credentials.expires_at
        )
        
        self.sessions[session_id] = context
        self.success_count += 1
        
        return AuthResult(
            status=AuthStatus.AUTHENTICATED,
            message="Authentication successful",
            context=context
        )
        
    def authorize(self, context: AuthContext, action: str) -> AuthResult:
        self.execution_count += 1
        
        if context.status != AuthStatus.AUTHENTICATED:
            self.failure_count += 1
            return AuthResult(
                status=context.status,
                message="Not authenticated"
            )
            
        if context.expires_at and context.expires_at < datetime.now():
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.EXPIRED,
                message="Session expired"
            )
            
        required_permission = self._action_to_permission(action)
        
        if required_permission not in context.permissions:
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.FORBIDDEN,
                message=f"Missing permission: {required_permission.value}"
            )
            
        self.success_count += 1
        
        return AuthResult(
            status=AuthStatus.AUTHENTICATED,
            message="Authorization successful"
        )
        
    def register_token(self, user_id: str, token: str, level: AuthLevel) -> None:
        expires_at = datetime.now() + timedelta(hours=24)
        
        self.tokens[user_id] = AuthCredentials(
            user_id=user_id,
            token=token,
            level=level,
            expires_at=expires_at
        )
        
    def revoke_token(self, user_id: str) -> bool:
        if user_id in self.tokens:
            del self.tokens[user_id]
            return True
        return False
        
    def _get_permissions(self, level: AuthLevel) -> Set[PermissionType]:
        mapping = {
            AuthLevel.NONE: set(),
            AuthLevel.BASIC: {PermissionType.READ},
            AuthLevel.STANDARD: {PermissionType.READ, PermissionType.REPORT},
            AuthLevel.ELEVATED: {PermissionType.READ, PermissionType.WRITE, PermissionType.REPORT},
            AuthLevel.ADMIN: {PermissionType.READ, PermissionType.WRITE, PermissionType.EXECUTE, PermissionType.ADMIN, PermissionType.AUDIT, PermissionType.REPORT, PermissionType.DELETE},
        }
        return mapping.get(level, set())
        
    def _action_to_permission(self, action: str) -> PermissionType:
        mapping = {
            "read": PermissionType.READ,
            "write": PermissionType.WRITE,
            "execute": PermissionType.EXECUTE,
            "admin": PermissionType.ADMIN,
            "audit": PermissionType.AUDIT,
            "report": PermissionType.REPORT,
            "delete": PermissionType.DELETE,
        }
        return mapping.get(action.lower(), PermissionType.READ)


class APIKeyAuthHook(BaseAuthHook):
    def __init__(self, name: str = "api_key_auth", permission: PermissionType = PermissionType.READ):
        super().__init__(name, permission)
        self.api_keys: Dict[str, AuthCredentials] = {}
        
    def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        self.execution_count += 1
        
        if credentials.token not in self.api_keys:
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.UNAUTHORIZED,
                message="Invalid API key"
            )
            
        stored = self.api_keys[credentials.token]
        
        if stored.expires_at and stored.expires_at < datetime.now():
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.EXPIRED,
                message="API key expired"
            )
            
        session_id = secrets.token_urlsafe(16)
        context = AuthContext(
            user_id=stored.user_id,
            session_id=session_id,
            auth_level=stored.level,
            permissions=self._get_permissions(stored.level),
            status=AuthStatus.AUTHENTICATED,
            authenticated_at=datetime.now(),
            expires_at=stored.expires_at
        )
        
        self.success_count += 1
        
        return AuthResult(
            status=AuthStatus.AUTHENTICATED,
            message="API key authentication successful",
            context=context
        )
        
    def authorize(self, context: AuthContext, action: str) -> AuthResult:
        self.execution_count += 1
        
        if context.status != AuthStatus.AUTHENTICATED:
            self.failure_count += 1
            return AuthResult(
                status=context.status,
                message="Not authenticated"
            )
            
        required_permission = self._action_to_permission(action)
        
        if required_permission not in context.permissions:
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.FORBIDDEN,
                message=f"Missing permission: {required_permission.value}"
            )
            
        self.success_count += 1
        
        return AuthResult(
            status=AuthStatus.AUTHENTICATED,
            message="Authorization successful"
        )
        
    def register_api_key(
        self,
        user_id: str,
        api_key: str,
        level: AuthLevel,
        expires_hours: int = 24
    ) -> None:
        expires_at = datetime.now() + timedelta(hours=expires_hours)
        
        self.api_keys[api_key] = AuthCredentials(
            user_id=user_id,
            token=api_key,
            level=level,
            expires_at=expires_at
        )
        
    def revoke_api_key(self, api_key: str) -> bool:
        if api_key in self.api_keys:
            del self.api_keys[api_key]
            return True
        return False
        
    def _get_permissions(self, level: AuthLevel) -> Set[PermissionType]:
        mapping = {
            AuthLevel.NONE: set(),
            AuthLevel.BASIC: {PermissionType.READ},
            AuthLevel.STANDARD: {PermissionType.READ, PermissionType.REPORT},
            AuthLevel.ELEVATED: {PermissionType.READ, PermissionType.WRITE, PermissionType.REPORT},
            AuthLevel.ADMIN: {PermissionType.READ, PermissionType.WRITE, PermissionType.EXECUTE, PermissionType.ADMIN, PermissionType.AUDIT, PermissionType.REPORT, PermissionType.DELETE},
        }
        return mapping.get(level, set())
        
    def _action_to_permission(self, action: str) -> PermissionType:
        mapping = {
            "read": PermissionType.READ,
            "write": PermissionType.WRITE,
            "execute": PermissionType.EXECUTE,
            "admin": PermissionType.ADMIN,
            "audit": PermissionType.AUDIT,
            "report": PermissionType.REPORT,
            "delete": PermissionType.DELETE,
        }
        return mapping.get(action.lower(), PermissionType.READ)


class PermissionHook(BaseAuthHook):
    def __init__(self, name: str = "permission_hook", permission: PermissionType = PermissionType.ADMIN):
        super().__init__(name, permission)
        self.permissions: Dict[str, Set[PermissionType]] = defaultdict(set)
        
    def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        self.execution_count += 1
        
        if credentials.user_id not in self.permissions:
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.UNAUTHORIZED,
                message="User not found"
            )
            
        session_id = secrets.token_urlsafe(16)
        context = AuthContext(
            user_id=credentials.user_id,
            session_id=session_id,
            auth_level=credentials.level,
            permissions=self.permissions[credentials.user_id],
            status=AuthStatus.AUTHENTICATED,
            authenticated_at=datetime.now()
        )
        
        self.success_count += 1
        
        return AuthResult(
            status=AuthStatus.AUTHENTICATED,
            message="Permission authentication successful",
            context=context
        )
        
    def authorize(self, context: AuthContext, action: str) -> AuthResult:
        self.execution_count += 1
        
        required = self._action_to_permission(action)
        
        if required not in context.permissions:
            self.failure_count += 1
            return AuthResult(
                status=AuthStatus.FORBIDDEN,
                message=f"Missing permission: {required.value}"
            )
            
        self.success_count += 1
        
        return AuthResult(
            status=AuthStatus.AUTHENTICATED,
            message="Permission check passed"
        )
        
    def grant_permission(self, user_id: str, permission: PermissionType) -> None:
        self.permissions[user_id].add(permission)
        
    def revoke_permission(self, user_id: str, permission: PermissionType) -> None:
        if permission in self.permissions[user_id]:
            self.permissions[user_id].remove(permission)
            
    def _action_to_permission(self, action: str) -> PermissionType:
        mapping = {
            "read": PermissionType.READ,
            "write": PermissionType.WRITE,
            "execute": PermissionType.EXECUTE,
            "admin": PermissionType.ADMIN,
            "audit": PermissionType.AUDIT,
            "report": PermissionType.REPORT,
            "delete": PermissionType.DELETE,
        }
        return mapping.get(action.lower(), PermissionType.READ)


class AuthManager:
    def __init__(self):
        self.hooks: Dict[str, BaseAuthHook] = {}
        self.sessions: Dict[str, AuthContext] = {}
        self.default_level = AuthLevel.NONE
        
    def register_hook(self, hook: BaseAuthHook) -> None:
        self.hooks[hook.name] = hook
        
    def authenticate(
        self,
        user_id: str,
        token: str,
        method: str = "token"
    ) -> AuthResult:
        for hook in self.hooks.values():
            if not hook.enabled:
                continue
                
            credentials = AuthCredentials(
                user_id=user_id,
                token=token,
                level=self.default_level
            )
            
            result = hook.authenticate(credentials)
            
            if result.status == AuthStatus.AUTHENTICATED and result.context:
                self.sessions[result.context.session_id] = result.context
                return result
                
        return AuthResult(
            status=AuthStatus.UNAUTHORIZED,
            message="Authentication failed"
        )
        
    def authorize(
        self,
        session_id: str,
        action: str
    ) -> AuthResult:
        if session_id not in self.sessions:
            return AuthResult(
                status=AuthStatus.UNAUTHORIZED,
                message="Session not found"
            )
            
        context = self.sessions[session_id]
        
        for hook in self.hooks.values():
            if not hook.enabled:
                continue
                
            result = hook.authorize(context, action)
            
            if result.status != AuthStatus.AUTHENTICATED:
                return result
                
        return AuthResult(
            status=AuthStatus.AUTHENTICATED,
            message="Authorization successful"
        )
        
    def revoke_session(self, session_id: str) -> bool:
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False
        
    def cleanup_expired_sessions(self) -> int:
        now = datetime.now()
        expired = [
            sid for sid, ctx in self.sessions.items()
            if ctx.expires_at and ctx.expires_at < now
        ]
        
        for sid in expired:
            del self.sessions[sid]
            
        return len(expired)
        
    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_hooks": len(self.hooks),
            "active_sessions": len(self.sessions),
            "default_level": self.default_level.value,
            "hook_stats": [hook.get_stats() for hook in self.hooks.values()]
        }


class RBACManager:
    def __init__(self):
        self.roles: Dict[str, Set[PermissionType]] = {}
        self.user_roles: Dict[str, Set[str]] = defaultdict(set)
        
    def create_role(self, role_name: str, permissions: Set[PermissionType]) -> None:
        self.roles[role_name] = permissions
        
    def assign_role(self, user_id: str, role_name: str) -> None:
        if role_name in self.roles:
            self.user_roles[user_id].add(role_name)
            
    def remove_role(self, user_id: str, role_name: str) -> None:
        if role_name in self.user_roles[user_id]:
            self.user_roles[user_id].remove(role_name)
            
    def get_permissions(self, user_id: str) -> Set[PermissionType]:
        permissions = set()
        
        for role in self.user_roles[user_id]:
            if role in self.roles:
                permissions.update(self.roles[role])
                
        return permissions
        
    def has_permission(self, user_id: str, permission: PermissionType) -> bool:
        return permission in self.get_permissions(user_id)


def authenticate_user(
    user_id: str,
    token: str,
    method: str = "token"
) -> AuthResult:
    manager = get_default_auth_manager()
    return manager.authenticate(user_id, token, method)


def authorize_action(
    session_id: str,
    action: str
) -> AuthResult:
    manager = get_default_auth_manager()
    return manager.authorize(session_id, action)


def check_permission(
    user_id: str,
    permission: PermissionType
) -> bool:
    rbac = get_default_rbac_manager()
    return rbac.has_permission(user_id, permission)


_default_auth_manager: Optional[AuthManager] = None
_default_rbac_manager: Optional[RBACManager] = None


def get_default_auth_manager() -> AuthManager:
    global _default_auth_manager
    
    if _default_auth_manager is None:
        _default_auth_manager = AuthManager()
        _default_auth_manager.register_hook(TokenAuthHook())
        _default_auth_manager.register_hook(APIKeyAuthHook())
        _default_auth_manager.register_hook(PermissionHook())
        
    return _default_auth_manager


def get_default_rbac_manager() -> RBACManager:
    global _default_rbac_manager
    
    if _default_rbac_manager is None:
        _default_rbac_manager = RBACManager()
        
    return _default_rbac_manager


def get_auth_stats() -> Dict[str, Any]:
    return get_default_auth_manager().get_stats()


def initialize_auth() -> None:
    auth_manager = get_default_auth_manager()
    rbac_manager = get_default_rbac_manager()
    
    rbac_manager.create_role("reader", {PermissionType.READ})
    rbac_manager.create_role("reporter", {PermissionType.READ, PermissionType.REPORT})
    rbac_manager.create_role("analyst", {PermissionType.READ, PermissionType.WRITE, PermissionType.REPORT})
    rbac_manager.create_role("admin", {PermissionType.READ, PermissionType.WRITE, PermissionType.EXECUTE, PermissionType.ADMIN, PermissionType.AUDIT, PermissionType.REPORT, PermissionType.DELETE})