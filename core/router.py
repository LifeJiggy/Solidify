"""
SoliGuard Core Router
Request routing and dispatch

Author: Peace Stephen (Tech Lead)
Description: Request router for audit endpoints
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable, Type
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib
import json

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class RouteMethod(Enum):
    """HTTP Methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class ResponseFormat(Enum):
    """Response formats"""
    JSON = "json"
    STREAM = "stream"
    SSE = "sse"
    RAW = "raw"


@dataclass
class Route:
    """Route definition"""
    path: str
    method: RouteMethod
    handler: Callable
    name: str
    description: str = ""
    middlewares: List[Callable] = field(default_factory=list)
    cache_enabled: bool = False
    cache_ttl: int = 300  # seconds


@dataclass
class RequestContext:
    """Request context"""
    request_id: str
    path: str
    method: str
    headers: Dict[str, str]
    query_params: Dict[str, Any]
    body: Any
    user: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Response:
    """Response object"""
    status_code: int = 200
    body: Any = None
    headers: Dict[str, str] = field(default_factory=dict)
    format: ResponseFormat = ResponseFormat.JSON
    error: Optional[str] = None


# ============================================================================
# Router
# ============================================================================

class Router:
    """
    Request router for SoliGuard
    
    Features:
    - Route registration
    - Middleware support
    - Request/Response processing
    - Caching
    - Rate limiting
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize router"""
        self.config = config or {}
        self.routes: Dict[str, Route] = {}
        self.middlewares: List[Callable] = []
        self.error_handlers: Dict[int, Callable] = {}
        self._request_count = 0
        self._cache: Dict[str, tuple] = {}  # key -> (response, timestamp)
        
        logger.info("✅ Router initialized")
    
    # ============================================================================
    # Route Registration
    # ============================================================================
    
    def register(
        self,
        path: str,
        method: RouteMethod,
        handler: Callable,
        name: Optional[str] = None,
        description: str = "",
        middlewares: Optional[List[Callable]] = None
    ) -> str:
        """Register a route"""
        route_key = f"{method.value}:{path}"
        
        route = Route(
            path=path,
            method=method,
            handler=handler,
            name=name or handler.__name__,
            description=description,
            middlewares=middlewares or []
        )
        
        self.routes[route_key] = route
        logger.debug(f"Registered route: {route_key}")
        
        return route_key
    
    def get(self, path: str, **kwargs):
        """Register GET route"""
        def decorator(handler):
            self.register(path, RouteMethod.GET, handler, **kwargs)
            return handler
        return decorator
    
    def post(self, path: str, **kwargs):
        """Register POST route"""
        def decorator(handler):
            self.register(path, RouteMethod.POST, handler, **kwargs)
            return handler
        return decorator
    
    def put(self, path: str, **kwargs):
        """Register PUT route"""
        def decorator(handler):
            self.register(path, RouteMethod.PUT, handler, **kwargs)
            return handler
        return decorator
    
    def delete(self, path: str, **kwargs):
        """Register DELETE route"""
        def decorator(handler):
            self.register(path, RouteMethod.DELETE, handler, **kwargs)
            return handler
        return decorator
    
    def add_middleware(self, middleware: Callable):
        """Add global middleware"""
        self.middlewares.append(middleware)
    
    def set_error_handler(self, status_code: int, handler: Callable):
        """Set error handler"""
        self.error_handlers[status_code] = handler
    
    # ============================================================================
    # Request Processing
    # ============================================================================
    
    async def handle_request(
        self,
        path: str,
        method: str,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None
    ) -> Response:
        """Handle incoming request"""
        self._request_count += 1
        request_id = self._generate_request_id(path, method)
        
        # Create context
        context = RequestContext(
            request_id=request_id,
            path=path,
            method=method,
            headers=headers or {},
            query_params=query_params or {},
            body=body
        )
        
        logger.debug(f"Handling request: {method} {path}")
        
        try:
            # Find route
            route_key = f"{method.upper()}:{path}"
            route = self.routes.get(route_key)
            
            if not route:
                return Response(
                    status_code=404,
                    error=f"Route not found: {method} {path}"
                )
            
            # Check cache
            if route.cache_enabled:
                cached = self._get_from_cache(route_key, context)
                if cached:
                    logger.debug(f"Cache hit: {route_key}")
                    return cached
            
            # Process through middlewares
            for middleware in self.middlewares:
                if asyncio.iscoroutinefunction(middleware):
                    context = await middleware(context)
                else:
                    context = middleware(context)
            
            # Process through route middlewares
            for mw in route.middlewares:
                if asyncio.iscoroutinefunction(mw):
                    context = await mw(context)
                else:
                    context = mw(context)
            
            # Execute handler
            if asyncio.iscoroutinefunction(route.handler):
                result = await route.handler(context)
            else:
                result = route.handler(context)
            
            # Build response
            if isinstance(result, Response):
                response = result
            else:
                response = Response(
                    body=result,
                    format=ResponseFormat.JSON
                )
            
            # Cache if enabled
            if route.cache_enabled:
                self._add_to_cache(route_key, context, response)
            
            return response
            
        except Exception as e:
            logger.error(f"Request handling error: {str(e)}")
            
            # Check for error handler
            error_handler = self.error_handlers.get(500)
            if error_handler:
                return await error_handler(context, e)
            
            return Response(
                status_code=500,
                error=str(e)
            )
    
    # ============================================================================
    # Caching
    # ============================================================================
    
    def _generate_request_id(self, path: str, method: str) -> str:
        """Generate unique request ID"""
        data = f"{method}:{path}:{datetime.utcnow().isoformat()}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def _get_cache_key(self, route_key: str, context: RequestContext) -> str:
        """Generate cache key"""
        # Include query params in cache key
        params = json.dumps(context.query_params, sort_keys=True)
        return f"{route_key}:{params}"
    
    def _get_from_cache(self, route_key: str, context: RequestContext) -> Optional[Response]:
        """Get response from cache"""
        cache_key = self._get_cache_key(route_key, context)
        
        if cache_key in self._cache:
            response, timestamp = self._cache[cache_key]
            age = (datetime.utcnow() - timestamp).total_seconds()
            
            if age < 300:  # 5 minutes TTL
                return response
            
            del self._cache[cache_key]
        
        return None
    
    def _add_to_cache(self, route_key: str, context: RequestContext, response: Response):
        """Add response to cache"""
        cache_key = self._get_cache_key(route_key, context)
        self._cache[cache_key] = (response, datetime.utcnow())
        
        # Cleanup old entries
        if len(self._cache) > 1000:
            self._cache = dict(list(self._cache.items())[-500:])
    
    def clear_cache(self):
        """Clear all cached responses"""
        self._cache.clear()
        logger.info("Cache cleared")
    
    # ============================================================================
    # Utility Methods
    # ============================================================================
    
    def get_route(self, path: str, method: str) -> Optional[Route]:
        """Get route by path and method"""
        return self.routes.get(f"{method.upper()}:{path}")
    
    def list_routes(self) -> List[Dict[str, Any]]:
        """List all registered routes"""
        return [
            {
                "path": r.path,
                "method": r.method.value,
                "name": r.name,
                "description": r.description
            }
            for r in self.routes.values()
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get router statistics"""
        return {
            "total_routes": len(self.routes),
            "total_requests": self._request_count,
            "cached_responses": len(self._cache),
            "middlewares": len(self.middlewares)
        }


# ============================================================================
# Factory
# ============================================================================

def create_router(config: Optional[Dict[str, Any]] = None) -> Router:
    """Create router instance"""
    return Router(config)


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    router = Router()
    
    # Register routes
    @router.get("/health")
    async def health(ctx: RequestContext):
        return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
    
    @router.post("/audit")
    async def audit(ctx: RequestContext):
        return {"result": "audited", "request_id": ctx.request_id}
    
    # List routes
    routes = router.list_routes()
    print(f"Registered routes: {len(routes)}")
    for r in routes:
        print(f"  {r['method']} {r['path']}")