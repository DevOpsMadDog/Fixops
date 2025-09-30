"""
Enterprise Redis cache service with high-performance optimization
"""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional, Union
import structlog
import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool
import orjson

from src.config.settings import get_settings

logger = structlog.get_logger()
settings = get_settings()


class CacheService:
    """High-performance Redis cache service with enterprise features"""
    
    _instance: Optional['CacheService'] = None
    _redis_pool: Optional[ConnectionPool] = None
    _redis_client: Optional[redis.Redis] = None
    
    def __init__(self):
        if CacheService._instance is not None:
            raise RuntimeError("CacheService is a singleton. Use get_instance() method.")
    
    @classmethod
    async def initialize(cls):
        """Initialize Redis connection pool with enterprise configuration"""
        if cls._redis_pool is not None:
            return
        
        # Parse Redis URL
        redis_url = settings.REDIS_URL
        
        # Create connection pool with performance optimizations
        cls._redis_pool = ConnectionPool.from_url(
            redis_url,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            retry_on_timeout=True,
            socket_keepalive=True,
            socket_keepalive_options={},
            health_check_interval=30,
            # Performance optimizations
            socket_connect_timeout=5,
            socket_timeout=5,
            decode_responses=False  # We'll handle JSON serialization manually
        )
        
        # Create Redis client
        cls._redis_client = redis.Redis(
            connection_pool=cls._redis_pool,
            decode_responses=False
        )
        
        # Test connection
        try:
            await cls._redis_client.ping()
            logger.info(
                "Redis cache service initialized",
                max_connections=settings.REDIS_MAX_CONNECTIONS,
                url=redis_url.split('@')[-1] if '@' in redis_url else redis_url  # Hide credentials
            )
        except Exception as e:
            logger.warning(f"Redis connection failed, falling back to in-memory cache: {str(e)}")
            # Use simple in-memory cache as fallback
            cls._redis_client = None
            cls._in_memory_cache = {}
    
    @classmethod
    def get_instance(cls) -> 'CacheService':
        """Get singleton instance of CacheService"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    @classmethod
    async def close(cls):
        """Close Redis connections"""
        if cls._redis_client:
            await cls._redis_client.close()
            cls._redis_client = None
        
        if cls._redis_pool:
            await cls._redis_pool.disconnect()
            cls._redis_pool = None
        
        logger.info("Redis cache service closed")
    
    async def ping(self) -> bool:
        """Health check for Redis connectivity"""
        try:
            if self._redis_client:
                await self._redis_client.ping()
                return True
            # In-memory cache is always available
            return hasattr(self.__class__, '_in_memory_cache')
        except Exception as e:
            logger.error(f"Redis ping failed: {str(e)}")
            return hasattr(self.__class__, '_in_memory_cache')
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        ttl: Optional[int] = None,
        nx: bool = False  # Set only if key doesn't exist
    ) -> bool:
        """Set key-value pair with optional TTL (optimized for performance)"""
        try:
            if self._redis_client:
                # Redis implementation
                # Serialize value with orjson for performance
                if isinstance(value, (dict, list)):
                    serialized_value = orjson.dumps(value)
                elif isinstance(value, str):
                    serialized_value = value.encode('utf-8')
                else:
                    serialized_value = str(value).encode('utf-8')
                
                # Set with options
                result = await self._redis_client.set(
                    key, 
                    serialized_value,
                    ex=ttl,  # Expiration in seconds
                    nx=nx
                )
                return bool(result)
            else:
                # In-memory cache fallback
                if nx and key in self.__class__._in_memory_cache:
                    return False
                
                # Store with timestamp for TTL support
                import time
                cache_item = {
                    'value': value,
                    'expires_at': time.time() + ttl if ttl else None
                }
                self.__class__._in_memory_cache[key] = cache_item
                return True
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {str(e)}")
            return False
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value by key with automatic deserialization"""
        try:
            if self._redis_client:
                # Redis implementation
                value = await self._redis_client.get(key)
                
                if value is None:
                    return default
                
                # Try to deserialize JSON, fallback to string
                try:
                    return orjson.loads(value)
                except orjson.JSONDecodeError:
                    # Return as string if not JSON
                    return value.decode('utf-8')
            else:
                # In-memory cache fallback
                import time
                if key not in self.__class__._in_memory_cache:
                    return default
                
                cache_item = self.__class__._in_memory_cache[key]
                
                # Check if expired
                if cache_item.get('expires_at') and time.time() > cache_item['expires_at']:
                    del self.__class__._in_memory_cache[key]
                    return default
                
                return cache_item['value']
                
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {str(e)}")
            return default
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            if self._redis_client:
                result = await self._redis_client.delete(key)
                return result > 0
            else:
                # In-memory cache fallback
                if key in self.__class__._in_memory_cache:
                    del self.__class__._in_memory_cache[key]
                    return True
                return False
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {str(e)}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            result = await self._redis_client.exists(key)
            return result > 0
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {str(e)}")
            return False
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key"""
        try:
            result = await self._redis_client.expire(key, ttl)
            return bool(result)
        except Exception as e:
            logger.error(f"Cache expire error for key {key}: {str(e)}")
            return False
    
    async def ttl(self, key: str) -> int:
        """Get remaining TTL for key (-1 = no expiry, -2 = key doesn't exist)"""
        try:
            return await self._redis_client.ttl(key)
        except Exception as e:
            logger.error(f"Cache TTL error for key {key}: {str(e)}")
            return -2
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter (atomic operation)"""
        try:
            result = await self._redis_client.incrby(key, amount)
            return result
        except Exception as e:
            logger.error(f"Cache increment error for key {key}: {str(e)}")
            return None
    
    async def decrement(self, key: str, amount: int = 1) -> Optional[int]:
        """Decrement counter (atomic operation)"""
        try:
            result = await self._redis_client.decrby(key, amount)
            return result
        except Exception as e:
            logger.error(f"Cache decrement error for key {key}: {str(e)}")
            return None
    
    async def set_hash(self, key: str, mapping: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Set hash map with optional TTL"""
        try:
            # Serialize hash values
            serialized_mapping = {}
            for field, value in mapping.items():
                if isinstance(value, (dict, list)):
                    serialized_mapping[field] = orjson.dumps(value)
                else:
                    serialized_mapping[field] = str(value)
            
            await self._redis_client.hset(key, mapping=serialized_mapping)
            
            if ttl:
                await self._redis_client.expire(key, ttl)
            
            return True
            
        except Exception as e:
            logger.error(f"Cache set_hash error for key {key}: {str(e)}")
            return False
    
    async def get_hash(self, key: str, field: Optional[str] = None) -> Any:
        """Get hash field or entire hash"""
        try:
            if field:
                # Get single field
                value = await self._redis_client.hget(key, field)
                if value:
                    try:
                        return orjson.loads(value)
                    except orjson.JSONDecodeError:
                        return value.decode('utf-8')
                return None
            else:
                # Get entire hash
                hash_data = await self._redis_client.hgetall(key)
                result = {}
                for k, v in hash_data.items():
                    try:
                        result[k.decode('utf-8')] = orjson.loads(v)
                    except orjson.JSONDecodeError:
                        result[k.decode('utf-8')] = v.decode('utf-8')
                return result
                
        except Exception as e:
            logger.error(f"Cache get_hash error for key {key}: {str(e)}")
            return None if field else {}
    
    async def add_to_set(self, key: str, *values: Any, ttl: Optional[int] = None) -> int:
        """Add values to set"""
        try:
            # Serialize values
            serialized_values = []
            for value in values:
                if isinstance(value, (dict, list)):
                    serialized_values.append(orjson.dumps(value))
                else:
                    serialized_values.append(str(value))
            
            result = await self._redis_client.sadd(key, *serialized_values)
            
            if ttl:
                await self._redis_client.expire(key, ttl)
            
            return result
            
        except Exception as e:
            logger.error(f"Cache add_to_set error for key {key}: {str(e)}")
            return 0
    
    async def get_set_members(self, key: str) -> List[Any]:
        """Get all members of a set"""
        try:
            members = await self._redis_client.smembers(key)
            result = []
            for member in members:
                try:
                    result.append(orjson.loads(member))
                except orjson.JSONDecodeError:
                    result.append(member.decode('utf-8'))
            return result
            
        except Exception as e:
            logger.error(f"Cache get_set_members error for key {key}: {str(e)}")
            return []
    
    async def is_in_set(self, key: str, value: Any) -> bool:
        """Check if value is in set"""
        try:
            # Serialize value for comparison
            if isinstance(value, (dict, list)):
                serialized_value = orjson.dumps(value)
            else:
                serialized_value = str(value)
            
            result = await self._redis_client.sismember(key, serialized_value)
            return bool(result)
            
        except Exception as e:
            logger.error(f"Cache is_in_set error for key {key}: {str(e)}")
            return False
    
    async def push_to_list(self, key: str, *values: Any, ttl: Optional[int] = None, left: bool = True) -> int:
        """Push values to list (left or right)"""
        try:
            # Serialize values
            serialized_values = []
            for value in values:
                if isinstance(value, (dict, list)):
                    serialized_values.append(orjson.dumps(value))
                else:
                    serialized_values.append(str(value))
            
            if left:
                result = await self._redis_client.lpush(key, *serialized_values)
            else:
                result = await self._redis_client.rpush(key, *serialized_values)
            
            if ttl:
                await self._redis_client.expire(key, ttl)
            
            return result
            
        except Exception as e:
            logger.error(f"Cache push_to_list error for key {key}: {str(e)}")
            return 0
    
    async def get_list_range(self, key: str, start: int = 0, end: int = -1) -> List[Any]:
        """Get range of list elements"""
        try:
            items = await self._redis_client.lrange(key, start, end)
            result = []
            for item in items:
                try:
                    result.append(orjson.loads(item))
                except orjson.JSONDecodeError:
                    result.append(item.decode('utf-8'))
            return result
            
        except Exception as e:
            logger.error(f"Cache get_list_range error for key {key}: {str(e)}")
            return []
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics"""
        try:
            info = await self._redis_client.info()
            return {
                "connected_clients": info.get("connected_clients", 0),
                "used_memory": info.get("used_memory", 0),
                "used_memory_human": info.get("used_memory_human", "0B"),
                "hit_rate": info.get("keyspace_hit_rate", 0),
                "total_commands_processed": info.get("total_commands_processed", 0),
                "instantaneous_ops_per_sec": info.get("instantaneous_ops_per_sec", 0),
                "uptime_in_seconds": info.get("uptime_in_seconds", 0)
            }
        except Exception as e:
            logger.error(f"Cache stats error: {str(e)}")
            return {}


# Singleton pattern helpers
async def get_cache() -> CacheService:
    """Get cache service instance"""
    return CacheService.get_instance()


# Cache decorators for performance optimization
def cache_result(key_prefix: str, ttl: int = 300):
    """Decorator to cache function results"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{key_prefix}:{hash(str(args) + str(sorted(kwargs.items())))}"
            
            cache = CacheService.get_instance()
            
            # Try to get from cache
            cached_result = await cache.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache.set(cache_key, result, ttl=ttl)
            
            return result
        
        return wrapper
    return decorator