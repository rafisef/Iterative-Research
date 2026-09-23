import asyncio
import inspect
from functools import wraps

def run_sync_or_async(func, *args, **kwargs):
    """Execute a callable that may be sync or async, returning its result."""
    if asyncio.iscoroutinefunction(func):
        return asyncio.run(func(*args, **kwargs))
    result = func(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result

def async_to_sync(async_func):
    """Convert an async function to a sync function using asyncio.run."""
    @wraps(async_func)
    def wrapper(*args, **kwargs):
        return asyncio.run(async_func(*args, **kwargs))
    return wrapper

def sync_to_async(sync_func):
    """Convert a sync function to an async function using asyncio.to_thread."""
    @wraps(sync_func)
    async def wrapper(*args, **kwargs):
        return await asyncio.to_thread(sync_func, *args, **kwargs)
    return wrapper

class SyncAsyncWrapper:
    """Wrap a callable to provide both synchronous and asynchronous interfaces."""
    def __init__(self, func):
        self._func = func
        self.is_async = asyncio.iscoroutinefunction(func)

    def call(self, *args, **kwargs):
        """Synchronous call."""
        if self.is_async:
            return asyncio.run(self._func(*args, **kwargs))
        return self._func(*args, **kwargs)

    async def acall(self, *args, **kwargs):
        """Asynchronous call."""
        if self.is_async:
            return await self._func(*args, **kwargs)
        return await asyncio.to_thread(self._func, *args, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.call(*args, **kwargs)

# Example usage:
if __name__ == "__main__":
    def sync_add(a, b):
        return a + b

    async def async_add(a, b):
        await asyncio.sleep(0.1)
        return a + b

    print(run_sync_or_async(sync_add, 1, 2))   # 3
    print(run_sync_or_async(async_add, 3, 4))  # 7

    wrapped_sync = SyncAsyncWrapper(sync_add)
    wrapped_async = SyncAsyncWrapper(async_add)

    print(wrapped_sync.call(5, 6))             # 11
    print(asyncio.run(wrapped_async.acall(7, 8)))  # 15

    # Convert between sync and async
    sync_from_async = async_to_sync(async_add)
    async_from_sync = sync_to_async(sync_add)

    print(sync_from_async(9, 10))              # 19
    print(asyncio.run(async_from_sync(11, 12))) # 23