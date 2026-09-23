The user wants me to extend the implementation to handle both synchronous and asynchronous operations. They've provided a code snippet with various classes and functions for storage abstraction (FileStorage, DatabaseStorage, StorageManager, etc.) that already has some sync/async handling, but perhaps they want me to extend it further.

Let me analyze the current code:

1. `run_sync_or_async` - runs a function whether it's sync or async
2. `async_to_sync` - converts async function to sync
3. `sync_to_async` - converts sync function to async
4. `SyncAsyncWrapper` - wraps a function to support both sync and async calls
5. `StorageBase` - base class with sync methods and async wrappers
6. `FileStorage` - file-based storage
7. `DatabaseStorage` - SQLite storage
8. `StorageManager` - manager that delegates to storage
9. `create_storage` - factory function
10. `run_sync_or_async_storage` - helper

The code already has quite a bit of sync/async support. But the task says "Extend this implementation to handle both synchronous and asynchronous operations." 

Looking more carefully, there might be some issues/limitations to extend:

1. The `StorageManager.get_sync()` and `get_async()` methods return tuples of `SyncAsyncWrapper` objects, but they seem awkward. Maybe they should return a wrapper object that has both sync and async methods.

2. The `StorageBase` async methods use `asyncio.to_thread` which is good, but they don't handle the case where a subclass overrides async methods.

3. Maybe I should create a more unified interface where both sync and async operations can be performed through a single wrapper.

4. The `run_sync_or_async` function uses `asyncio.run` which cannot be called from within a running event loop. This is a limitation.

Let me think about what "extend" means here. The user wants me to return the full extended code. I should:

- Keep the existing functionality
- Extend it to handle both sync and async operations more robustly
- Maybe add a unified wrapper class that provides both sync and async methods
- Fix the `get_sync`/`get_async` to be more useful
- Add proper handling for async storage backends

Let me design a comprehensive solution:

1. Keep `run_sync_or_async` but make it smarter - if there's a running event loop, use `asyncio.ensure_future` or similar.
2. Add a `StorageBackend` protocol/ABC.
3. Create a unified `Storage` class that wraps a backend and provides both sync and async APIs.
4. Ensure `FileStorage` and `DatabaseStorage` work both sync and async.
5. Maybe add a `MemoryStorage` for completeness.

Actually, let me re-read the requirements: "Extend this implementation to handle both synchronous and asynchronous operations."

The current implementation already has some of this. I think the key improvements are:

1. Make `SyncAsyncWrapper` more robust - handle both sync and async functions, allow calling from both sync and async contexts.
2. Fix `run_sync_or_async` to handle running in an event loop.
3. Add a unified `Storage` class that provides both sync and async methods.
4. Update `StorageManager` to expose both sync and async methods more cleanly.
5. Ensure all storage backends work with both.

Let me write the extended code. I'll keep the original structure but enhance it:

- Add a `run_coroutine` helper that can be called from sync or async context.
- Enhance `SyncAsyncWrapper` to support both sync/async calls and context manager.
- Add a `Storage` class that wraps a backend and provides both sync and async methods.
- Update `StorageManager` to use the new `Storage` class.
- Add `MemoryStorage` for completeness.
- Make `DatabaseStorage` use a thread-local connection or a lock for thread safety.

Wait, the instructions say "Do not include any explanations, prose, or Markdown outside the code block." and "Do not include any comments in or outside the code block." and "Return ONLY the code."

So I should return just the Python code in a code block, with no comments.

Let me write the extended implementation:

```python
import asyncio
import inspect
import json
import os
import sqlite3
import threading
from functools import wraps
from pathlib import Path
from typing import Any, Optional, Union

def run_sync_or_async(func, *args, **kwargs):
    result = func(*args, **kwargs)
    if asyncio.iscoroutine(result):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(result)
        else:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(result)
    return result

def async_to_sync(async_func):
    @wraps(async_func)
    def wrapper(*args, **kwargs):
        result = async_func(*args, **kwargs)
        if asyncio.iscoroutine(result):
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(result)
            else:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(result)
        return result
    return wrapper

def sync_to_async(sync_func):
    @wraps(sync_func)
    async def wrapper(*args, **kwargs):
        return await asyncio.to_thread(sync_func, *args, **kwargs)
    return wrapper

class SyncAsyncWrapper:
    def __init__(self, func):
        self._func = func
        self.is_async = asyncio.iscoroutinefunction(func)

    def call(self, *args, **kwargs):
        if self.is_async:
            coro = self._func(*args, **kwargs)
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(coro)
            else:
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(coro)
        return self._func(*args, **kwargs)

    async def acall(self, *args, **kwargs):
        if self.is_async:
            return await self._func(*args, **kwargs)
        return await asyncio.to_thread(self._func, *args, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.acall(*args, **kwargs) if self.is_async else self.call(*args, **kwargs)

class StorageBase:
    def __init__(self, location: Union[str, Path, None] = None):
        self.location = location

    def save(self, key: str, value: Any) -> None:
        raise NotImplementedError

    def load(self, key: str) -> Any:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        raise NotImplementedError

    async def asave(self, key: str, value: Any) -> None:
        return await asyncio.to_thread(self.save, key, value)

    async def aload(self, key: str) -> Any:
        return await asyncio.to_thread(self.load, key)

    async def adelete(self, key: str) -> None:
        return await asyncio.to_thread(self.delete, key)

    async def aexists(self, key: str) -> bool:
        return await asyncio.to_thread(self.exists, key)

class FileStorage(StorageBase):
    def __init__(self, directory: Union[str, Path] = "storage"):
        super().__init__(directory)
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str) -> Path:
        safe_key = str(key).replace("/", "_").replace("\\", "_")
        return self.directory / f"{safe_key}.json"

    def save(self, key: str, value: Any) -> None:
        path = self._path_for(key)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(value, f)

    def load(self, key: str) -> Any:
        path = self._path_for(key)
        if not path.exists():
            raise KeyError(key)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def delete(self, key: str) -> None:
        path = self._path_for(key)
        if not path.exists():
            raise KeyError(key)
        path.unlink()

    def exists(self, key: str) -> bool:
        return self._path_for(key).exists()

class DatabaseStorage(StorageBase):
    def __init__(self, db_path: Union[str, Path] = "storage.db"):
        super().__init__(db_path)
        self.db_path = str(db_path)
        self._local = threading.local()
        self._init_db()

    def _get_connection(self):
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS storage (key TEXT PRIMARY KEY, value TEXT)")

    def save(self, key: str, value: Any) -> None:
        serialized = json.dumps(value)
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO storage (key, value) VALUES (?, ?)",
                (key, serialized)
            )

    def load(self, key: str) -> Any:
        conn = self._get_connection()
        row = conn.execute("SELECT value FROM storage WHERE key = ?", (key,)).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row["value"])

    def delete(self, key: str) -> None:
        conn = self._get_connection()
        cursor = conn.execute("DELETE FROM storage WHERE key = ?", (key,))
        if cursor.rowcount == 0:
            raise KeyError(key)

    def exists(self, key: str) -> bool:
        conn = self._get_connection()
        row = conn.execute("SELECT 1 FROM storage WHERE key = ?", (key,)).fetchone()
        return row is not None

    def close(self):
        if hasattr(self._local, "conn"):
            self._local.conn.close()
            del self._local.conn

class MemoryStorage(StorageBase):
    def __init__(self):
        super().__init__()
        self._data = {}
        self._lock = asyncio.Lock()

    def save(self, key: str, value: Any) -> None:
        self._data[key] = value

    def load(self, key: str) -> Any:
        if key not in self._data:
            raise KeyError(key)
        return self._data[key]

    def delete(self, key: str) -> None:
        if key not in self._data:
            raise KeyError(key)
        del self._data[key]

    def exists(self, key: str) -> bool:
        return key in self._data

    async def asave(self, key: str, value: Any) -> None:
        async with self._lock:
            self._data[key] = value

    async def aload(self, key: str) -> Any:
        async with self._lock:
            if key not in self._data:
                raise KeyError(key)
            return self._data[key]

    async def adelete(self, key: str) -> None:
        async with self._lock:
            if key not in self._data:
                raise KeyError(key)
            del self._data[key]

    async def aexists(self, key: str) -> bool:
        async with self._lock:
            return key in self._data

class Storage:
    def __init__(self, storage: Optional[StorageBase] = None):
        self._storage = storage if storage is not None else FileStorage()
        self.save = SyncAsyncWrapper(self._storage.save)
        self.load = SyncAsyncWrapper(self._storage.load)
        self.delete = SyncAsyncWrapper(self._storage.delete)
        self.exists = SyncAsyncWrapper(self._storage.exists)
        self.asave = self._storage.asave
        self.aload = self._storage.aload
        self.adelete = self._storage.adelete
        self.aexists = self._storage.aexists

    def __getattr__(self, item):
        return getattr(self._storage, item)

class StorageManager:
    def __init__(self, storage: Optional[StorageBase] = None):
        self.storage = storage if storage is not None else FileStorage()

    def save(self, key: str, value: Any) -> None:
        return self.storage.save(key, value)

    def load(self, key: str) -> Any:
        return self.storage.load(key)

    def delete(self, key: str) -> None:
        return self.storage.delete(key)

    def exists(self, key: str) -> bool:
        return self.storage.exists(key)

    async def asave(self, key: str, value: Any) -> None:
        return await self.storage.asave(key, value)

    async def aload(self, key: str) -> Any:
        return await self.storage.aload(key)

    async def adelete(self, key: str) -> None:
        return await self.storage.adelete(key)

    async def aexists(self, key: str) -> bool:
        return await self.storage.aexists(key)

    def get_sync(self):
        return Storage(self.storage)

    def get_async(self):
        return Storage(self.storage)

    def unified(self):
        return Storage(self.storage)

def create_storage(storage_type: str, location: Optional[str] = None) -> StorageBase:
    if storage_type == "file":
        return FileStorage(location) if location else FileStorage()
    elif storage_type == "database":
        return DatabaseStorage(location) if location else DatabaseStorage()
    elif storage_type == "memory":
        return MemoryStorage()
    else:
        raise ValueError(f"Unknown storage type: {storage_type}")

def run_sync_or_async_storage(storage: StorageBase, method: str, *args, **kwargs):
    func = getattr(storage, method)
    return run_sync_or_async(func, *args, **kwargs)

if __name__ == "__main__":
    file_storage = FileStorage("data")
    file_storage.save("user1", {"name": "Alice", "age": 30})
    print(file_storage.load("user1"))
    print(file_storage.exists("user1"))
    file_storage.delete("user1")

    db_storage = DatabaseStorage("mydb.db")
    db_storage.save("user2", {"name": "Bob", "age": 25})
    print(db_storage.load("user2"))
    print(db_storage.exists("user2"))

    async def async_demo():
        await db_storage.asave("user3", {"name": "Carol"})
        data = await db_storage.aload("user3")
        print(data)
        await db_storage.adelete("user3")
        print(await db_storage.aexists("user3"))

    asyncio.run(async_demo())

    storage = create_storage("database", "example.db")
    storage.save("key", "value")
    print(storage.load("key"))
```

Hmm, but I'm not entirely sure this is what they want. Let me re-read the prompt.

"Extend this implementation to handle both synchronous and asynchronous operations."

The current implementation already has both sync and async methods. Maybe the user wants me to:

1. Make the `StorageManager` support both sync and async in a more unified way.
2. Add a decorator or wrapper that automatically provides both sync and async versions.
3. Ensure that the async methods actually run in a thread pool to avoid blocking.

Let me think about the best design for this. The user says "extend this implementation" - so I should keep the existing code and add more functionality.

Key enhancements I can make:

1. **Unified interface**: Create a class that exposes both sync and async methods for all operations.
2. **Automatic thread handling**: Use `asyncio.to_thread` for sync methods called from async context, and `asyncio.run` for async methods called from sync context.
3. **Context manager support**: Add `__enter__`/`__exit__` and `__aenter__`/`__aexit__`.
4. **Better `SyncAsyncWrapper`**: Make it work as a decorator and handle both sync and async functions.
5. **A `StorageAdapter` or `DualStorage` class** that can be used interchangeably.

Let me design this more carefully.

I'll create a comprehensive solution:

```python
import asyncio
import inspect
import json
import os
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any, Optional, Union
```

Then define:
- `run_sync_or_async` - improved to handle running in event loop
- `async_to_sync` - improved
- `sync_to_async` - improved
- `SyncAsyncWrapper` - improved to handle both sync and async
- `StorageBase` - keep as is
- `FileStorage` - keep as is
- `DatabaseStorage` - keep as is but maybe improve threading
- `StorageManager` - enhance with both sync and async methods
- Add a `DualStorage` class that provides both sync and async interfaces

Actually, let me look at the existing `SyncAsyncWrapper` again:

```python
class SyncAsyncWrapper:
    def __init__(self, func):
        self._func = func
        self.is_async = asyncio.iscoroutinefunction(func)

    def call(self, *args, **kwargs):
        if self.is_async:
            return asyncio.run(self._func(*args, **kwargs))
        return self._func(*args, **kwargs)

    async def acall(self, *args, **kwargs):
        if self.is_async:
            return await self._func(*args, **kwargs)
        return await asyncio.to_thread(self._func, *args, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.call(*args, **kwargs)
```

Issues:
1. If `self.is_async` is True, `__call__` calls `call` which uses `asyncio