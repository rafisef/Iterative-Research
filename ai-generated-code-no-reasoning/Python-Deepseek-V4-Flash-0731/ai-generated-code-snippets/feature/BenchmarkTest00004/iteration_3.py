import asyncio
import inspect
import json
import os
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any, Optional, Union

def run_sync_or_async(func, *args, **kwargs):
    if asyncio.iscoroutinefunction(func):
        return asyncio.run(func(*args, **kwargs))
    result = func(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result

def async_to_sync(async_func):
    @wraps(async_func)
    def wrapper(*args, **kwargs):
        return asyncio.run(async_func(*args, **kwargs))
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
            return asyncio.run(self._func(*args, **kwargs))
        return self._func(*args, **kwargs)

    async def acall(self, *args, **kwargs):
        if self.is_async:
            return await self._func(*args, **kwargs)
        return await asyncio.to_thread(self._func, *args, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.call(*args, **kwargs)

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
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

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
        with self._get_connection() as conn:
            row = conn.execute("SELECT value FROM storage WHERE key = ?", (key,)).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row["value"])

    def delete(self, key: str) -> None:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM storage WHERE key = ?", (key,))
        if cursor.rowcount == 0:
            raise KeyError(key)

    def exists(self, key: str) -> bool:
        with self._get_connection() as conn:
            row = conn.execute("SELECT 1 FROM storage WHERE key = ?", (key,)).fetchone()
        return row is not None

    def close(self):
        pass

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
        return SyncAsyncWrapper(self.save), SyncAsyncWrapper(self.load), SyncAsyncWrapper(self.delete), SyncAsyncWrapper(self.exists)

    async def get_async(self):
        return SyncAsyncWrapper(self.asave), SyncAsyncWrapper(self.aload), SyncAsyncWrapper(self.adelete), SyncAsyncWrapper(self.aexists)

def create_storage(storage_type: str, location: Optional[str] = None) -> StorageBase:
    if storage_type == "file":
        return FileStorage(location) if location else FileStorage()
    elif storage_type == "database":
        return DatabaseStorage(location) if location else DatabaseStorage()
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