'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import os
import json
import sqlite3
import logging

logger = logging.getLogger(__name__)

def get_config():
    config = {
        "STORAGE_TYPE": os.environ.get("STORAGE_TYPE", "database"),
        "FILE_STORAGE_PATH": os.environ.get("FILE_STORAGE_PATH", "/tmp/benchmark_storage"),
        "COOKIE_MAX_AGE": int(os.environ.get("COOKIE_MAX_AGE", str(60 * 3))),
        "COOKIE_SECURE": os.environ.get("COOKIE_SECURE", "true").lower() == "true",
        "COOKIE_DOMAIN": os.environ.get("COOKIE_DOMAIN", "localhost"),
        "COOKIE_NAME": os.environ.get("COOKIE_NAME", "BenchmarkTest00011"),
        "COOKIE_DEFAULT_VALUE": os.environ.get("COOKIE_DEFAULT_VALUE", "noCookieValueSupplied"),
        "DB_DEFAULT_USERNAME": os.environ.get("DB_DEFAULT_USERNAME", "admin"),
        "DB_DEFAULT_PASSWORD": os.environ.get("DB_DEFAULT_PASSWORD", "admin123"),
        "ALLOW_STORAGE_OVERRIDE": os.environ.get("ALLOW_STORAGE_OVERRIDE", "true").lower() == "true",
        "MAX_WRITE_USERNAME_LENGTH": int(os.environ.get("MAX_WRITE_USERNAME_LENGTH", "255")),
        "MAX_WRITE_PASSWORD_LENGTH": int(os.environ.get("MAX_WRITE_PASSWORD_LENGTH", "255")),
        "USERS_FILENAME": os.environ.get("USERS_FILENAME", "users.json"),
        "BENCHMARK_ROUTE_PREFIX": os.environ.get("BENCHMARK_ROUTE_PREFIX", "/benchmark/sqli-00"),
        "BENCHMARK_TEST_NAME": os.environ.get("BENCHMARK_TEST_NAME", "BenchmarkTest00011"),
        "DB_PATH": os.environ.get("DB_PATH", "/tmp/benchmark_storage/benchmark.db"),
        "DB_POOL_SIZE": int(os.environ.get("DB_POOL_SIZE", "5")),
        "FILE_BACKUP_ENABLED": os.environ.get("FILE_BACKUP_ENABLED", "false").lower() == "true",
        "FILE_BACKUP_PATH": os.environ.get("FILE_BACKUP_PATH", "/tmp/benchmark_storage/backup"),
        "DB_SEED_USER1": os.environ.get("DB_SEED_USER1", "user1"),
        "DB_SEED_PASS1": os.environ.get("DB_SEED_PASS1", "password1"),
        "DB_SEED_USER2": os.environ.get("DB_SEED_USER2", "user2"),
        "DB_SEED_PASS2": os.environ.get("DB_SEED_PASS2", "password2"),
    }
    return config

CONFIG = get_config()
STORAGE_TYPE = CONFIG["STORAGE_TYPE"]
FILE_STORAGE_PATH = CONFIG["FILE_STORAGE_PATH"]

class StorageError(Exception):
    pass

class FileStorageError(StorageError):
    pass

class DatabaseStorageError(StorageError):
    pass

def ensure_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def get_default_seed_data(config):
    return [
        {"username": config["DB_DEFAULT_USERNAME"], "password": config["DB_DEFAULT_PASSWORD"]},
        {"username": config["DB_SEED_USER1"], "password": config["DB_SEED_PASS1"]},
        {"username": config["DB_SEED_USER2"], "password": config["DB_SEED_PASS2"]},
    ]

def load_file_data(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return None

def save_file_data(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

def backup_file_data(file_path, backup_path, filename):
    import shutil
    import time
    ensure_directory(backup_path)
    timestamp = int(time.time())
    backup_file = os.path.join(backup_path, f"{timestamp}_{filename}")
    if os.path.exists(file_path):
        shutil.copy2(file_path, backup_file)

def initialize_file_storage(config):
    storage_path = config["FILE_STORAGE_PATH"]
    ensure_directory(storage_path)
    file_path = os.path.join(storage_path, config["USERS_FILENAME"])
    if not os.path.exists(file_path):
        default_data = get_default_seed_data(config)
        save_file_data(file_path, default_data)
        return True
    return False

def read_from_file(param):
    config = get_config()
    result = ""
    try:
        storage_path = config["FILE_STORAGE_PATH"]
        ensure_directory(storage_path)
        file_path = os.path.join(storage_path, config["USERS_FILENAME"])
        data = load_file_data(file_path)
        if data is None:
            default_data = get_default_seed_data(config)
            save_file_data(file_path, default_data)
            result += "<br>File storage initialized with default data. No matching records found.<br>"
            return result
        matches = [entry["username"] for entry in data if entry.get("password") == param]
        if matches:
            result += f"<br>Results for query: SELECT username from USERS where password = '{param}'<br>"
            for username in matches:
                result += f"username: {username}<br>"
        else:
            result += f"<br>No results found for query: SELECT username from USERS where password = '{param}'<br>"
    except json.JSONDecodeError as e:
        raise FileStorageError(f"Corrupted file storage: {str(e)}")
    except PermissionError as e:
        raise FileStorageError(f"File permission error: {str(e)}")
    except Exception as e:
        raise FileStorageError(f"File storage error: {str(e)}")
    return result

def read_from_database(param):
    result = ""
    try:
        import helpers.db_sqlite
        sql = f'SELECT username from USERS where password = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (param,))
        result += helpers.db_sqlite.results(cur, sql)
        con.close()
    except Exception as e:
        raise DatabaseStorageError(f"Database read error: {str(e)}")
    return result

def write_to_file(username, password):
    config = get_config()
    result = ""
    try:
        storage_path = config["FILE_STORAGE_PATH"]
        ensure_directory(storage_path)
        file_path = os.path.join(storage_path, config["USERS_FILENAME"])
        if config["FILE_BACKUP_ENABLED"]:
            backup_file_data(file_path, config["FILE_BACKUP_PATH"], config["USERS_FILENAME"])
        data = load_file_data(file_path)
        if data is None:
            data = get_default_seed_data(config)
        existing_usernames = [entry["username"] for entry in data]
        if username in existing_usernames:
            for entry in data:
                if entry["username"] == username:
                    entry["password"] = password
            result += "<br>Record updated in file storage successfully.<br>"
        else:
            data.append({"username": username, "password": password})
            result += "<br>Record written to file storage successfully.<br>"
        save_file_data(file_path, data)
    except json.JSONDecodeError as e:
        raise FileStorageError(f"Corrupted file storage: {str(e)}")
    except PermissionError as e:
        raise FileStorageError(f"File permission error: {str(e)}")
    except Exception as e:
        raise FileStorageError(f"File storage write error: {str(e)}")
    return result

def write_to_database(username, password):
    result = ""
    try:
        import helpers.db_sqlite
        check_sql = 'SELECT COUNT(*) FROM USERS WHERE username = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(check_sql, (username,))
        count = cur.fetchone()[0]
        if count > 0:
            sql = 'UPDATE USERS SET password = ? WHERE username = ?'
            cur.execute(sql, (password, username))
            result += "<br>Record updated in database storage successfully.<br>"
        else:
            sql = 'INSERT INTO USERS (username, password) VALUES (?, ?)'
            cur.execute(sql, (username, password))
            result += "<br>Record written to database storage successfully.<br>"
        con.commit()
        con.close()
    except sqlite3.IntegrityError as e:
        raise DatabaseStorageError(f"Database integrity error: {str(e)}")
    except sqlite3.OperationalError as e:
        raise DatabaseStorageError(f"Database operational error: {str(e)}")
    except Exception as e:
        raise DatabaseStorageError(f"Database write error: {str(e)}")
    return result

def delete_from_file(username):
    config = get_config()
    result = ""
    try:
        storage_path = config["FILE_STORAGE_PATH"]
        ensure_directory(storage_path)
        file_path = os.path.join(storage_path, config["USERS_FILENAME"])
        data = load_file_data(file_path)
        if data is None:
            result += "<br>No file storage found. Nothing to delete.<br>"
            return result
        if config["FILE_BACKUP_ENABLED"]:
            backup_file_data(file_path, config["FILE_BACKUP_PATH"], config["USERS_FILENAME"])
        original_count = len(data)
        data = [entry for entry in data if entry.get("username") != username]
        if len(data) < original_count:
            save_file_data(file_path, data)
            result += "<br>Record deleted from file storage successfully.<br>"
        else:
            result += "<br>No matching record found to delete in file storage.<br>"
    except Exception as e:
        raise FileStorageError(f"File storage delete error: {str(e)}")
    return result

def delete_from_database(username):
    result = ""
    try:
        import helpers.db_sqlite
        sql = 'DELETE FROM USERS WHERE username = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (username,))
        rows_affected = cur.rowcount
        con.commit()
        if rows_affected > 0:
            result += "<br>Record deleted from database storage successfully.<br>"
        else:
            result += "<br>No matching record found to delete in database storage.<br>"
        con.close()
    except Exception as e:
        raise DatabaseStorageError(f"Database delete error: {str(e)}")
    return result

def list_from_file():
    config = get_config()
    result = ""
    try:
        storage_path = config["FILE_STORAGE_PATH"]
        ensure_directory(storage_path)
        file_path = os.path.join(storage_path, config["USERS_FILENAME"])
        data = load_file_data(file_path)
        if data is None:
            result += "<br>No file storage found.<br>"
            return result
        if data:
            result += "<br>All records in file storage:<br>"
            for entry in data:
                result += f"username: {escape_for_html(entry.get('username', ''))}<br>"
        else:
            result += "<br>File storage is empty.<br>"
    except Exception as e:
        raise FileStorageError(f"File storage list error: {str(e)}")
    return result

def list_from_database():
    result = ""
    try:
        import helpers.db_sqlite
        sql = 'SELECT username FROM USERS'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        if rows:
            result += "<br>All records in database storage:<br>"
            for row in rows:
                result += f"username: {escape_for_html(row[0])}<br>"
        else:
            result += "<br>Database storage is empty.<br>"
        con.close()
    except Exception as e:
        raise DatabaseStorageError(f"Database list error: {str(e)}")
    return result

def get_storage_stats_file():
    config = get_config()
    stats = {
        "type": "file",
        "path": config["FILE_STORAGE_PATH"],
        "filename": config["USERS_FILENAME"],
        "record_count": 0,
        "file_size_bytes": 0,
        "backup_enabled": config["FILE_BACKUP_ENABLED"],
    }
    try:
        file_path = os.path.join(config["FILE_STORAGE_PATH"], config["USERS_FILENAME"])
        if os.path.exists(file_path):
            stats["file_size_bytes"] = os.path.getsize(file_path)
            data = load_file_data(file_path)
            if data:
                stats["record_count"] = len(data)
    except Exception:
        pass
    return stats

def get_storage_stats_database():
    stats = {
        "type": "database",
        "record_count": 0,
    }
    try:
        import helpers.db_sqlite
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM USERS")
        stats["record_count"] = cur.fetchone()[0]
        con.close()
    except Exception:
        pass
    return stats

def handle_storage_operation(operation, storage_type, **kwargs):
    result = ""
    try:
        if operation == "read":
            if storage_type == "file":
                result += read_from_file(kwargs.get("param", ""))
            else:
                result += read_from_database(kwargs.get("param", ""))
        elif operation == "write":
            if storage_type == "file":
                result += write_to_file(kwargs.get("username", ""), kwargs.get("password", ""))
            else:
                result += write_to_database(kwargs.get("username", ""), kwargs.get("password", ""))
        elif operation == "delete":
            if storage_type == "file":
                result += delete_from_file(kwargs.get("username", ""))
            else:
                result += delete_from_database(kwargs.get("username", ""))
        elif operation == "list":
            if storage_type == "file":
                result += list_from_file()
            else:
                result += list_from_database()
    except FileStorageError as e:
        result += f"<br>File storage error: {escape_for_html