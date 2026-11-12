import os
import pathlib
import sqlite3
from werkzeug.security import generate_password_hash


def get_db_path() -> str:
    return os.environ.get("DB_PATH", "demo.sqlite3")


def init_db(db_path: str | None = None) -> None:
    """Initialize SQLite schema and seed demo users with hashed passwords."""
    target_path = db_path or get_db_path()
    pathlib.Path(target_path).unlink(missing_ok=True)
    conn = sqlite3.connect(target_path)
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        demo_users = [
            ("alice", generate_password_hash("alice123", method="pbkdf2:sha256")),
            ("bob", generate_password_hash("bob12345", method="pbkdf2:sha256")),
        ]
        cur.executemany("INSERT INTO users(username, password) VALUES (?, ?)", demo_users)

        demo_posts = [
            ("Welcome", "This is a demo post."),
            ("Security Tips", "Never trust user input. Use parameterized queries."),
        ]
        cur.executemany("INSERT INTO posts(title, body) VALUES (?, ?)", demo_posts)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    path = get_db_path()
    init_db(path)
    print(f"Initialized SQLite DB at {path}")
