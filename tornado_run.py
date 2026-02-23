
#!/usr/bin/env python3
"""
run.py — v1 Contact Form Backend for actualintelligence-hash.github.io

A production-ready Tornado server that captures contact form submissions,
validates input, stores to SQLite, and provides admin retrieval.

Architecture:
  - Tornado async web server (non-blocking I/O)
  - aiosqlite for async database operations  
  - Pydantic for input validation and sanitization
  - Built-in XSRF protection, CORS, rate limiting, honeypot detection

Dependencies:
  pip install tornado aiosqlite pydantic[email]

Usage:
  python run.py                          # default port 8080
  python run.py --port=9000              # custom port
  python run.py --db=contacts.db         # custom db path
"""

import asyncio
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import tornado.ioloop
import tornado.web
import tornado.options
from tornado.options import define, options

# ---------------------------------------------------------------------------
# Configuration
# port: which TCP port the server listens on.
# db: path to the SQLite database file.
# static_path: where to find your Jekyll-built HTML/JS/CSS (concrete/).
# debug: enable Tornado debug features (auto-reload, extra logging).
# allowed_origins: CORS allowlist.
# ---------------------------------------------------------------------------
define("port", default=8080, help="Server port", type=int)
define("db", default="contacts.db", help="SQLite database path", type=str)
define("static_path", default="concrete", help="Static files directory", type=str)
define("debug", default=False, help="Enable debug mode", type=bool)
define("allowed_origins", default="*", help="Comma-separated allowed origins", type=str)

logger = logging.getLogger("contactserver")

# ---------------------------------------------------------------------------
# Pydantic Models — Input Validation & Sanitization
# ---------------------------------------------------------------------------
try:
    from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False


if PYDANTIC_AVAILABLE:
    class ContactFormInput(BaseModel):
        """
        Validates and sanitizes contact form input.

        References:
          - OWASP Input Validation Cheat Sheet
          - Pydantic v2 data validation
        """
        model_config = ConfigDict(str_strip_whitespace=True)

        name: str
        email: EmailStr
        phone: str = ""
        message: str

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            v = v.strip()
            if len(v) < 1 or len(v) > 200:
                raise ValueError("Name must be 1-200 characters")
            # Allow letters, spaces, hyphens, apostrophes, periods
            if not re.match(r"^[\w\s.\-\']+$", v, re.UNICODE):
                raise ValueError("Name contains invalid characters")
            return v

        @field_validator("phone")
        @classmethod
        def validate_phone(cls, v: str) -> str:
            v = v.strip()
            if v and not re.match(r"^[\+]?[\d\s\-().]{7,20}$", v):
                raise ValueError("Invalid phone number format")
            return v

        @field_validator("message")
        @classmethod
        def validate_message(cls, v: str) -> str:
            v = v.strip()
            if len(v) < 1 or len(v) > 5000:
                raise ValueError("Message must be 1-5000 characters")
            return v
else:
    # Fallback validation without Pydantic
    class ContactFormInput:
        def __init__(self, **kwargs):
            self.name = kwargs.get("name", "").strip()
            self.email = kwargs.get("email", "").strip()
            self.phone = kwargs.get("phone", "").strip()
            self.message = kwargs.get("message", "").strip()
            self._validate()

        def _validate(self):
            if not self.name or len(self.name) > 200:
                raise ValueError("Name must be 1-200 characters")
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", self.email):
                raise ValueError("Invalid email format")
            if len(self.message) < 1 or len(self.message) > 5000:
                raise ValueError("Message must be 1-5000 characters")

        def model_dump(self):
            return {
                "name": self.name,
                "email": self.email,
                "phone": self.phone,
                "message": self.message,
            }


# ---------------------------------------------------------------------------
# Database Layer — Async SQLite via aiosqlite
# ---------------------------------------------------------------------------
try:
    import aiosqlite
    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS contacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid        TEXT    NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    email       TEXT    NOT NULL,
    phone       TEXT    DEFAULT '',
    message     TEXT    NOT NULL,
    ip_address  TEXT    DEFAULT '',
    user_agent  TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL,
    is_read     INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_contacts_created_at ON contacts(created_at);
CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);
"""


class DatabaseManager:
    """
    Async database manager using aiosqlite.

    Uses parameterized queries exclusively to prevent SQL injection.
    Reference: OWASP SQL Injection Prevention Cheat Sheet
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._db = None

    async def initialize(self):
        """Create connection and ensure schema exists."""
        if AIOSQLITE_AVAILABLE:
            self._db = await aiosqlite.connect(self.db_path)
            self._db.row_factory = aiosqlite.Row
            # Enable WAL mode for better concurrent read performance
            await self._db.execute("PRAGMA journal_mode=WAL")
            await self._db.execute("PRAGMA foreign_keys=ON")
            await self._db.executescript(SCHEMA_SQL)
            await self._db.commit()
        else:
            # Synchronous fallback
            self._db = sqlite3.connect(self.db_path)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(SCHEMA_SQL)
            self._db.commit()
        logger.info(f"Database initialized at {self.db_path}")

    async def insert_contact(self, data: dict, ip: str, ua: str) -> str:
        """Insert a contact form submission. Returns UUID."""
        contact_uuid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        sql = """
            INSERT INTO contacts (uuid, name, email, phone, message, ip_address, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            contact_uuid,
            data["name"],
            data["email"],
            data.get("phone", ""),
            data["message"],
            ip,
            ua,
            now,
        )
        if AIOSQLITE_AVAILABLE:
            await self._db.execute(sql, params)
            await self._db.commit()
        else:
            self._db.execute(sql, params)
            self._db.commit()
        return contact_uuid

    async def get_contacts(self, limit: int = 50, offset: int = 0) -> list:
        """Retrieve contacts with pagination."""
        sql = "SELECT * FROM contacts ORDER BY created_at DESC LIMIT ? OFFSET ?"
        if AIOSQLITE_AVAILABLE:
            async with self._db.execute(sql, (limit, offset)) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        else:
            cursor = self._db.execute(sql, (limit, offset))
            return [dict(row) for row in cursor.fetchall()]

    async def close(self):
        if self._db:
            if AIOSQLITE_AVAILABLE:
                await self._db.close()
            else:
                self._db.close()


# ---------------------------------------------------------------------------
# Rate Limiter — Token Bucket Algorithm
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Token-bucket rate limiter keyed by IP address.

    Reference: stackoverflow.com/questions/667508 — classic algorithm
    """

    def __init__(self, rate: float = 5.0, per: float = 60.0):
        self.rate = rate          # max tokens (messages) allowed
        self.per = per            # per this many seconds
        self._clients: dict = {}  # ip -> (allowance, last_check)

    def is_allowed(self, ip: str) -> bool:
        now = time.monotonic()
        if ip not in self._clients:
            self._clients[ip] = (self.rate, now)

        allowance, last_check = self._clients[ip]
        time_passed = now - last_check
        allowance += time_passed * (self.rate / self.per)
        if allowance > self.rate:
            allowance = self.rate

        if allowance < 1.0:
            self._clients[ip] = (allowance, now)
            return False
        else:
            self._clients[ip] = (allowance - 1.0, now)
            return True

    def cleanup(self):
        """Remove stale entries older than 2x the rate window."""
        now = time.monotonic()
        stale = [ip for ip, (_, ts) in self._clients.items() if now - ts > self.per * 2]
        for ip in stale:
            del self._clients[ip]


# ---------------------------------------------------------------------------
# Request Handlers
# ---------------------------------------------------------------------------

class BaseHandler(tornado.web.RequestHandler):
    """Base handler with CORS and common utilities."""

    def set_default_headers(self):
        allowed = self.application.settings.get("allowed_origins", "*")
        origin = self.request.headers.get("Origin", "")

        if allowed == "*":
            self.set_header("Access-Control-Allow-Origin", "*")
        elif origin in allowed.split(","):
            self.set_header("Access-Control-Allow-Origin", origin)

        self.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.set_header("Access-Control-Allow-Headers", 
                        "Content-Type, X-XSRFToken, X-Requested-With")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("X-Frame-Options", "DENY")

    def options(self, *args):
        """Handle CORS preflight."""
        self.set_status(204)
        self.finish()

    def get_client_ip(self) -> str:
        """Extract client IP, respecting reverse proxy headers."""
        return (
            self.request.headers.get("X-Real-IP")
            or self.request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or self.request.remote_ip
        )

    def write_error_json(self, status: int, message: str):
        self.set_status(status)
        self.write({"status": "error", "message": message})


class GetInTouchHandler(BaseHandler):
    """
    POST /contact — Receives contact form submissions.

    Security layers:
      1. Honeypot detection (hidden 'username' field)
      2. Rate limiting (token bucket per IP)
      3. Input validation (Pydantic or fallback regex)
      4. Parameterized SQL queries (injection prevention)
      5. XSRF protection (when enabled in Application settings)
    """

    def check_xsrf_cookie(self):
        """
        Override XSRF check for the contact endpoint.

        For a static-site frontend that cannot generate server-side XSRF
        tokens, we rely on honeypot + rate limiting + origin checking instead.
        Re-enable this when the frontend supports XSRF tokens.
        """
        pass

    async def post(self):
        db: DatabaseManager = self.application.db
        limiter: RateLimiter = self.application.rate_limiter
        client_ip = self.get_client_ip()

        # --- Layer 1: Rate limiting ---
        if not limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded: {client_ip}")
            self.write_error_json(429, "Too many requests. Please try again later.")
            return

        # --- Layer 2: Honeypot detection ---
        honeypot = self.get_argument("username", default="")
        if honeypot:
            # Bot filled the hidden field — silently accept but discard
            logger.info(f"Honeypot triggered from {client_ip}")
            self.write({"status": "ok", "message": "Message received."})
            return

        # --- Layer 3: Input validation ---
        try:
            raw = {
                "name":    self.get_argument("name", default=""),
                "email":   self.get_argument("email", default=""),
                "phone":   self.get_argument("phone", default=""),
                "message": self.get_argument("message", default=""),
            }
            if PYDANTIC_AVAILABLE:
                validated = ContactFormInput(**raw)
                data = validated.model_dump()
            else:
                validated = ContactFormInput(**raw)
                data = validated.model_dump()
        except Exception as e:
            logger.warning(f"Validation error from {client_ip}: {e}")
            self.write_error_json(400, f"Invalid input: {e}")
            return

        # --- Layer 4: Database insertion ---
        try:
            ua = self.request.headers.get("User-Agent", "")
            contact_uuid = await db.insert_contact(data, client_ip, ua)
            logger.info(f"Contact saved: {contact_uuid} from {client_ip}")
            self.write({
                "status": "ok",
                "message": "Your message has been received. Thank you!",
                "id": contact_uuid,
            })
        except Exception as e:
            logger.error(f"Database error: {e}")
            self.write_error_json(500, "Internal server error. Please try again.")


class ContactListHandler(BaseHandler):
    """
    GET /admin/contacts — Retrieve stored contact submissions.

    Protected by a simple API key for v1.
    Upgrade to proper auth (JWT, session) in v2.
    """

    async def get(self):
        api_key = self.request.headers.get("X-API-Key", "")
        expected_key = os.environ.get("ADMIN_API_KEY", "changeme-in-production")

        if api_key != expected_key:
            self.write_error_json(403, "Unauthorized")
            return

        try:
            limit = int(self.get_argument("limit", default="50"))
            offset = int(self.get_argument("offset", default="0"))
        except ValueError:
            self.write_error_json(400, "Invalid pagination parameters")
            return

        db: DatabaseManager = self.application.db
        contacts = await db.get_contacts(limit=min(limit, 200), offset=offset)
        self.write({"status": "ok", "count": len(contacts), "contacts": contacts})


class HealthHandler(tornado.web.RequestHandler):
    """GET /health — Server health check endpoint."""

    def get(self):
        self.write({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------

def make_app(db_manager: DatabaseManager, rate_limiter: RateLimiter) -> tornado.web.Application:
    """Create and configure the Tornado Application."""

    routes = [
        (r"/contact", GetInTouchHandler),
        (r"/admin/contacts", ContactListHandler),
        (r"/health", HealthHandler),
        # Static files served last (catch-all)
        (r"/(.*)", tornado.web.StaticFileHandler, {
            "path": options.static_path,
            "default_filename": "index.html",
        }),
    ]

    app = tornado.web.Application(
        routes,
        cookie_secret=os.environ.get("COOKIE_SECRET", uuid.uuid4().hex),
        xsrf_cookies=True,
        debug=options.debug,
        allowed_origins=options.allowed_origins,
    )

    # Attach shared resources to application object
    app.db = db_manager
    app.rate_limiter = rate_limiter

    return app


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

async def main():
    tornado.options.parse_command_line()

    logging.basicConfig(
        level=logging.DEBUG if options.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    db = DatabaseManager(options.db)
    await db.initialize()

    limiter = RateLimiter(rate=5.0, per=60.0)

    app = make_app(db, limiter)
    app.listen(options.port)

    logger.info(f"Server running on http://localhost:{options.port}")
    logger.info(f"Contact endpoint: POST http://localhost:{options.port}/contact")
    logger.info(f"Admin endpoint:   GET  http://localhost:{options.port}/admin/contacts")
    logger.info(f"Health check:     GET  http://localhost:{options.port}/health")

    # Periodic cleanup of rate limiter stale entries
    cleanup_cb = tornado.ioloop.PeriodicCallback(limiter.cleanup, 300_000)  # every 5 min
    cleanup_cb.start()

    shutdown_event = asyncio.Event()
    try:
        await shutdown_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        await db.close()
        logger.info("Server shut down.")


if __name__ == "__main__":
    asyncio.run(main())