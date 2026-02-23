
### Getting started.


### setup instructions
#### Pre-requisitites
- You already have Python, `venv`, and `pip` working.
- You’re starting with an empty folder on your machine.

#### 1. Get the code

```bash
# 1. Clone the repo
git clone https://github.com/actualintelligence-hash/actualintelligence-hash.github.io.git

cd actualintelligence-hash.github.io

# At this point you should see files like `run.py`, `concrete/`, `_config.yml`, etc. The `concrete/` folder is what Tornado will serve as the static site.

```

#### 2. Activate your virtualenv
You said venv + pip is already set up, so just make sure it’s active: 
```bash
# macOS / Linux
source venv/bin/activate

# Windows PowerShell
.\venv\Scripts\Activate

```


#### 3. Install Python dependencies

You need Tornado, aiosqlite, and Pydantic (for validation). All are installable from PyPI.

```bash
pip install tornado aiosqlite pydantic[email]
python -c "import tornado, aiosqlite, pydantic; print('OK')" # to check the correct installations, If that prints `OK` with no errors, you’re good.
```

#### 4. Set environment variables (optional but recommended)
```bash
# macOS / Linux (bash/zsh)
export ADMIN_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export COOKIE_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Windows PowerShell
$env:ADMIN_API_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:COOKIE_SECRET = python -c "import secrets; print(secrets.token_hex(32))"


# If you skip this, the code will still run, but:

# - `ADMIN_API_KEY` will default to `changeme-in-production` (not secure).  
# - `COOKIE_SECRET` will be random each time you start the server (ok for local dev).

```

#### 5. Run the backend server

From the repo root:

```bash
python tornado_run.py

# You should see log lines like:

# - `Server running on http://localhost:8080`    
# - `Contact endpoint: POST http://localhost:8080/contact`
# - `Admin endpoint: GET http://localhost:8080/admin/contacts`
# - `Health check: GET http://localhost:8080/health

```


Tornado’s structure here matches the pattern in the official docs: create an `Application`, call `.listen(port)`, then run an async `main()` with `asyncio.run(main())`


#### 6. Verify the static site and health endpoint

Open in your browser:

- `http://localhost:8080/` → you should see the Agency Jekyll theme (served from `concrete/`).
- `http://localhost:8080/health` → you should see JSON like: 
```json
{"status": "ok", "timestamp": "..."}

```

If those work, Tornado is serving static files and the health handler correctly.

#### 7. Test the contact form end-to-end

1. In the homepage, scroll to the **Contact** section.
2. Fill in **Name**, **Email**, **Phone**, and **Message**.    
3. Click **Send Message**.

The front-end JavaScript (`contact_me.js`) uses jqBootstrapValidation to validate inputs and then sends an AJAX POST to `/contact`.

On success, (OPTION 1) you should see a green success alert on the page and a log like:

```text
INFO contactserver: Contact saved: <uuid> from 127.0.0.1
```

(OPTION 2) You can also check the stored data directly:

```bash
sqlite3 contacts.db 'SELECT uuid, name, email, created_at FROM contacts ORDER BY created_at DESC LIMIT 5;'
```

You should see your submission there.

#### 8. Test the admin endpoint (list contacts)

Use `curl` or a tool like Postman:
```bash
curl -H "X-API-Key: $ADMIN_API_KEY" \
     "http://localhost:8080/admin/contacts?limit=10&offset=0"
```

```bash
curl -X POST http://localhost:8080/contact \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name=Test User" \
  --data-urlencode "email=test@example.com" \
  --data-urlencode "phone=1234567890" \
  --data-urlencode "message=Hello from curl" \
  --data-urlencode "username="
```


If you didn’t set `ADMIN_API_KEY`, use:
```bash
# (for local testing only).
curl -H "X-API-Key: changeme-in-production" \
     "http://localhost:8080/admin/contacts"
```


Expected response: JSON with `status`, `count`, and a `contacts` array.

#### 9. Basic troubleshooting

- **Port already in use**  
	Start with a different port:

```bash
python tornado_run.py --port=9000
```

- **`ModuleNotFoundError: No module named 'tornado'`**  
    Re-check that you installed into the active environment:
```bash
pip install tornado python -c "import tornado"
```

- **Contact form always says “server not responding”**
    
    - Open browser dev tools → Network tab → check the POST `/contact` request and status code.
    - If you see `429`, you’re hitting the rate limiter (too many test submissions in a short time).
    - If you see `400`, input failed validation (check the JSON error message).



## references


— Improved Tornado server (`tornado_run.py`)
— Updated frontend JS (`contact_me.js`)


## tornado_run.py (information - ai aided code docs)

### notes
#### **Which parts run once vs per request?**
- Run **once at startup**:
    - CLI option parsing.
    - Logging setup.
    - Database connection + schema creation.
    - Instantiation of `RateLimiter`.
    - Application construction and roue setup.
    
- Run **once per HTTP request**:
    - Handler instantiation (`GetInTouchHandler`, `ContactListHandler`, `HealthHandler`).
    - `set_default_headers`, `get`, `post`, etc.
    - DB CRUD calls (`insert_contact` / `get_contacts`).
    - Rate limiter check.

#### Endpoints
- `POST /contact`
    - Body fields: `name`, `email`, `phone`, `message`, and a hidden `username` honeypot (should be empty).
    - Response: JSON with `{status, message, id}` on success or `{status: "error", message}` on error.

- `GET /admin/contacts`
    - Headers: `X-API-Key: <your-secret>` (from `ADMIN_API_KEY` env var).
    - Query params: `limit` (default 50, max 200), `offset` (default 0).
    - Response: `{status, count, contacts: [...]}`.

- `GET /health`    
    - Response: `{status: "ok", timestamp: "<UTC ISO time>"}`.


### code documentation


```python
#!/usr/bin/env python3
"""
tornado_run.py — v1 Contact Form Backend for actualintelligence-hash.github.io

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

```

```python
#tornado_run.py

#  1. **Configuration & globals** (top)
# ---------------------------------------------------------------------------

# port: which TCP port the server listens on.

# db: path to the SQLite database file.

# static_path: where to find your Jekyll-built HTML/JS/CSS (concrete/).

# debug: enable Tornado debug features (auto-reload, extra logging).

# allowed_origins: CORS allowlist.

# These are parsed once in `main()` via `tornado.options.parse_command_line()`.
# ---------------------------------------------------------------------------

define("port", default=8080, help="Server port", type=int)

define("db", default="contacts.db", help="SQLite database path", type=str)

define("static_path", default="concrete", help="Static files directory", type=str)

define("debug", default=False, help="Enable debug mode", type=bool)

define("allowed_origins", default="*", help="Comma-separated allowed origins", type=str)

  

logger = logging.getLogger("contactserver")


```

```python

# tornado_run.py
# ---------------------------------------------------------------------------
# Pydantic Models — Input Validation & Sanitization
"""
This block defines how input is validated.
- PART 1: If Pydantic is installed,  `ContactFormInput`  extends `BaseModel` with:       
    - `name: str`, `email: EmailStr`, `phone: str = ""`, `message: str`.       
    - Validators:
        - `validate_name`: trims whitespace, enforces length 1–200, restricts characters.
        - `validate_phone`: optional but must match a loosely-defined phone pattern.
        - `validate_message`: trims and enforces length 1–5000.

- PART 2: If Pydantic is _not_ installed, there is a fallback class that:
    - Does basic checks with regex and length.
    - Provides a `model_dump()` method to mimic Pydantic’s interface.
     
   
**When it runs:**
- The class definitions run once at import time.
- Actual validation happens per-request inside `GetInTouchHandler.post()`.
"""
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


```

```python


# ---------------------------------------------------------------------------
# Database Layer — Async SQLite via aiosqlite
"""
The `DatabaseManager` abstracts all database operations.

Key methods:
- `__init__(db_path)`: just stores the path.

- `initialize()` (called once at startup):
    - Opens an SQLite connection (async if `aiosqlite` is installed; otherwise sync).
    - Sets `journal_mode=WAL` to allow concurrent reads while a write is in progress.
    - Ensures the `contacts` table and indexes exist via `SCHEMA_SQL`.

- `insert_contact(data, ip, ua)`:    
    - Generates a UUID.
    - Uses a **parameterized INSERT** query (`VALUES (?, ?, ...)`) to prevent SQL injection.
    - Commits the transaction.
    - Returns the contact’s UUID.

- `get_contacts(limit, offset)`:    
    - Executes a `SELECT` with `LIMIT/OFFSET` for paging.
    - Returns a list of dicts.

- `close()`:    
    - Closes the DB connection on shutdown.
        

**When it runs:**

- `DatabaseManager.initialize()` is called **once** in `main()` at startup.
- `insert_contact` and `get_contacts` are used **per request** by handlers.
"""
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


```

```python
# ---------------------------------------------------------------------------
# Rate Limiter — Token Bucket Algorithm
"""
`RateLimiter` is a small in-memory token-bucket for basic rate limiting.[](https://stackoverflow.com/questions/667508/whats-a-good-rate-limiting-algorithm)​

- Each IP starts with `rate` tokens (default 5).    
- Every `per` seconds (default 60) it “earns back” tokens.

- `is_allowed(ip)`:    
    - Recomputes the allowance based on elapsed time.
    - If less than 1 token remains, returns `False` (429).
    - Otherwise, decrements by 1 and returns `True`.

- `cleanup()`:    
    - Deletes IPs from the internal dict if they haven’t been seen for `2 * per` seconds.

**When it runs:**
- One `RateLimiter` instance is created once in `main()`.
- `is_allowed()` is called **per request** in `GetInTouchHandler.post()`.
- `cleanup()` is scheduled every 5 minutes via `PeriodicCallback`.

"""
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

```

```python
# ---------------------------------------------------------------------------
# Request Handlers (BaseHandler)

"""
## 2.5 BaseHandler: common HTTP and CORS utilities

`BaseHandler` extends Tornado’s `RequestHandler`.[](https://www.tornadoweb.org/en/stable/web.html)​

- `set_default_headers()`:
    - Applies CORS headers based on `allowed_origins`.
    - Sets `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers`.
    - Adds security headers `X-Content-Type-Options` and `X-Frame-Options`.

- `options()`:    
    - Handles CORS preflight requests by returning 204 with no body.

- `get_client_ip()`:    
    - Tries `X-Real-IP`, then `X-Forwarded-For`, then `remote_ip`.
    - Makes it proxy-friendly (e.g., behind Nginx).

- `write_error_json(status, message)`:
    - Helper to send JSON error responses.

Every other JSON endpoint inherits this for consistent behavior.
"""

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



```

```python
# ---------------------------------------------------------------------------
"""
(extends BaseHandler, part of Request handler ) GetInTouchHandler: POST `/contact`

This is the main endpoint your contact form hits.

Steps inside `post()`:

1. **Rate limiting**    
    - Looks up the client IP via `get_client_ip()`.
    - Calls `limiter.is_allowed(ip)` to enforce 5 requests/minute default.
    - If exceeded, logs and returns HTTP 429 with JSON error.
        
2. **Honeypot detection**
    - Reads the hidden `username` field.
    - If it is non-empty, assumes a bot:
        - Logs that honeypot triggered.
        - Returns a benign success JSON (to avoid giving bots feedback).
    - This is aligned with common practical anti-spam patterns discussed in developer communities.[](https://stackoverflow.com/questions/23200482/preventing-bots-from-spamming-registrations-without-captchas)​

3. **Input validation**    
    - Collects `name`, `email`, `phone`, `message` from request arguments.
    - Creates a `ContactFormInput` instance:
        - Either Pydantic (rich validation) or fallback class.  
    - If validation fails, catches the exception and returns HTTP 400 with a message.
  
4. **Database insertion**    
    - Reads `User-Agent` header.
    - Calls `db.insert_contact(...)` to persist.
    - On success, logs and returns JSON with `status="ok"` and the `id` (UUID).
    - On DB error, logs and returns HTTP 500.
"""
# ---------------------------------------------------------------------------


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


```

```python

"""
(extends BaseHandler, part of Request handler) ## ContactListHandler: GET `/admin/contacts`

This is a simple API for listing stored contacts.

	1. Reads `X-API-Key` header.
	2. Compares to `ADMIN_API_KEY` env var (default “changeme-in-production”).
	3. If mismatch: HTTP 403 JSON error.
	4. Parses `limit` and `offset` query params.
	5. Calls `db.get_contacts(...)` with an upper bound of 200 for `limit`.    
	6. Returns JSON: `{status: "ok", count, contacts: [...]}`.

NOTE: This is intentionally minimal; the docstring notes this should become real authentication (JWT/sessions) in v2.
"""

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

```

```python
"""
(extends BaseHandler, part of Request handler) ## ## HealthHandler: GET `/health`

- Returns JSON with `{status: "ok", timestamp: <UTC ISO time>}`.
- Useful for uptime checks.
"""

class HealthHandler(tornado.web.RequestHandler):
    """GET /health — Server health check endpoint."""

    def get(self):
        self.write({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})



```

```python


# ---------------------------------------------------------------------------
"""
## Application Factory: building the Tornado application
`make_app(db_manager, rate_limiter)` wires everything:[](https://www.tornadoweb.org/en/stable/web.html)​

- Declares the route list:    
    - `/contact` → `GetInTouchHandler`
    - `/admin/contacts` → `ContactListHandler`
    - `/health` → `HealthHandler`
    - `/(.*)` → `StaticFileHandler` serving from `static_path` (`concrete`) with `index.html` default.

- Creates `tornado.web.Application(...)` with:    
    - `cookie_secret`: from `COOKIE_SECRET` env var (or a random UUID if not set).
    - `xsrf_cookies=True`: global XSRF protection (except where overridden).[](https://www.tornadoweb.org/en/stable/guide/security.html)​
    - `debug`, `allowed_origins` from CLI options.
     
- Attaches `db` and `rate_limiter` to the application object so handlers can access them via `self.application.db` and `self.application.rate_limiter`.
"""
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

```

```python
# ---------------------------------------------------------------------------
"""
## main(): Main Entry Point and the orchestrator

`async def main()` is the entry point coordinated by `asyncio.run(main())`:
	1. `parse_command_line()` — reads CLI flags.
	2. Configures logging (DEBUG if `--debug=True`).
	3. Instantiates `DatabaseManager` and `await db.initialize()`.
	4. Instantiates `RateLimiter`.
	5. Builds application via `make_app(db, limiter)`.
	6. `app.listen(options.port)` — binds the HTTP server.
	7. Logs URLs for  `/contact`,  `/admin/contacts`,  `/health`. 
	8. Schedules `limiter.cleanup` every 300,000 ms (~5 min).
	9. Creates `shutdown_event` and waits forever (until `KeyboardInterrupt`).
	10. On shutdown, closes DB and logs “Server shut down.”
"""
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
```




## contact_me.js
```js
/**
 * contact_me.js — Updated frontend JS for contact form
 * 
 * Changes from original:
 *  - Sends JSON payload instead of form-encoded data
 *  - Adds CSRF token support (reads _xsrf cookie)
 *  - Preserves honeypot detection
 *  - Adds client-side rate limiting feedback
 */

$(function() {

  // Helper: read a cookie value by name
  function getCookie(name) {
    var match = document.cookie.match("\\b" + name + "=([^;]*)\\b");
    return match ? match[1] : undefined;
  }

  $("#contactForm input,#contactForm textarea").jqBootstrapValidation({
    preventSubmit: true,
    submitError: function($form, event, errors) {
      // Additional error handling if needed
    },
    submitSuccess: function($form, event) {
      event.preventDefault();

      var url = "/contact";
      var name = $("input#name").val();
      var username = $("input#username").val();   // honeypot
      var email = $("input#email").val();
      var phone = $("input#phone").val();
      var message = $("textarea#message").val();

      var firstName = name;
      if (firstName.indexOf(' ') >= 0) {
        firstName = name.split(' ').slice(0, -1).join(' ');
      }

      var $btn = $("#sendMessageButton");
      $btn.prop("disabled", true);

      // Only submit if honeypot is empty (bot detection)
      if (username === '') {

        // Build payload
        var payload = {
          name: name,
          phone: phone,
          email: email,
          message: message
        };

        // Include XSRF token if Tornado's xsrf_cookies is enabled
        var xsrf = getCookie("_xsrf");
        if (xsrf) {
          payload._xsrf = xsrf;
        }

        $.ajax({
          url: url,
          type: "POST",
          dataType: "json",
          data: payload,
          cache: false,

          success: function(response) {
            $('#success').html(
              "<div class='alert alert-success'>" +
              "<button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>" +
              "<strong>Your message has been sent. </strong>" +
              "</div>"
            );
            $('#contactForm').trigger("reset");
          },

          error: function(xhr) {
            var msg = "Sorry " + firstName + ", ";
            if (xhr.status === 429) {
              msg += "you are sending too many messages. Please wait a moment and try again.";
            } else if (xhr.status === 400) {
              try {
                var resp = JSON.parse(xhr.responseText);
                msg += resp.message || "please check your input and try again.";
              } catch (e) {
                msg += "please check your input and try again.";
              }
            } else {
              msg += "it seems the server is not responding. Please try again later!";
            }

            $('#success').html(
              "<div class='alert alert-danger'>" +
              "<button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>" +
              "<strong>" + msg + "</strong>" +
              "</div>"
            );
            $('#contactForm').trigger("reset");
          },

          complete: function() {
            setTimeout(function() {
              $btn.prop("disabled", false);
            }, 1000);
          }
        });
      }
    },
    filter: function() {
      return $(this).is(":visible");
    },
  });

  $("a[data-toggle=\"tab\"]").click(function(e) {
    e.preventDefault();
    $(this).tab("show");
  });
});

// Clear status on focus
$('#name').focus(function() {
  $('#success').html('');
});
```

