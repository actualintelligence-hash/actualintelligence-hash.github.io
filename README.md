
### Getting started.


### setup instructions for frontend

#### 1. build jekyll site

```
bundle install
bundle exec jekyll build
bundle exec jekyll serve
```
website frontend is served at http://127.0.0.1:4000/agency-jekyll-theme-starter

### setup instructions for backend






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
python tornado_run.py \
  --port=8080 \
  --allowed_origins=http://127.0.0.1:4000


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

