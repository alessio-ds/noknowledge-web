# Deploying noknowledge-web

`noknowledge-web` is a **static site**. Serving it needs no Node process and no
extra port: any web server can hand out the files in `dist/`. The only decision
is how the browser reaches a relay.

## Recommended — same origin as the relay (Caddy)

Run the relay and the web client behind one hostname. The client's default relay
is its own origin, so there is nothing to configure and no CORS preflight.

Example for a relay already reverse-proxied on `localhost:9999`:

```caddyfile
noknowledge.remotewire.net {
	encode zstd gzip

	# The relay keeps owning /api/*.
	handle /api/* {
		reverse_proxy localhost:9999
	}

	# Everything else is the static web client.
	handle {
		root * /srv/noknowledge-web
		try_files {path} /index.html
		file_server
	}

	# Vite emits content-hashed asset names; index.html stays uncached.
	@assets path /assets/*
	header @assets Cache-Control "public, max-age=31536000, immutable"
}
```

Deploy:

```bash
# 1. Build the client (on your machine or in CI)
npm run build

# 2. Copy the static output to the server
rsync -avz --delete dist/ user@server:/srv/noknowledge-web/

# 3. Reload Caddy
sudo systemctl reload caddy     # or: caddy reload --config /etc/caddy/Caddyfile
```

Then open `https://noknowledge.remotewire.net`.

Notes:

- `handle /api/*` must come **before** the general `handle` block; Caddy's
  `handle` directives are mutually exclusive and matched in order.
- No new port is opened. Caddy itself serves the files; the relay stays on 9999.
- Long-poll requests are held up to ~20 s by the client. Caddy's reverse proxy
  has no default response timeout, so `/api/*` works as-is.
- To deploy from the repo without copying, point `root *` at
  `/path/to/noknowledge-web/dist` instead.

## Option B — static host + separate relay (CORS required)

If you host `dist/` on GitHub Pages, Netlify, S3, etc. and point users at a relay
on another origin, the relay must send CORS headers. The client sends custom
headers (`X-NK-Read`, `X-NK-Write`, `X-NK-Mailbox`, `X-NK-Chunk`), so every call
is preflighted.

Add to the FastAPI app (`noknowledge/server/app.py`):

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-web-app.example"],  # exact origin(s), not "*"
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=[
        "X-NK-Read",
        "X-NK-Write",
        "X-NK-Mailbox",
        "X-NK-Chunk",
        "X-NK-Hashcash",
        "Content-Type",
    ],
    max_age=600,
)
```

Then pin the relay at build time, because the app's own origin is no longer the
relay:

```bash
VITE_DEFAULT_RELAYS="https://noknowledge.remotewire.net" npm run build
```

An alternative that avoids CORS entirely: have Caddy add the headers itself with
`header` directives, or put a tiny reverse proxy in front of the relay that
injects them. Notes:

- Do **not** enable `allow_credentials`; the client uses header tokens, not
  cookies.
- An explicit origin list is preferred. `allow_origins=["*"]` also works because
  authorization is by capability token rather than origin, but it lets any site
  use your relay as a store-and-forward service.
- Users can also set their own relays under **Settings**.

## Notes

- The app is built with `base: './'`, so it works from a subpath
  (e.g. `https://example.com/chat/`) without rebuilding.
- `dist/` is fully static; no server-side rendering or Node runtime is required.
- If you want a preview server locally, `npm run preview` listens on
  `127.0.0.1:4173` and proxies `/api` to `NK_RELAY` (default `http://127.0.0.1:8000`).
