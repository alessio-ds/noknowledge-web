# Deploying noknowledge-web

`noknowledge-web` is a static site. Serving it is the easy part; the only real
decision is how your users' browsers will reach a relay.

## Option A — serve the app from the relay (recommended, no CORS)

Put the relay behind a reverse proxy that serves `dist/` for everything except
`/api`, which it forwards to the relay. The page and the API share an origin, so
no CORS headers or preflights are involved.

Minimal nginx sketch:

```nginx
server {
    listen 443 ssl;
    server_name chat.example;

    root /srv/noknowledge-web/dist;
    index index.html;

    location / {
        try_files $uri /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 75s;   # covers long-poll `wait`
    }
}
```

The default relay is the app's own origin, so no configuration is needed.

## Option B — static host + separate relay (CORS required)

If you host `dist/` on GitHub Pages, Netlify, S3, etc. and point users at a relay
on another origin, the relay must send CORS headers. The relay uses custom
request headers (`X-NK-Read`, `X-NK-Write`, `X-NK-Mailbox`, `X-NK-Chunk`), so
every call is preflighted.

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

Notes:

- Do **not** enable `allow_credentials`; the client uses header tokens, not
  cookies.
- An explicit origin list is preferred. `allow_origins=["*"]` also works because
  authorization is by capability token rather than origin, but it lets any site
  use your relay as a store-and-forward service.
- Pin the app's relay with `VITE_DEFAULT_RELAYS="https://relay.example"` at build
  time, or have users set it under **Settings**.
- If users self-host relays, they can enter their own URLs in Settings.

## Notes

- The app is built with `base: './'`, so it works from a subpath.
- `npm run build` output is `dist/`; no server-side rendering or Node runtime is
  required.
- Long-poll requests hold a connection up to 20 s in the UI; size your proxy timeouts
  accordingly.
