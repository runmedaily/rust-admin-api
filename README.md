# rust-admin-api

Admin panel and forward auth server for reverse proxies. Built with Rust (Axum) and deployable as a NixOS service with built-in Caddy integration.

Provides user management (create/delete, roles), JWT API tokens, and a `/api/verify` endpoint that works as a forward auth middleware for Caddy, Traefik, or Nginx — protecting any service behind a login page or Bearer token.

## Quick start

```bash
nix develop
cargo run
# → http://localhost:3000  (login: admin / admin)
```

Or with a config file:

```bash
cp config.example.toml config.toml
cargo run -- --config config.toml
```

## CLI

```
rust-admin-api [OPTIONS]

Options:
    --config <PATH>      Path to config.toml [default: /etc/rust-admin-api/config.toml]
    --web-port <PORT>    Web server port (overrides config file)
```

## Configuration

See [config.example.toml](config.example.toml):

```toml
[server]
listen_addr = "0.0.0.0:3000"

[auth]
auth_url = "https://auth.example.com"   # public URL for redirect construction
cookie_domain = ".example.com"           # cross-subdomain cookie sharing
cookie_secure = true                     # required behind HTTPS
jwt_secret = "change-me"                 # or use jwt_secret_file for production
# jwt_secret_file = "/srv/rust-admin-api/jwt.secret"

[database]
path = "admin.db"
```

All fields have defaults. Missing config file = defaults. Missing fields = defaults.

## Forward auth endpoint

`GET /api/verify` — designed for Caddy's `forward_auth`, Traefik's `ForwardAuth`, or Nginx's `auth_request`.

Accepts authentication via **session cookie** (browser) or **`Authorization: Bearer <jwt>`** header (API).

**Authenticated request** → `200 OK` with headers:
- `X-Forwarded-User: <username>`
- `X-Forwarded-Role: <admin|user>`

**Unauthenticated browser** (`Accept: text/html`) → `307` redirect to login page with `?rd=<original_url>` for post-login redirect back.

**Unauthenticated API client** → `401 Unauthorized` with `X-Auth-Redirect` header.

## API tokens (JWT)

Admins can create long-lived JWT tokens from the dashboard for programmatic access. Tokens authenticate via `Authorization: Bearer <jwt>` and work with the `/api/verify` endpoint.

```bash
# Use a token with curl
curl -H "Authorization: Bearer eyJ..." https://app.example.com/api/data

# The proxy verifies via /api/verify and forwards with user headers
```

Tokens are tracked in the database and can be revoked from the dashboard. The JWT secret is configured via `jwt_secret` or `jwt_secret_file` (the NixOS module auto-generates one on first deploy).

## Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Redirect to dashboard or login |
| GET | `/login` | Login page (accepts `?rd=<url>`) |
| POST | `/login` | Authenticate |
| GET | `/logout` | End session |
| GET | `/dashboard` | Admin panel |
| POST | `/users/create` | Create user (admin only) |
| POST | `/users/delete` | Delete user (admin only) |
| POST | `/tokens/create` | Create API token (admin only) |
| POST | `/tokens/revoke` | Revoke API token (admin only) |
| GET | `/api/verify` | Forward auth endpoint |

## NixOS deployment

### Minimal — just the auth server

```nix
{
  inputs.rust-admin-api.url = "github:youruser/rust-admin-api";

  outputs = { rust-admin-api, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        rust-admin-api.nixosModules.rust-admin-api
        {
          services.rust-admin-api = {
            enable = true;
            openFirewall = true;
          };
        }
      ];
    };
  };
}
```

### With Caddy — protect any service with auth

This is the recommended setup. Caddy handles HTTPS automatically and the module wires up forward auth for you.

```nix
{
  inputs = {
    rust-admin-api.url = "github:youruser/rust-admin-api";
    firetv-monitor.url = "github:youruser/firetv-monitor";
  };

  outputs = { rust-admin-api, firetv-monitor, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        rust-admin-api.nixosModules.rust-admin-api
        firetv-monitor.nixosModules.firetv-monitor
        {
          # Your app — unchanged
          services.firetv-monitor = {
            enable = true;
            webPort = 8081;
          };

          # Auth + Caddy — everything wired automatically
          services.rust-admin-api = {
            enable = true;
            domain = "auth.myhouse.com";
            cookieDomain = ".myhouse.com";

            caddy = {
              enable = true;
              protectedServices = {
                "firetv.myhouse.com" = "http://localhost:8081";
                # add more:
                # "grafana.myhouse.com" = "http://localhost:3000";
                # "jellyfin.myhouse.com" = "http://localhost:8096";
              };
            };
          };
        }
      ];
    };
  };
}
```

This gives you:
- `auth.myhouse.com` — login page and admin dashboard (auto HTTPS)
- `firetv.myhouse.com` — your app, protected by login (auto HTTPS)
- Session cookies shared across `*.myhouse.com`
- Adding another protected service = one line in `protectedServices`

### NixOS module options

| Option | Default | Description |
|--------|---------|-------------|
| `enable` | `false` | Enable the service |
| `dataDir` | `/srv/rust-admin-api` | Database and data directory |
| `webPort` | `3030` | Internal server port |
| `domain` | `""` | Public domain (required with Caddy) |
| `authUrl` | `""` | Public URL (auto-derived when Caddy enabled) |
| `cookieDomain` | `null` | Cookie domain for cross-subdomain auth |
| `cookieSecure` | `true` | Secure flag on cookies |
| `openFirewall` | `false` | Open port directly (not needed with Caddy) |
| `caddy.enable` | `false` | Set up Caddy with forward auth |
| `caddy.protectedServices` | `{}` | `domain → upstream` map to protect |

## Manual proxy configuration

If you're not using the NixOS module's Caddy integration, here are configs for common proxies.

### Caddy

```
auth.example.com {
    reverse_proxy localhost:3030
}

app.example.com {
    forward_auth localhost:3030 {
        uri /api/verify
        copy_headers X-Forwarded-User X-Forwarded-Role
    }
    reverse_proxy localhost:8081
}
```

### Traefik

```yaml
http:
  middlewares:
    admin-auth:
      forwardAuth:
        address: "http://localhost:3030/api/verify"
        authResponseHeaders:
          - "X-Forwarded-User"
          - "X-Forwarded-Role"

  routers:
    my-app:
      rule: "Host(`app.example.com`)"
      middlewares:
        - admin-auth
      service: my-app-svc
```

### Nginx

```nginx
location = /auth {
    internal;
    proxy_pass http://localhost:3030/api/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Uri $request_uri;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location / {
    auth_request /auth;
    auth_request_set $auth_user $upstream_http_x_forwarded_user;
    proxy_set_header X-Forwarded-User $auth_user;
    proxy_pass http://localhost:8081;
}
```

## Stack

- [Axum](https://github.com/tokio-rs/axum) — async web framework
- [Askama](https://github.com/djc/askama) — compile-time HTML templates
- [SQLite](https://www.sqlite.org/) (rusqlite) — embedded database
- [Argon2](https://en.wikipedia.org/wiki/Argon2) — password hashing
- [Crane](https://crane.dev/) + [Fenix](https://github.com/nix-community/fenix) — reproducible Nix builds
