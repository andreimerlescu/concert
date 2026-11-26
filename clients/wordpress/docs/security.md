# Security Architecture

The WordPress plugin follows Concert's security standards (`S1`–`S9`):

## 1. Zero Secrets in Database, HTML, or JavaScript (`S1`, `S3`, `S5`, `S6`, `S7`)

- `CONCERT_ADMIN_TOKEN` is **never** stored in `wp_options`.
- **WP Admin → Settings → Concert** is strictly read-only: it displays only the non-sensitive channel name (e.g., `constant:CONCERT_ADMIN_TOKEN_FILE`), never an `<input>` pre-filled with the token and never inline JavaScript holding credentials.
- `Concert\WordPress\Secret` redacts itself across `__toString()`, `__debugInfo()`, and `jsonSerialize()`, returning `[REDACTED]`. Raw token bytes are accessed only at the single `Authorization: Bearer` header construction site via `reveal()`.
- Any transport error message is scrubbed before returning so a downstream library error can never echo the Bearer token into logs or notices.
- Missing, empty, or placeholder tokens fail closed (`purge()` refuses to issue an unauthenticated request).
- `CONCERT_ADMIN_TOKEN_FILE` verifies on POSIX systems that group and world permission bits are zero (`chmod 0600` or stricter).

## 2. Strict Authorization & CSRF Protection (`S9`)

- Both the Admin Bar menu registration and the `admin_post_concert_purge_cache` handler verify `current_user_can('manage_options')`.
- Every purge action verifies a cryptographic WordPress nonce via `wp_verify_nonce($_REQUEST['_wpnonce'], 'concert_purge_cache')`.
- Redirects after purging use `wp_safe_redirect()` to prevent open redirects.

## 3. Transport & Boundary Validation (`S9`)

- `UrlValidator::validateEndpoint()` enforces `https://` for all remote hosts and permits `http://` strictly for loopback (`localhost`, `127.0.0.1`, `::1`).
- Embedded URL credentials (`user:pass@host`), query strings, fragments, and CR/LF/NUL control characters are rejected.
- Outbound purge calls enforce `sslverify => true`, `redirection => 0`, and a bounded timeout (default `5s`, max `30s`).

## 4. Rotating `CONCERT_ADMIN_TOKEN`

1. Issue a new operator token in Concert and add it alongside the old token (or update the secret file atomically with `chmod 0600`).
2. Reload PHP-FPM if using environment variables (secret file updates take effect immediately on the next PHP request).
3. Revoke the old token in Concert.
