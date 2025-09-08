# Instagram MCP Server

An MCP server that authenticates with Instagram and provides tools to list media and publish a post (single image) to an Instagram account.

## Token Handling

- Short‑lived token: After the auth code exchange, Instagram returns a short‑lived user token.
- Long‑lived token: The server transparently upgrades it to a long‑lived token (~60 days) using `grant_type=ig_exchange_token`.
- Auto‑refresh: When a stored long‑lived token is within 7 days of expiry, the server refreshes it using `grant_type=ig_refresh_token` and updates the stored expiry.
- Stored fields: `accessToken` (long‑lived), plus optional metadata:
  - `accessTokenType`
  - `accessTokenExpiresAt` (epoch ms)
- Backward compatibility: If an existing stored token has no `accessTokenExpiresAt`, the server attempts to upgrade it in place the next time it’s used. Existing keys (`accessToken`, `userId`) are preserved.

## Storage

Supports in‑memory and Upstash Redis (REST) storage. When using Upstash, tokens are saved as JSON blobs under the configured key prefix and your per‑client `memoryKey`.

## OAuth Scopes

The default scopes requested are:

```
instagram_business_basic,instagram_business_content_publish
```

These allow reading media and publishing content on eligible Instagram accounts.

## MCP Tools

- `auth_url`: Returns the Instagram Login URL.
- `exchange_auth_code`: Exchanges an OAuth code and upgrades to a long‑lived user token.
- `list_media`: Lists media for the authenticated Instagram account.
- `create_post`: Publishes a single‑image post for the authenticated account.

## CLI Options (selected)

- `--transport`: `sse` | `stdio` | `http` (default: `sse`)
- `--storage`: `memory-single` | `memory` | `upstash-redis-rest` (default: `memory-single`)
- `--storageHeaderKey`: Header name to identify the per‑client memory key (required for `memory`/`upstash-redis-rest`).
- `--instagramAppId`, `--instagramAppSecret`, `--instagramRedirectUri`, `--instagramState`
- `--upstashRedisRestUrl`, `--upstashRedisRestToken` (for Upstash)
- `--toolsPrefix`: Prefix to add to tool names (default: `instagram_`).

## Scripts

- Lint: `npm run lint` | Auto‑fix: `npm run lint:fix`
- Build: `npm run build`
- Start: `npm start`

## Notes

- Instagram long‑lived user tokens do not use a standard `refresh_token`. The token can be extended using the refresh endpoint; this server attempts refreshes when a token is within 7 days of expiry.
