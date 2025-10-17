#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { InMemoryEventStore } from '@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js'
import { z } from 'zod'
import { Redis } from '@upstash/redis'
import { randomUUID } from 'node:crypto'

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio' | 'http';
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  instagramAppId: string;
  instagramAppSecret: string;
  instagramRedirectUri: string;
  instagramState?: string;
  storageHeaderKey?: string;
  upstashRedisRestUrl?: string;
  upstashRedisRestToken?: string;
}

interface Storage {
  get(memoryKey: string): Promise<Record<string, any> | undefined>;
  set(memoryKey: string, data: Record<string, any>): Promise<void>;
}

// --------------------------------------------------------------------
// In-Memory Storage Implementation
// --------------------------------------------------------------------
class MemoryStorage implements Storage {
  private storage: Record<string, Record<string, any>> = {};
  async get(memoryKey: string) {
    return this.storage[memoryKey];
  }
  async set(memoryKey: string, data: Record<string, any>) {
    // Merge new data with existing data so that previous tokens are preserved.
    this.storage[memoryKey] = { ...this.storage[memoryKey], ...data };
  }
}

// --------------------------------------------------------------------
// Upstash Redis Storage Implementation
// --------------------------------------------------------------------
class RedisStorage implements Storage {
  private redis: Redis;
  private keyPrefix: string;
  constructor(redisUrl: string, redisToken: string, keyPrefix: string) {
    this.redis = new Redis({ url: redisUrl, token: redisToken });
    this.keyPrefix = keyPrefix;
  }
  async get(memoryKey: string): Promise<Record<string, any> | undefined> {
    const data = await this.redis.get(`${this.keyPrefix}:${memoryKey}`);
    if (data === null) return undefined;
    if (typeof data === 'string') {
      try { return JSON.parse(data); } catch { return undefined; }
    }
    return data as any;
  }
  async set(memoryKey: string, data: Record<string, any>) {
    const existing = (await this.get(memoryKey)) || {};
    const newData = { ...existing, ...data };
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(newData));
  }
}

// --------------------------------------------------------------------
// Instagram OAuth & API Helpers
// --------------------------------------------------------------------
/**
 * Stored credentials (per memoryKey):
 *   { provider: "instagram", accessToken: string, userId: string }
 */

// Generate the Instagram OAuth URL.
function generateInstagramAuthUrl(config: Config): string {
  const params = new URLSearchParams({
    client_id: config.instagramAppId,
    redirect_uri: config.instagramRedirectUri,
    scope: 'instagram_business_basic,instagram_business_content_publish',
    response_type: 'code'
  });
  if (config.instagramState) {
    params.set('state', config.instagramState);
  }
  return `https://api.instagram.com/oauth/authorize?${params.toString()}`;
}

// Exchange a short-lived Instagram user token for a long-lived token (~60 days)
async function exchangeToLongLivedInstagramToken(
  shortLivedToken: string,
  config: Config
): Promise<{ access_token: string; token_type?: string; expires_in?: number }> {
  const params = new URLSearchParams({
    grant_type: 'ig_exchange_token',
    client_secret: config.instagramAppSecret,
    access_token: shortLivedToken,
  });
  const url = `https://graph.instagram.com/access_token?${params.toString()}`;
  const resp = await fetch(url, { method: 'GET' });
  const data = await resp.json();
  if (!resp.ok || !data?.access_token) {
    const msg = data?.error?.message || 'Failed to exchange for long-lived Instagram token';
    throw new Error(msg);
  }
  return data;
}

// Refresh a long-lived Instagram user token (extends ~60 days again)
async function refreshLongLivedInstagramToken(
  longLivedToken: string
): Promise<{ access_token: string; token_type?: string; expires_in?: number }> {
  const params = new URLSearchParams({
    grant_type: 'ig_refresh_token',
    access_token: longLivedToken,
  });
  const url = `https://graph.instagram.com/refresh_access_token?${params.toString()}`;
  const resp = await fetch(url, { method: 'GET' });
  const data = await resp.json();
  if (!resp.ok || !data?.access_token) {
    const msg = data?.error?.message || 'Failed to refresh long-lived Instagram token';
    throw new Error(msg);
  }
  return data;
}

// Ensure we have a long-lived token stored at key `accessToken`.
// Backward compatible: if an existing token has no expiry metadata, attempt upgrade in place.
async function ensureLongLivedInstagramToken(
  storage: Storage,
  config: Config,
  memoryKey: string
): Promise<string> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken) {
    throw new Error('No Instagram access token available.');
  }

  const current = stored.accessToken as string;

  const now = Date.now();
  const expiresAt: number | undefined = stored.accessTokenExpiresAt;

  // If we know expiry and it is far enough in the future, just use it.
  if (expiresAt && expiresAt > now) {
    // Proactively refresh if within 7 days of expiry
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    if (expiresAt - now < sevenDays) {
      try {
        console.log('[instagram-mcp] Access token near expiry; refreshing long-lived token.');
        const refreshed = await refreshLongLivedInstagramToken(current);
        const newExpiresAt = refreshed.expires_in ? now + refreshed.expires_in * 1000 : undefined;
        await storage.set(memoryKey, {
          accessToken: refreshed.access_token,
          accessTokenType: refreshed.token_type || stored.accessTokenType,
          accessTokenExpiresAt: newExpiresAt,
        });
        return refreshed.access_token;
      } catch (e) {
        console.warn('[instagram-mcp] Token refresh failed; using existing token until expiry.', e);
        return current;
      }
    }
    return current;
  }

  // No known expiry => attempt to upgrade to long-lived token.
  try {
    console.log('[instagram-mcp] Upgrading to long-lived Instagram token.');
    const exchanged = await exchangeToLongLivedInstagramToken(current, config);
    const newExpiresAt = exchanged.expires_in ? now + exchanged.expires_in * 1000 : undefined;
    await storage.set(memoryKey, {
      accessToken: exchanged.access_token,
      accessTokenType: exchanged.token_type,
      accessTokenExpiresAt: newExpiresAt,
    });
    return exchanged.access_token;
  } catch (e) {
    console.warn('[instagram-mcp] Long-lived upgrade failed; keeping existing token for compatibility.', e);
    return current;
  }
}

// Exchange an auth code for an Instagram access token.
async function exchangeInstagramAuthCode(
  code: string,
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<string> {
  const params = new URLSearchParams({
    client_id: config.instagramAppId,
    client_secret: config.instagramAppSecret,
    grant_type: 'authorization_code',
    redirect_uri: config.instagramRedirectUri,
    code: code.trim()
  });
  const response = await fetch('https://api.instagram.com/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });
  const data = await response.json();
  if (!data.access_token) {
    throw new Error('Failed to obtain Instagram access token.');
  }
  // Store provider and userId immediately for backward compatibility
  await storage.set(memoryKey, { provider: 'instagram', userId: data.user_id });

  // Try to upgrade to a long-lived token immediately; if it fails, store short-lived.
  let finalToken = data.access_token as string;
  try {
    console.log('[instagram-mcp] Exchanging short-lived token for long-lived token.');
    const exchanged = await exchangeToLongLivedInstagramToken(data.access_token, config);
    finalToken = exchanged.access_token;
    const now = Date.now();
    const newExpiresAt = exchanged.expires_in ? now + exchanged.expires_in * 1000 : undefined;
    await storage.set(memoryKey, {
      accessToken: finalToken,
      accessTokenType: exchanged.token_type,
      accessTokenExpiresAt: newExpiresAt,
    });
  } catch (e) {
    console.warn('[instagram-mcp] Long-lived exchange failed; storing short-lived token.', e);
    await storage.set(memoryKey, { accessToken: finalToken });
  }
  return finalToken;
}

// Fetch the authenticated Instagram user’s basic profile.
async function fetchInstagramUser(
  storage: Storage,
  _config: Config,
  memoryKey: string
): Promise<{ user_id: string; username: string }> {
  // Ensure a long-lived token (auto-upgrade legacy tokens)
  const accessToken = await ensureLongLivedInstagramToken(storage, _config, memoryKey);
  const response = await fetch(`https://graph.instagram.com/me?fields=user_id,username&access_token=${accessToken}`, { method: 'GET' });
  const data = await response.json();
  if (!data.user_id) {
    throw new Error('Failed to fetch Instagram user id.');
  }
  await storage.set(memoryKey, { userId: data.user_id });
  return data;
}

// Authenticate with Instagram: exchange the code and fetch user info.
async function authInstagram(
  args: { code: string },
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<{ success: boolean; provider: string; user: { user_id: string; username: string } }> {
  await exchangeInstagramAuthCode(args.code, config, storage, memoryKey);
  const user = await fetchInstagramUser(storage, config, memoryKey);
  return { success: true, provider: "instagram", user };
}

// List media from Instagram.
async function listInstagramMedia(storage: Storage, _config: Config, memoryKey: string): Promise<any[]> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.userId) {
    throw new Error('No Instagram credentials available. Authenticate first.');
  }
  const accessToken = await ensureLongLivedInstagramToken(storage, _config, memoryKey);
  const fields = 'id,caption,media_type,media_url,permalink,timestamp,username,thumbnail_url,children,media_product_type,comments_count,like_count';
  const url = `https://graph.instagram.com/v22.0/${stored.userId}/media?fields=${fields}&access_token=${accessToken}`;
  const response = await fetch(url, { method: 'GET' });
  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch media: ${data.error ? data.error.message : 'Unknown error'}`);
  }
  return data.data;
}

// Create a new Instagram post (single image).
async function createInstagramPost(
  args: { imageUrl: string; caption: string },
  storage: Storage,
  _config: Config,
  memoryKey: string
): Promise<{ success: boolean; message: string; postId: string }> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.userId) {
    throw new Error('No Instagram credentials available. Authenticate first.');
  }
  const accessToken = await ensureLongLivedInstagramToken(storage, _config, memoryKey);
  // Step 1: Create a media container.
  let containerData: any;
  const containerUrl = `https://graph.instagram.com/v22.0/${stored.userId}/media`;
  try {
    const containerResponse = await fetch(containerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        image_url: args.imageUrl,
        caption: args.caption,
        access_token: accessToken
      })
    });
    const contentType = containerResponse.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      containerData = await containerResponse.json();
    } else {
      const text = await containerResponse.text();
      throw new Error(`Failed to create media container, unexpected response: ${text}`);
    }
    if (!containerResponse.ok || containerData.error) {
      throw new Error(`Failed to create media container: ${containerData.error ? containerData.error.message : 'Unknown error'}`);
    }
  } catch (error: any) {
    throw new Error(`Error creating media container: ${error.message}`);
  }
  const containerId = containerData.id;

  // Step 2: Publish the media container.
  let publishData: any;
  const publishUrl = `https://graph.instagram.com/v22.0/${stored.userId}/media_publish`;
  try {
    const publishResponse = await fetch(publishUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        creation_id: containerId,
        access_token: accessToken
      })
    });
    const contentType = publishResponse.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      publishData = await publishResponse.json();
    } else {
      const text = await publishResponse.text();
      throw new Error(`Instagram post creation failed, unexpected response: ${text}`);
    }
    if (!publishResponse.ok || publishData.error) {
      throw new Error(`Instagram post creation failed: ${publishData.error ? publishData.error.message : 'Unknown error'}`);
    }
  } catch (error: any) {
    throw new Error(`Error publishing media container: ${error.message}`);
  }
  return { success: true, message: 'Post created successfully.', postId: publishData.id };
}

// --------------------------------------------------------------------
// MCP Server Creation: Register Instagram Tools with Configurable Prefix
// --------------------------------------------------------------------
function createMcpServer(memoryKey: string, config: Config, toolsPrefix: string): McpServer {
  const server = new McpServer({
    name: `Instagram MCP Server (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  });
  const storage: Storage = config.storage === 'upstash-redis-rest'
    ? new RedisStorage(config.upstashRedisRestUrl!, config.upstashRedisRestToken!, config.storageHeaderKey!)
    : new MemoryStorage();

  server.tool(
    `${toolsPrefix}auth_url`,
    'Return an OAuth URL for Instagram login with instagram_business_basic and instagram_business_content_publish scopes.',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
    async () => {
      try {
        const authUrl = generateInstagramAuthUrl(config);
        return toTextJson({ authUrl });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}exchange_auth_code`,
    'Authenticate with Instagram by exchanging an auth code. This sets up Instagram authentication.',
    { code: z.string() },
    async (args: { code: string }) => {
      try {
        const result = await authInstagram(args, config, storage, memoryKey);
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}list_media`,
    'List all media posts from the authenticated Instagram account.',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
    async () => {
      try {
        const media = await listInstagramMedia(storage, config, memoryKey);
        return toTextJson({ media });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}create_post`,
    'Create a new Instagram post (single image) on the authenticated account. Provide imageUrl and caption as text.',
    { imageUrl: z.string(), caption: z.string() },
    async (args: { imageUrl: string; caption: string }) => {
      try {
        const result = await createInstagramPost(args, storage, config, memoryKey);
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  return server;
}

//////////////////////////////////////////////////////////////////////////////
// Express / Streamable HTTP / SSE / stdio Setup
//////////////////////////////////////////////////////////////////////////////

const log = (...args: any[]): void => console.log('[instagram-mcp]', ...args)
const logErr = (...args: any[]): void => console.error('[instagram-mcp]', ...args)

async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio', 'http'], default: 'sse' })
    .option('storage', {
      type: 'string',
      choices: ['memory-single', 'memory', 'upstash-redis-rest'],
      default: 'memory-single',
      describe:
        'Choose storage backend: "memory-single" uses fixed single-user storage; "memory" uses multi-user in-memory storage (requires --storageHeaderKey); "upstash-redis-rest" uses Upstash Redis (requires --storageHeaderKey, --upstashRedisRestUrl, and --upstashRedisRestToken).'
    })
    .option('instagramAppId', { type: 'string', demandOption: true, describe: "Instagram App ID" })
    .option('instagramAppSecret', { type: 'string', demandOption: true, describe: "Instagram App Secret" })
    .option('instagramRedirectUri', { type: 'string', demandOption: true, describe: "Instagram Redirect URI" })
    .option('instagramState', { type: 'string', default: '', describe: "OAuth state parameter" })
    .option('toolsPrefix', { type: 'string', default: 'instagram_', describe: 'Prefix to add to all tool names.' })
    .option('storageHeaderKey', { type: 'string', describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.' })
    .option('upstashRedisRestUrl', { type: 'string', describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)' })
    .option('upstashRedisRestToken', { type: 'string', describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)' })
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as Config['transport'],
    storage: argv.storage as Config['storage'],
    instagramAppId: argv.instagramAppId,
    instagramAppSecret: argv.instagramAppSecret,
    instagramRedirectUri: argv.instagramRedirectUri,
    instagramState: (argv.instagramState as string) || undefined,
    storageHeaderKey:
      (argv.storage === 'memory-single')
        ? undefined
        : (argv.storageHeaderKey && argv.storageHeaderKey.trim()
            ? argv.storageHeaderKey.trim()
            : (() => { console.error('Error: --storageHeaderKey is required for storage modes "memory" or "upstash-redis-rest".'); process.exit(1); return ''; })()),
    upstashRedisRestUrl: argv.upstashRedisRestUrl,
    upstashRedisRestToken: argv.upstashRedisRestToken,
  };

  if ((argv.upstashRedisRestUrl || argv.upstashRedisRestToken) && config.storage !== 'upstash-redis-rest') {
    console.error("Error: --upstashRedisRestUrl and --upstashRedisRestToken can only be used when --storage is 'upstash-redis-rest'.");
    process.exit(1);
  }
  if (config.storage === 'upstash-redis-rest') {
    if (!config.upstashRedisRestUrl || !config.upstashRedisRestUrl.trim()) {
      console.error("Error: --upstashRedisRestUrl is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
    if (!config.upstashRedisRestToken || !config.upstashRedisRestToken.trim()) {
      console.error("Error: --upstashRedisRestToken is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
  }

  const toolsPrefix: string = argv.toolsPrefix;

  // stdio
  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createMcpServer(memoryKey, config, toolsPrefix);
    const transport = new StdioServerTransport();
    void server.connect(transport);
    log('Listening on stdio');
    return;
  }

  // Streamable HTTP (root "/")
  if (config.transport === 'http') {
    const app = express();

    // Do not JSON-parse "/" — the transport handles raw body/streaming
    app.use((req, res, next) => {
      if (req.path === '/') return next();
      express.json()(req, res, next);
    });

    interface HttpSession {
      memoryKey: string;
      server: McpServer;
      transport: StreamableHTTPServerTransport;
    }
    const sessions = new Map<string, HttpSession>();

    function resolveMemoryKeyFromHeaders(req: Request): string | undefined {
      if (config.storage === 'memory-single') return 'single';
      const keyName = (config.storageHeaderKey as string).toLowerCase();
      const headerVal = req.headers[keyName];
      if (typeof headerVal !== 'string' || !headerVal.trim()) return undefined;
      return headerVal.trim();
    }

    function createServerFor(memoryKey: string) {
      return createMcpServer(memoryKey, config, toolsPrefix);
    }

    // POST / — JSON-RPC input; initializes a session if none exists
    app.post('/', async (req: Request, res: ExpressResponse) => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;

        if (sessionId && sessions.has(sessionId)) {
          const { transport } = sessions.get(sessionId)!;
          await transport.handleRequest(req, res);
          return;
        }

        // New initialization — require a valid memoryKey (no anonymous)
        const memoryKey = resolveMemoryKeyFromHeaders(req);
        if (!memoryKey) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: `Bad Request: Missing or invalid "${config.storageHeaderKey}" header` },
            id: (req as any)?.body?.id
          });
          return;
        }

        const server = createServerFor(memoryKey);
        const eventStore = new InMemoryEventStore();

        let transport!: StreamableHTTPServerTransport;
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          eventStore,
          onsessioninitialized: (newSessionId: string) => {
            sessions.set(newSessionId, { memoryKey, server, transport });
            log(`[${newSessionId}] HTTP session initialized for key "${memoryKey}"`);
          }
        });

        transport.onclose = async () => {
          const sid = transport.sessionId;
          if (sid && sessions.has(sid)) {
            sessions.delete(sid);
            log(`[${sid}] Transport closed; removed session`);
          }
          try { await server.close(); } catch { /* already closed */ }
        };

        await server.connect(transport);
        await transport.handleRequest(req, res);
      } catch (err) {
        logErr('Error handling HTTP POST /:', err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    // GET / — server->client event stream (SSE under the hood)
    app.get('/', async (req: Request, res: ExpressResponse) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !sessions.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
          id: (req as any)?.body?.id
        });
        return;
      }
      try {
        const { transport } = sessions.get(sessionId)!;
        await transport.handleRequest(req, res);
      } catch (err) {
        logErr(`[${sessionId}] Error handling HTTP GET /:`, err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    // DELETE / — session termination
    app.delete('/', async (req: Request, res: ExpressResponse) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !sessions.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
          id: (req as any)?.body?.id
        });
        return;
      }
      try {
        const { transport } = sessions.get(sessionId)!;
        await transport.handleRequest(req, res);
      } catch (err) {
        logErr(`[${sessionId}] Error handling HTTP DELETE /:`, err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Error handling session termination' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    app.listen(config.port, () => {
      log(`Listening on port ${config.port} (http)`);
    });

    return; // stop here for http transport
  }

  // SSE transport
  const app = express();
  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: ExpressResponse) => {
    let memoryKey: string;
    if ((argv.storage as string) === 'memory-single') {
      memoryKey = "single";
    } else {
      const headerVal = req.headers[(argv.storageHeaderKey as string).toLowerCase()];
      if (typeof headerVal !== 'string' || !headerVal.trim()) {
        res.status(400).json({ error: `Missing or invalid "${argv.storageHeaderKey}" header` });
        return;
      }
      memoryKey = headerVal.trim();
    }
    const server = createMcpServer(memoryKey, config, toolsPrefix);
    const transport = new SSEServerTransport('/message', res);
    await server.connect(transport);
    const sessionId = transport.sessionId;
    sessions.push({ memoryKey, server, transport, sessionId });
    log(`[${sessionId}] SSE connected for key: "${memoryKey}"`);
    transport.onclose = () => {
      log(`[${sessionId}] SSE connection closed`);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    req.on('close', () => {
      log(`[${sessionId}] Client disconnected`);
      sessions = sessions.filter(s => s.transport !== transport);
    });
  });

  app.post('/message', async (req: Request, res: ExpressResponse) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      logErr('Missing sessionId');
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`);
      res.status(404).send({ error: 'No active session' });
      return;
    }
    try {
      await target.transport.handlePostMessage(req, res);
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err);
      res.status(500).send({ error: 'Internal error' });
    }
  });

  app.listen(argv.port, () => {
    log(`Listening on port ${argv.transport === 'http' ? '(http)' : argv.transport} at ${argv.port}`);
  });
}

main().catch((err: any) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
