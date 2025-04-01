#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { Redis } from '@upstash/redis'

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
  transport: 'sse' | 'stdio';
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
    return data === null ? undefined : data;
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
 * For Instagram Basic Display API, we use OAuth.
 * Stored credentials (per memoryKey) will include:
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
  // Save tokens in storage.
  await storage.set(memoryKey, { provider: 'instagram', accessToken: data.access_token, userId: data.user_id });
  return data.access_token;
}

// Fetch the authenticated Instagram user’s basic profile.
async function fetchInstagramUser(
  storage: Storage,
  config: Config,
  memoryKey: string
): Promise<{ user_id: string; username: string }> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken) {
    throw new Error('No Instagram access token available.');
  }
  const response = await fetch(`https://graph.instagram.com/me?fields=user_id,username&access_token=${stored.accessToken}`, { method: 'GET' });
  const data = await response.json();
  if (!data.user_id) {
    throw new Error('Failed to fetch Instagram user id.');
  }
  // Update stored userId.
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
async function listInstagramMedia(storage: Storage, config: Config, memoryKey: string): Promise<any[]> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken || !stored.userId) {
    throw new Error('No Instagram credentials available. Authenticate first.');
  }
  const fields = 'id,caption,media_type,media_url,permalink,timestamp,username,thumbnail_url,children,media_product_type,comments_count,like_count';
  const url = `https://graph.instagram.com/v22.0/${stored.userId}/media?fields=${fields}&access_token=${stored.accessToken}`;
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
  config: Config,
  memoryKey: string
): Promise<{ success: boolean; message: string; postId: string }> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken || !stored.userId) {
    throw new Error('No Instagram credentials available. Authenticate first.');
  }
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
        access_token: stored.accessToken
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
        access_token: stored.accessToken
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
  // Use storage as per configuration.
  const storage: Storage = config.storage === 'upstash-redis-rest'
    ? new RedisStorage(config.upstashRedisRestUrl!, config.upstashRedisRestToken!, config.storageHeaderKey!)
    : new MemoryStorage();

  server.tool(
    `${toolsPrefix}auth_url`,
    'Return an OAuth URL for Instagram login with instagram_business_basic and instagram_business_content_publish scopes.',
    {},
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
    {},
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
// Express/SSE/stdio Setup (same as in other MCPs)
//////////////////////////////////////////////////////////////////////////////

const log = (...args: any[]): void => console.log('[instagram-mcp]', ...args)
const logErr = (...args: any[]): void => console.error('[instagram-mcp]', ...args)

async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
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

  // Build configuration
  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio',
    storage: argv.storage as 'memory-single' | 'memory' | 'upstash-redis-rest',
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

  // Additional CLI validation:
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

  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createMcpServer(memoryKey, config, toolsPrefix);
    const transport = new StdioServerTransport();
    void server.connect(transport);
    log('Listening on stdio');
    return;
  }

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
    log(`Listening on port ${argv.port} (${argv.transport})`);
  });
}

main().catch((err: any) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
