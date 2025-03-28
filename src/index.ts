#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'

// Define interfaces for Instagram user and media responses
interface InstagramUser {
  user_id: string
  username: string
}

interface InstagramMedia {
  id: string
  // Add other fields if needed (e.g. media_type, media_url, timestamp, etc.)
}

// --------------------------------------------------------------------
// 1) Parse CLI options (including Instagram credentials and state)
// --------------------------------------------------------------------
const argv = yargs(hideBin(process.argv))
  .option('port', { type: 'number', default: 8000 })
  .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
  .option('instagramAppId', { type: 'string', demandOption: true, describe: "Instagram App ID" })
  .option('instagramAppSecret', { type: 'string', demandOption: true, describe: "Instagram App Secret" })
  .option('instagramRedirectUri', { type: 'string', demandOption: true, describe: "Instagram Redirect URI" })
  .option('instagramState', { type: 'string', default: '', describe: "OAuth state parameter" })
  .help()
  .parseSync()

// Define log functions with explicit types
const log = (...args: any[]): void => console.log('[instagram-mcp]', ...args)
const logErr = (...args: any[]): void => console.error('[instagram-mcp]', ...args)

// --------------------------------------------------------------------
// 2) Global Instagram Auth State
// --------------------------------------------------------------------
let instagramAccessToken: string | null = null
let instagramUserId: string | null = null

// --------------------------------------------------------------------
// 3) Instagram OAuth Setup
// --------------------------------------------------------------------
const INSTAGRAM_APP_ID: string = argv.instagramAppId
const INSTAGRAM_APP_SECRET: string = argv.instagramAppSecret
const INSTAGRAM_REDIRECT_URI: string = argv.instagramRedirectUri
const INSTAGRAM_STATE: string = argv.instagramState

// Generate the Instagram OAuth URL.
// The URL is based on Instagram’s OAuth endpoint for Basic Display.
// Scopes used here are for professional account operations:
// - instagram_business_basic: To read basic profile info.
// - instagram_business_content_publish: To publish content.
function generateInstagramAuthUrl(): string {
  const params = new URLSearchParams({
    client_id: INSTAGRAM_APP_ID,
    redirect_uri: INSTAGRAM_REDIRECT_URI,
    scope: 'instagram_business_basic,instagram_business_content_publish',
    response_type: 'code'
  })
  if (INSTAGRAM_STATE) {
    params.set('state', INSTAGRAM_STATE)
  }
  return `https://api.instagram.com/oauth/authorize?${params.toString()}`
}

// Exchange authorization code for an Instagram user access token.
// For Instagram’s Basic Display API the token exchange is a POST request.
async function exchangeInstagramAuthCode(code: string): Promise<string> {
  const params = new URLSearchParams({
    client_id: INSTAGRAM_APP_ID,
    client_secret: INSTAGRAM_APP_SECRET,
    grant_type: 'authorization_code',
    redirect_uri: INSTAGRAM_REDIRECT_URI,
    code: code.trim()
  })
  const response = await fetch('https://api.instagram.com/oauth/access_token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: params.toString()
  })
  const data = await response.json()
  if (!data.access_token) {
    throw new Error('Failed to obtain Instagram access token.')
  }
  instagramAccessToken = data.access_token
  instagramUserId = data.user_id
  return data.access_token
}

// Fetch the authenticated Instagram user’s basic profile.
async function fetchInstagramUser(): Promise<InstagramUser> {
  if (!instagramAccessToken) throw new Error('No Instagram access token available.')
  const response = await fetch(`https://graph.instagram.com/me?fields=user_id,username&access_token=${instagramAccessToken}`, {
    method: 'GET'
  })
  const data = await response.json()
  if (!data.user_id) throw new Error('Failed to fetch Instagram user id.')
  instagramUserId = data.user_id
  return data
}

// Authenticate with Instagram: exchange the code and fetch user info.
async function authInstagram({ code }: { code: string }): Promise<{ success: boolean; provider: string; user: InstagramUser }> {
  await exchangeInstagramAuthCode(code)
  const user = await fetchInstagramUser()
  return { success: true, provider: "instagram", user }
}

// --------------------------------------------------------------------
// 4) Tool Functions: Instagram Media Operations
// --------------------------------------------------------------------

// List all media posts from the authenticated Instagram professional account.
// This calls the /<IG_ID>/media endpoint.
async function listInstagramMedia(): Promise<InstagramMedia[]> {
  if (!instagramAccessToken || !instagramUserId) throw new Error('No Instagram access token available.')
  const response = await fetch(`https://graph.instagram.com/${instagramUserId}/media?access_token=${instagramAccessToken}`, {
    method: 'GET'
  })
  const data = await response.json()
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch media: ${data.error ? data.error.message : 'Unknown error'}`)
  }
  return data.data
}

async function createInstagramPost({ imageUrl, caption }: { imageUrl: string; caption: string }): Promise<{ success: boolean; message: string; postId: string }> {
  if (!instagramAccessToken || !instagramUserId) {
    throw new Error('No Instagram access token available.')
  }

  // Step 1: Create a media container.
  let containerData: any;
  const containerUrl = `https://graph.instagram.com/v22.0/${instagramUserId}/media`;
  try {
    const containerResponse = await fetch(containerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // Include the access token here
      body: JSON.stringify({
        image_url: imageUrl,
        caption: caption,
        access_token: instagramAccessToken
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
  const publishUrl = `https://graph.instagram.com/v22.0/${instagramUserId}/media_publish`;
  try {
    const publishResponse = await fetch(publishUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        creation_id: containerId,
        access_token: instagramAccessToken
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
// 5) Helper: JSON response formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2)
      }
    ]
  }
}

// --------------------------------------------------------------------
// 6) Create the MCP server, registering our tools
// --------------------------------------------------------------------
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'Instagram MCP Server',
    version: '1.0.0'
  })

  // Tool: Return the Instagram OAuth URL.
  server.tool(
    'instagram_auth_url',
    'Return an OAuth URL for Instagram login with instagram_business_basic and instagram_business_content_publish scopes.',
    {},
    async () => {
      try {
        const authUrl = generateInstagramAuthUrl()
        return toTextJson({ authUrl })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // Tool: Exchange auth code for access token and fetch user info.
  server.tool(
    'instagram_exchange_auth_code',
    'Authenticate with Instagram by exchanging an auth code. This sets up Instagram authentication.',
    {
      code: z.string()
    },
    async (args: { code: string }) => {
      try {
        const result = await authInstagram(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // Tool: List media posts from the authenticated Instagram account.
  server.tool(
    'instagram_list_media',
    'List all media posts from the authenticated Instagram professional account.',
    {},
    async () => {
      try {
        const media = await listInstagramMedia()
        return toTextJson({ media })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // Tool: Create a new Instagram post (single image).
  server.tool(
    'instagram_create_post',
    'Create a new Instagram post (single image) on the authenticated account. Provide imageUrl and caption as text.',
    {
      imageUrl: z.string(),
      caption: z.string()
    },
    async (args: { imageUrl: string; caption: string }) => {
      try {
        const result = await createInstagramPost(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  return server
}

// --------------------------------------------------------------------
// 7) Minimal Fly.io "replay" handling (optional)
// --------------------------------------------------------------------
function parseFlyReplaySrc(headerValue: string): { [key: string]: string } {
  const regex = /(.*?)=(.*?)($|;)/g
  const matches = headerValue.matchAll(regex)
  const result: { [key: string]: string } = {}
  for (const match of matches) {
    if (match.length >= 3) {
      const key = match[1].trim()
      const value = match[2].trim()
      result[key] = value
    }
  }
  return result
}
let machineId: string | null = null
function saveMachineId(req: Request): void {
  if (machineId) return
  const headerKey = 'fly-replay-src'
  const raw = req.headers[headerKey.toLowerCase()]
  if (!raw || typeof raw !== 'string') return
  try {
    const parsed = parseFlyReplaySrc(raw)
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state)
      const obj = JSON.parse(decoded)
      if (obj.machineId) machineId = obj.machineId
    }
  } catch {
    // ignore
  }
}

// --------------------------------------------------------------------
// 8) Main: Start either SSE or stdio server
// --------------------------------------------------------------------
function main(): void {
  const server = createMcpServer()

  if (argv.transport === 'stdio') {
    const transport = new StdioServerTransport()
    void server.connect(transport)
    log('Listening on stdio')
    return
  }

  const port = argv.port
  const app = express()
  let sessions: Array<{ server: McpServer; transport: SSEServerTransport }> = []

  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  app.get('/', async (req: Request, res: Response) => {
    saveMachineId(req)
    const transport = new SSEServerTransport('/message', res)
    const mcpInstance = createMcpServer()
    await mcpInstance.connect(transport)
    sessions.push({ server: mcpInstance, transport })

    const sessionId = transport.sessionId
    log(`[${sessionId}] SSE connection established`)

    transport.onclose = () => {
      log(`[${sessionId}] SSE closed`)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] SSE client disconnected`)
      sessions = sessions.filter(s => s.transport !== transport)
    })
  })

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      logErr('Missing sessionId')
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId)
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`)
      res.status(404).send({ error: 'No active session' })
      return
    }
    try {
      await target.transport.handlePostMessage(req, res)
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err)
      res.status(500).send({ error: 'Internal error' })
    }
  })

  app.listen(port, () => {
    log(`Listening on port ${port} (${argv.transport})`)
  })
}

main()
