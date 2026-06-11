import express, { Request, Response, NextFunction } from "express";
import { randomUUID, timingSafeEqual } from "crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createMcpServer, type ServerContext } from "./index.js";

interface HttpServerOptions {
  port: number;
  host: string;
  apiKey?: string;
  ctx: ServerContext;
  onServerCreated?: (server: Server) => void;
  onServerClosed?: (server: Server) => void;
}

interface Session {
  transport: StreamableHTTPServerTransport;
  server: Server;
  lastActivity: number;
}

const DEFAULT_BODY_LIMIT = "1mb";

function getBodyLimit(): string {
  return process.env.MCP_MAX_BODY_SIZE || DEFAULT_BODY_LIMIT;
}

function tokensEqual(actual: string | null, expected: string): boolean {
  if (!actual) return false;
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  return (
    actualBuffer.length === expectedBuffer.length &&
    timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

export async function startHttpServer(options: HttpServerOptions): Promise<void> {
  const { port, host, apiKey, ctx, onServerCreated, onServerClosed } = options;
  const app = express();
  app.disable("x-powered-by");

  // Session storage
  const sessions = new Map<string, Session>();

  const cleanupSession = (id: string, reason: string): boolean => {
    const session = sessions.get(id);
    if (!session) return false;
    sessions.delete(id);
    onServerClosed?.(session.server);
    console.error(`raybridge: HTTP session ${reason}: ${id}`);
    return true;
  };

  const closeSession = async (id: string, reason: string): Promise<boolean> => {
    const session = sessions.get(id);
    if (!session) return false;
    cleanupSession(id, reason);
    await session.server.close();
    return true;
  };

  // CORS for remote access (before other middleware)
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID, Authorization"
    );
    res.header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.header("Access-Control-Expose-Headers", "Mcp-Session-Id, Mcp-Protocol-Version");
    if (req.method === "OPTIONS") {
      res.sendStatus(204);
      return;
    }
    next();
  });

  // Health check endpoint (before JSON parsing to avoid issues)
  app.get("/health", (_req: Request, res: Response) => {
    res.json({
      status: "ok",
      sessions: sessions.size,
      extensions: ctx.extensions.length,
      tools: ctx.tools.length,
    });
  });

  // Optional Bearer token authentication (MCP spec compliant)
  if (apiKey) {
    app.use("/mcp", (req: Request, res: Response, next: NextFunction) => {
      const authHeader = req.headers.authorization;
      const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;
      if (!tokensEqual(token, apiKey)) {
        res.status(401).json({ error: "Invalid or missing Bearer token" });
        return;
      }
      next();
    });
  }

  // JSON body parsing (only for MCP endpoint, after optional auth)
  app.use("/mcp", express.json({ limit: getBodyLimit(), strict: true }));
  app.use("/mcp", (err: any, _req: Request, res: Response, next: NextFunction) => {
    if (err.type === "entity.too.large") {
      res.status(413).json({ error: "MCP request body is too large" });
      return;
    }

    if (err instanceof SyntaxError || err.type === "entity.parse.failed") {
      res.status(400).json({ error: "Invalid JSON request body" });
      return;
    }

    next(err);
  });

  // MCP endpoint - handles all HTTP methods
  app.all("/mcp", async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    // Handle existing session
    if (sessionId && sessions.has(sessionId)) {
      const session = sessions.get(sessionId)!;
      session.lastActivity = Date.now();
      await session.transport.handleRequest(req, res, req.body);
      return;
    }

    // Handle new session (initialize request)
    if (!sessionId && req.method === "POST" && isInitializeRequest(req.body)) {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: async (id: string) => {
          transport.onclose = () => {
            void closeSession(id, "closed").catch((error) => {
              console.error(`raybridge: Failed to close HTTP session ${id}:`, error);
            });
          };
          const server = createMcpServer(ctx);
          await server.connect(transport);
          sessions.set(id, {
            transport,
            server,
            lastActivity: Date.now(),
          });
          onServerCreated?.(server);
          console.error(`raybridge: HTTP session started: ${id}`);
        },
      });
      await transport.handleRequest(req, res, req.body);
      return;
    }

    // Handle session termination
    if (sessionId && req.method === "DELETE") {
      if (await closeSession(sessionId, "terminated")) {
        res.status(200).json({ status: "session terminated" });
      } else {
        res.status(404).json({ error: "Session not found" });
      }
      return;
    }

    // Invalid request
    res.status(400).json({
      error: "Invalid request. Expected initialize request or valid session ID.",
    });
  });

  // Session cleanup (30 min idle timeout)
  const IDLE_TIMEOUT = 30 * 60 * 1000; // 30 minutes
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [id, session] of sessions) {
      if (now - session.lastActivity > IDLE_TIMEOUT) {
        void closeSession(id, "expired").catch((error) => {
          console.error(`raybridge: Failed to clean up expired HTTP session ${id}:`, error);
        });
      }
    }
  }, 5 * 60 * 1000); // Check every 5 minutes

  // Graceful shutdown
  process.on("SIGINT", async () => {
    console.error("\nraybridge: Shutting down HTTP server...");
    clearInterval(cleanupInterval);
    for (const id of Array.from(sessions.keys())) {
      await closeSession(id, "closed during shutdown");
    }
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    clearInterval(cleanupInterval);
    for (const id of Array.from(sessions.keys())) {
      await closeSession(id, "closed during shutdown");
    }
    process.exit(0);
  });

  app.listen(port, host, () => {
    console.error(`raybridge: HTTP server listening on http://${host}:${port}`);
    console.error(`raybridge: MCP endpoint: http://${host}:${port}/mcp`);
    console.error(`raybridge: Health check: http://${host}:${port}/health`);
    if (apiKey) {
      console.error("raybridge: API key authentication enabled");
    }
  });
}
