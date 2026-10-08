import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { InvalidArgumentError } from 'commander';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { logger } from '../../logger.js';
import { logMcpAuditEvent } from './auditLog.js';
import { checkBearerAuth, generateHttpToken } from './httpAuth.js';

export const DEFAULT_HTTP_PORT = 3277;
export const HTTP_TOKEN_ENV_VAR = 'DASHLANE_MCP_HTTP_TOKEN';
export const DEFAULT_IDLE_TIMEOUT_MINUTES = 30;
// setTimeout overflows (and fires immediately) above 2^31 - 1 ms.
export const MAX_IDLE_TIMEOUT_MINUTES = Math.floor(2147483647 / 60000);

const HTTP_HOST = '127.0.0.1';
const MCP_PATH = '/mcp';
const MAX_BODY_BYTES = 4 * 1024 * 1024;

/**
 * Hostnames accepted in the Host header (DNS-rebinding protection, port-agnostic).
 * The container aliases let an MCP client inside a dev container reach the host
 * loopback via host.docker.internal / host.containers.internal. The socket still
 * binds 127.0.0.1 only, and every request still requires the bearer token.
 */
const ALLOWED_HOSTNAMES = new Set([
    '127.0.0.1',
    'localhost',
    '[::1]',
    'host.docker.internal',
    'host.containers.internal',
]);

const sendJsonRpcError = (
    res: http.ServerResponse,
    httpStatus: number,
    code: number,
    message: string,
    extraHeaders: Record<string, string> = {}
): void => {
    res.writeHead(httpStatus, { 'Content-Type': 'application/json', ...extraHeaders });
    res.end(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }));
};

/** Validate the Host header hostname (ignoring port) against the allow-list. */
export const isAllowedHost = (hostHeader: string | undefined): boolean => {
    if (!hostHeader) {
        return false;
    }
    try {
        return ALLOWED_HOSTNAMES.has(new URL(`http://${hostHeader}`).hostname);
    } catch {
        return false;
    }
};

const getSessionId = (req: http.IncomingMessage): string | undefined => {
    const value = req.headers['mcp-session-id'];
    return typeof value === 'string' ? value : undefined;
};

const readJsonBody = (req: http.IncomingMessage): Promise<unknown> =>
    new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
        let size = 0;
        req.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                req.destroy();
                reject(new Error('Request body too large'));
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            if (chunks.length === 0) {
                resolve(undefined);
                return;
            }
            try {
                resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
                reject(new Error('Invalid JSON body'));
            }
        });
        req.on('error', reject);
    });

/** Parse `--idle-timeout <minutes>`: a non-negative number, where 0 disables the idle shutdown. */
export const parseIdleTimeoutMinutes = (value: string): number => {
    const minutes = Number(value);
    if (value.trim() === '' || !Number.isFinite(minutes) || minutes < 0 || minutes > MAX_IDLE_TIMEOUT_MINUTES) {
        throw new InvalidArgumentError(
            `Idle timeout must be a number of minutes between 0 and ${MAX_IDLE_TIMEOUT_MINUTES} (0 = never stop).`
        );
    }
    return minutes;
};

const formatMinutes = (minutes: number): string => `${minutes} ${minutes === 1 ? 'minute' : 'minutes'}`;

export const idleShutdownMessage = (minutes: number): string =>
    `Stopped after ${formatMinutes(minutes)} without activity. Run dcli mcp --http again to continue.`;

/** Resolve the bearer token from the environment, or generate a one-time token. */
export const resolveHttpToken = (): { token: string; generated: boolean } => {
    const fromEnv = process.env[HTTP_TOKEN_ENV_VAR];
    if (fromEnv && fromEnv.length > 0) {
        return { token: fromEnv, generated: false };
    }
    return { token: generateHttpToken(), generated: true };
};

/**
 * Build the HTTP server for the vault MCP (stateful sessions over Streamable HTTP).
 * Exposed separately from `runHttpTransport` so tests can listen on an ephemeral port.
 *
 * @param serverFactory - returns a fresh, fully-registered McpServer for each new session.
 * @param token - the bearer token required on every request.
 * @param idle - optional idle shutdown: `onIdle` is called once `timeoutMs` passes with no authenticated
 *   request. The timer starts when the server is listening; a timeout of 0 (or no option) never fires.
 */
export const buildHttpServer = (
    serverFactory: () => McpServer,
    token: string,
    idle?: { timeoutMs: number; onIdle: () => void }
): http.Server => {
    const transports: Record<string, StreamableHTTPServerTransport> = {};

    let idleTimer: NodeJS.Timeout | undefined;
    let idleArmed = false;
    const restartIdleTimer = (): void => {
        if (!idle || idle.timeoutMs <= 0 || !idleArmed) {
            return;
        }
        clearTimeout(idleTimer);
        idleTimer = setTimeout(idle.onIdle, idle.timeoutMs);
        idleTimer.unref();
    };

    const handleRequest = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
        try {
            // 1. DNS-rebinding protection: only accept known local/container hostnames.
            if (!isAllowedHost(req.headers.host)) {
                sendJsonRpcError(res, 403, -32000, `Invalid Host: ${req.headers.host ?? '(none)'}`);
                return;
            }

            // 2. Only the /mcp endpoint is served.
            const pathname = new URL(req.url ?? '/', `http://${req.headers.host}`).pathname;
            if (pathname !== MCP_PATH) {
                sendJsonRpcError(res, 404, -32601, 'Not found');
                return;
            }

            // 3. Bearer authentication on every request.
            const auth = checkBearerAuth(req.headers.authorization, token);
            if (auth !== 'ok') {
                logMcpAuditEvent({
                    schema_version: '1.0',
                    category: 'McpAgentAccess',
                    timestamp: new Date().toISOString(),
                    tool: 'http_auth',
                    status: 'blocked',
                    reason: auth,
                });
                sendJsonRpcError(res, 401, -32001, 'Unauthorized', { 'WWW-Authenticate': 'Bearer' });
                return;
            }

            // Only authenticated requests count as activity; restart again when the response ends
            // so a slow request is not measured as idle time.
            restartIdleTimer();
            res.once('close', restartIdleTimer);

            // 4. Route by method.
            if (req.method === 'POST') {
                let body: unknown;
                try {
                    body = await readJsonBody(req);
                } catch {
                    sendJsonRpcError(res, 400, -32700, 'Parse error');
                    return;
                }

                const sessionId = getSessionId(req);
                const existing = sessionId ? transports[sessionId] : undefined;
                let transport: StreamableHTTPServerTransport;

                if (existing) {
                    transport = existing;
                } else if (!sessionId && isInitializeRequest(body)) {
                    const newTransport = new StreamableHTTPServerTransport({
                        sessionIdGenerator: () => randomUUID(),
                        enableJsonResponse: true,
                        onsessioninitialized: (id) => {
                            transports[id] = newTransport;
                        },
                    });
                    newTransport.onclose = () => {
                        if (newTransport.sessionId) {
                            delete transports[newTransport.sessionId];
                        }
                    };
                    await serverFactory().connect(newTransport);
                    transport = newTransport;
                } else {
                    sendJsonRpcError(res, 400, -32000, 'Bad Request: No valid session ID provided');
                    return;
                }

                await transport.handleRequest(req, res, body);
                return;
            }

            if (req.method === 'GET' || req.method === 'DELETE') {
                // GET (server->client stream) and DELETE (session termination) need an existing session.
                const sessionId = getSessionId(req);
                const existing = sessionId ? transports[sessionId] : undefined;
                if (!existing) {
                    sendJsonRpcError(res, 400, -32000, 'Bad Request: No valid session ID provided');
                    return;
                }
                await existing.handleRequest(req, res);
                return;
            }

            sendJsonRpcError(res, 405, -32000, 'Method Not Allowed', { Allow: 'POST, GET, DELETE' });
        } catch (error) {
            logger.error(`Vault MCP HTTP request error: ${error instanceof Error ? error.message : String(error)}`);
            if (!res.headersSent) {
                sendJsonRpcError(res, 500, -32603, 'Internal server error');
            }
        }
    };

    const server = http.createServer((req, res) => {
        void handleRequest(req, res);
    });
    server.on('listening', () => {
        idleArmed = true;
        restartIdleTimer();
    });
    server.on('close', () => {
        idleArmed = false;
        clearTimeout(idleTimer);
    });
    return server;
};

const printStartupNotice = (port: number, token: string, generated: boolean, idleTimeoutMinutes: number): void => {
    const lines = [`Dashlane vault MCP (HTTP) listening on http://${HTTP_HOST}:${port}${MCP_PATH}`];
    if (generated) {
        lines.push(
            '',
            'One-time access token for this session (clients must send it):',
            `  Authorization: Bearer ${token}`,
            '',
            `Set ${HTTP_TOKEN_ENV_VAR} before starting to reuse a fixed token across restarts.`
        );
    } else {
        lines.push(`Using access token from ${HTTP_TOKEN_ENV_VAR}.`);
    }
    lines.push(
        '',
        idleTimeoutMinutes > 0
            ? `Stops automatically after ${formatMinutes(idleTimeoutMinutes)} without activity (--idle-timeout 0 to disable).`
            : 'Idle shutdown is disabled (--idle-timeout 0).',
        '',
        `From a dev container, connect to: http://host.containers.internal:${port}${MCP_PATH}`,
        `  (Podman; on Docker use host.docker.internal)`
    );
    // stderr only: never put the token on stdout (which is the MCP channel for the stdio transport).
    process.stderr.write(lines.join('\n') + '\n');
};

/**
 * Start the vault MCP HTTP server bound to localhost and block until SIGINT/SIGTERM.
 * Resolves once the server has shut down (after running `onShutdown`).
 */
export const runHttpTransport = (
    serverFactory: () => McpServer,
    options: { port: number; idleTimeoutMinutes?: number; onShutdown?: () => void }
): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const { token, generated } = resolveHttpToken();
        const idleTimeoutMinutes = options.idleTimeoutMinutes ?? DEFAULT_IDLE_TIMEOUT_MINUTES;

        const removeSignalHandlers = () => {
            process.off('SIGINT', shutdown);
            process.off('SIGTERM', shutdown);
        };

        let shuttingDown = false;
        const shutdown = () => {
            if (shuttingDown) {
                return;
            }
            shuttingDown = true;
            removeSignalHandlers();
            server.close(() => {
                options.onShutdown?.();
                resolve();
            });
            // server.close() waits for keep-alive connections; drop them so shutdown is prompt.
            server.closeAllConnections();
        };

        const server = buildHttpServer(serverFactory, token, {
            timeoutMs: idleTimeoutMinutes * 60_000,
            onIdle: () => {
                process.stderr.write(idleShutdownMessage(idleTimeoutMinutes) + '\n');
                shutdown();
            },
        });

        server.on('error', (error) => {
            removeSignalHandlers();
            reject(error);
        });
        server.listen(options.port, HTTP_HOST, () => {
            printStartupNotice(options.port, token, generated, idleTimeoutMinutes);
        });
        process.once('SIGINT', shutdown);
        process.once('SIGTERM', shutdown);
    });
