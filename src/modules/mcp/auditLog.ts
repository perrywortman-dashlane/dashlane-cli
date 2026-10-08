import fs from 'fs';
import path from 'path';

export interface BaseAuditEvent {
    schema_version: '1.0';
    category: 'McpAgentAccess';
    timestamp: string;
    tool: 'search_vault' | 'call_api' | 'get_audit_logs' | 'sync_vault' | 'http_auth';
    status: 'success' | 'error' | 'blocked';
    error_message?: string;
}

export interface CallApiAuditEvent extends BaseAuditEvent {
    tool: 'call_api';
    method: string;
    url: string;
    http_status?: number;
    secret_id: string;
}

export interface SearchVaultAuditEvent extends BaseAuditEvent {
    tool: 'search_vault';
    query: string;
    result_count: number;
}

export interface GetAuditLogsAuditEvent extends BaseAuditEvent {
    tool: 'get_audit_logs';
    count: number;
}

export interface SyncVaultAuditEvent extends BaseAuditEvent {
    tool: 'sync_vault';
    changes?: number;
}

/** Logged when an HTTP-transport request fails bearer-token authentication. */
export interface HttpAuthAuditEvent extends BaseAuditEvent {
    tool: 'http_auth';
    status: 'blocked';
    reason: 'missing_token' | 'invalid_token';
}

export type McpAuditEvent =
    | CallApiAuditEvent
    | SearchVaultAuditEvent
    | GetAuditLogsAuditEvent
    | SyncVaultAuditEvent
    | HttpAuthAuditEvent;

const VALID_TOOLS = new Set(['search_vault', 'call_api', 'get_audit_logs', 'sync_vault', 'http_auth']);
const VALID_STATUSES = new Set(['success', 'error', 'blocked']);

export function isValidAuditEvent(value: unknown): boolean {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    const obj = value as Record<string, unknown>;
    return (
        obj.schema_version === '1.0' &&
        obj.category === 'McpAgentAccess' &&
        typeof obj.timestamp === 'string' &&
        typeof obj.tool === 'string' &&
        VALID_TOOLS.has(obj.tool) &&
        typeof obj.status === 'string' &&
        VALID_STATUSES.has(obj.status)
    );
}

const USER_DATA_PATH =
    process.env.APPDATA ||
    (process.platform === 'darwin'
        ? (process.env.HOME as string) + '/Library/Application Support'
        : (process.env.HOME as string) + '/.local/share');
const AUDIT_DIR = path.join(USER_DATA_PATH, 'dashlane-cli');
const AUDIT_LOG_PATH = path.join(AUDIT_DIR, 'mcp-audit.log');

let dirEnsured = false;
let permissionsEnsured = false;

export async function readLastAuditLogs(count: number): Promise<McpAuditEvent[]> {
    let fileHandler;
    try {
        fileHandler = await fs.promises.open(AUDIT_LOG_PATH, 'r');
    } catch (e) {
        // Return empty array if file does not exist
        if (e instanceof Error && 'code' in e && e.code === 'ENOENT') {
            return [];
        }
        throw e;
    }

    try {
        const stat = await fileHandler.stat();
        const fileSize = stat.size;
        if (fileSize === 0) return [];

        // Read from the end of the file in chunks to find the last N lines
        const CHUNK_SIZE = 8192;
        const results: McpAuditEvent[] = [];
        let position = fileSize;
        let trailing = '';

        while (position > 0 && results.length < count) {
            const readSize = Math.min(CHUNK_SIZE, position);
            position -= readSize;

            const buf = Buffer.alloc(readSize);
            await fileHandler.read(buf, 0, readSize, position);
            const chunk = buf.toString('utf-8') + trailing;
            trailing = '';

            const lines = chunk.split('\n');

            // First element may be a partial line if we're not at the start of the file
            if (position > 0) {
                trailing = lines.shift() ?? '';
            }

            // Process lines in reverse (most recent first)
            for (let i = lines.length - 1; i >= 0 && results.length < count; i--) {
                const line = lines[i].trim();
                if (line.length === 0) continue;
                try {
                    const parsed: unknown = JSON.parse(line);
                    if (isValidAuditEvent(parsed)) {
                        results.push(parsed as McpAuditEvent);
                    }
                } catch {
                    // skip malformed lines
                }
            }
        }

        // Handle any remaining partial line from the start of the file
        if (results.length < count && trailing.trim().length > 0) {
            try {
                const parsed: unknown = JSON.parse(trailing.trim());
                if (isValidAuditEvent(parsed)) {
                    results.push(parsed as McpAuditEvent);
                }
            } catch {
                // skip malformed line
            }
        }

        return results;
    } finally {
        await fileHandler.close();
    }
}

export function logMcpAuditEvent(event: McpAuditEvent): void {
    try {
        if (!dirEnsured) {
            fs.mkdirSync(AUDIT_DIR, { recursive: true });
            dirEnsured = true;
        }
        const line = JSON.stringify(event) + '\n';
        // Only the user can read the log: it holds search queries and URLs
        fs.appendFileSync(AUDIT_LOG_PATH, line, { mode: 0o600 });
        if (!permissionsEnsured) {
            fs.chmodSync(AUDIT_LOG_PATH, 0o600); // the file may exist from an older version
            permissionsEnsured = true;
        }
    } catch {
        // Audit logging must never crash the server
    }
}
