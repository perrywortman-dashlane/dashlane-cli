import { assert } from 'chai';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { SessionTokenManager } from './sessionTokens.js';
import { isPrivateIp, validateUrl } from './urlValidation.js';
import { redactCredential, redactDeep } from './credentialGuard.js';
import { buildAuthHeader, detectAuthType } from './authDetection.js';
import {
    buildPolicyBlockMessage,
    checkCredentialPolicy,
    getCredentialPolicy,
    isDomainAllowed,
    listCredentialPolicies,
    normalizeDomain,
    removeCredentialPolicy,
    saveCredentialPolicy,
} from './credentialPolicy.js';
import { prepareDB } from '../database/prepare.js';
import Database from 'better-sqlite3';
import {
    pickResponseFields,
    decodeBase64Content,
    truncateResponse,
    buildRequestHeaders,
    describeRequestError,
    hasControlCharacters,
} from './apiCall.js';
import { matchesTitle } from './vaultSearch.js';
import fs from 'node:fs';
import os from 'node:os';
import nodePath from 'node:path';
import { logMcpAuditEvent, readLastAuditLogs, isValidAuditEvent, type McpAuditEvent } from './auditLog.js';
import { generateHttpToken, timingSafeBearerCompare, checkBearerAuth } from './httpAuth.js';
import { createSearchRateLimiter, MAX_SEARCHES_PER_MINUTE, MAX_SEARCHES_PER_SESSION } from './rateLimiter.js';
import {
    buildHttpServer,
    isAllowedHost,
    idleShutdownMessage,
    runHttpTransport,
    HTTP_TOKEN_ENV_VAR,
    parseIdleTimeoutMinutes,
    MAX_IDLE_TIMEOUT_MINUTES,
} from './httpTransport.js';
import { createVaultSyncer, MIN_SYNC_INTERVAL_MS } from './vaultSync.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import winston from 'winston';
import { initLogger, logger, useStderrForLogs } from '../../logger.js';
import { askMasterPassword, disablePrompts, enablePrompts } from '../../utils/dialogs.js';
import { z } from 'zod';

// --- SessionTokenManager ---

describe('SessionTokenManager', () => {
    it('encrypt then decrypt returns the original ID', () => {
        const manager = new SessionTokenManager();
        const realId = '{727870B8-D60D-499F-8CDE-8CE805C1E3F4}';
        const token = manager.encrypt(realId);
        const decrypted = manager.decrypt(token);
        assert(decrypted === realId, `Expected ${realId}, got ${decrypted}`);
    });

    it('encrypted token is not the same as the original ID', () => {
        const manager = new SessionTokenManager();
        const realId = '{727870B8-D60D-499F-8CDE-8CE805C1E3F4}';
        const token = manager.encrypt(realId);
        assert(token !== realId, 'Token should not equal the real ID');
    });

    it('different session managers produce different tokens for the same ID', () => {
        const manager1 = new SessionTokenManager();
        const manager2 = new SessionTokenManager();
        const realId = '{727870B8-D60D-499F-8CDE-8CE805C1E3F4}';
        const token1 = manager1.encrypt(realId);
        const token2 = manager2.encrypt(realId);
        assert(token1 !== token2, 'Different managers should produce different tokens');
    });

    it('token from one manager cannot be decrypted by another', () => {
        const manager1 = new SessionTokenManager();
        const manager2 = new SessionTokenManager();
        const realId = '{727870B8-D60D-499F-8CDE-8CE805C1E3F4}';
        const token = manager1.encrypt(realId);
        const decrypted = manager2.decrypt(token);
        assert(decrypted === null, 'Cross-manager decrypt should return null');
    });

    it('invalid token returns null', () => {
        const manager = new SessionTokenManager();
        assert(manager.decrypt('totally-invalid-token') === null, 'Invalid token should return null');
        assert(manager.decrypt('') === null, 'Empty string should return null');
    });

    it('encrypting the same ID twice produces different tokens', () => {
        const manager = new SessionTokenManager();
        const realId = '{727870B8-D60D-499F-8CDE-8CE805C1E3F4}';
        const token1 = manager.encrypt(realId);
        const token2 = manager.encrypt(realId);
        assert(token1 !== token2, 'Same ID should produce different tokens due to random IV');
    });

    it('both tokens from the same manager decrypt to the same ID', () => {
        const manager = new SessionTokenManager();
        const realId = '{727870B8-D60D-499F-8CDE-8CE805C1E3F4}';
        const token1 = manager.encrypt(realId);
        const token2 = manager.encrypt(realId);
        assert(manager.decrypt(token1) === realId, 'First token should decrypt correctly');
        assert(manager.decrypt(token2) === realId, 'Second token should decrypt correctly');
    });

    it('clear() invalidates tokens issued before it', () => {
        const manager = new SessionTokenManager();
        const realId = '{727870B8-D60D-499F-8CDE-8CE805C1E3F4}';
        const token = manager.encrypt(realId);
        manager.clear();
        assert(manager.decrypt(token) === null, 'Token issued before clear() should no longer decrypt');
        assert(manager.decrypt(manager.encrypt(realId)) === realId, 'Manager should keep working after clear()');
    });
});

// --- isPrivateIp ---

describe('isPrivateIp', () => {
    it('detects IPv4 private ranges', () => {
        assert(isPrivateIp('10.0.0.1') === true, '10.x should be private');
        assert(isPrivateIp('10.255.255.255') === true, '10.x should be private');
        assert(isPrivateIp('172.16.0.1') === true, '172.16.x should be private');
        assert(isPrivateIp('172.31.255.255') === true, '172.31.x should be private');
        assert(isPrivateIp('192.168.0.1') === true, '192.168.x should be private');
        assert(isPrivateIp('192.168.255.255') === true, '192.168.x should be private');
        assert(isPrivateIp('169.254.169.254') === true, '169.254.x should be private (cloud metadata)');
        assert(isPrivateIp('127.0.0.1') === true, '127.x should be private (loopback)');
        assert(isPrivateIp('0.0.0.0') === true, '0.0.0.0 should be private');
    });

    it('allows public IPv4 addresses', () => {
        assert(isPrivateIp('8.8.8.8') === false, 'Google DNS should be public');
        assert(isPrivateIp('140.82.121.3') === false, 'GitHub IP should be public');
        assert(isPrivateIp('172.15.0.1') === false, '172.15.x is outside the private range');
        assert(isPrivateIp('172.32.0.1') === false, '172.32.x is outside the private range');
    });

    it('detects IPv6 private/reserved addresses', () => {
        assert(isPrivateIp('::1') === true, 'IPv6 loopback should be private');
        assert(isPrivateIp('fe80::1') === true, 'IPv6 link-local should be private');
        assert(isPrivateIp('fc00::1') === true, 'IPv6 unique local (fc) should be private');
        assert(isPrivateIp('fd00::1') === true, 'IPv6 unique local (fd) should be private');
    });

    it('detects IPv4-mapped IPv6 addresses', () => {
        assert(isPrivateIp('::ffff:127.0.0.1') === true, 'IPv4-mapped loopback should be private');
        assert(isPrivateIp('::ffff:10.0.0.1') === true, 'IPv4-mapped 10.x should be private');
        assert(isPrivateIp('::ffff:192.168.1.1') === true, 'IPv4-mapped 192.168.x should be private');
        assert(isPrivateIp('::ffff:169.254.169.254') === true, 'IPv4-mapped metadata should be private');
    });
});

// --- validateUrl ---

describe('validateUrl', () => {
    it('allows valid HTTPS URLs', async () => {
        const result = await validateUrl('https://api.github.com/user/repos');
        assert(result.safe === true, 'Public HTTPS URL should be safe');
    });

    it('blocks HTTP URLs', async () => {
        const result = await validateUrl('http://api.github.com/user/repos');
        assert(result.safe === false, 'HTTP should be blocked');
        assert(result.reason === 'Only HTTPS URLs are allowed', `Wrong reason: ${result.reason}`);
    });

    it('blocks invalid URLs', async () => {
        const result = await validateUrl('not-a-url');
        assert(result.safe === false, 'Invalid URL should be blocked');
        assert(result.reason === 'Invalid URL', `Wrong reason: ${result.reason}`);
    });

    it('blocks localhost', async () => {
        const result = await validateUrl('https://localhost/api');
        assert(result.safe === false, 'Localhost should be blocked');
    });

    it('blocks 0.0.0.0', async () => {
        const result = await validateUrl('https://0.0.0.0/api');
        assert(result.safe === false, '0.0.0.0 should be blocked');
    });

    it('blocks private IP addresses', async () => {
        const privateUrls = [
            'https://10.0.0.1/api',
            'https://172.16.0.1/api',
            'https://192.168.1.1/api',
            'https://169.254.169.254/latest/meta-data/',
            'https://127.0.0.1/api',
        ];
        for (const url of privateUrls) {
            const result = await validateUrl(url);
            assert(result.safe === false, `${url} should be blocked`);
        }
    });
});

// --- credentialGuard ---

describe('redactCredential', () => {
    it('masks a raw token echoed in a response', () => {
        const out = redactCredential('{"Authorization":"Bearer ghp_secret123"}', 'ghp_secret123');
        assert(!out.includes('ghp_secret123'), `Token leaked: ${out}`);
        assert(out.includes('[REDACTED]'));
    });

    it('masks the decoded user:password of a Basic credential', () => {
        const encoded = Buffer.from('user:pass').toString('base64');
        const out = redactCredential(`${encoded} and user:pass`, encoded);
        assert(!out.includes(encoded) && !out.includes('user:pass'), `Credential leaked: ${out}`);
    });

    it('leaves text unchanged for an empty credential', () => {
        assert(redactCredential('hello', '') === 'hello');
    });

    it('masks every occurrence of the same secret', () => {
        const out = redactCredential('ghp_secret123 and ghp_secret123, again ghp_secret123', 'ghp_secret123');
        assert(!out.includes('ghp_secret123'), `Token leaked: ${out}`);
        assert(out.split('[REDACTED]').length - 1 === 3, `Expected 3 redactions: ${out}`);
    });

    it('masks a token inside base64 content after decoding', () => {
        const body = { encoding: 'base64', content: Buffer.from('TOKEN=ghp_secret123').toString('base64') };
        const out = JSON.stringify(redactDeep(decodeBase64Content(body), 'ghp_secret123'));
        assert(!out.includes('ghp_secret123'), `Token leaked: ${out}`);
    });

    it('masks a token with "/" that the server escaped in JSON', () => {
        const token = 'abc/def+ghi';
        const parsed: unknown = JSON.parse('{"echo":"abc\\/def+ghi"}');
        const out = JSON.stringify(redactDeep(parsed, token));
        assert(!out.includes('def+ghi'), `Token leaked: ${out}`);
    });
});

// --- detectAuthType ---

describe('detectAuthType', () => {
    it('returns Bearer for a typical API token', () => {
        const result = detectAuthType('ghp_abc123def456');
        assert(result.scheme === 'Bearer', `Expected Bearer, got ${result.scheme}`);
        assert(result.headerValue === 'Bearer ghp_abc123def456', `Wrong header value: ${result.headerValue}`);
    });

    it('returns Bearer for a JWT token', () => {
        const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123';
        const result = detectAuthType(jwt);
        assert(result.scheme === 'Bearer', 'JWT should be detected as Bearer');
    });

    it('returns Basic for valid base64-encoded user:password', () => {
        const encoded = Buffer.from('myuser:mypassword').toString('base64');
        const result = detectAuthType(encoded);
        assert(result.scheme === 'Basic', `Expected Basic, got ${result.scheme}`);
        assert(result.headerValue === `Basic ${encoded}`, `Wrong header value: ${result.headerValue}`);
    });

    it('returns Bearer for base64 without colon', () => {
        const encoded = Buffer.from('just-a-token').toString('base64');
        const result = detectAuthType(encoded);
        assert(result.scheme === 'Bearer', 'Base64 without colon should be Bearer');
    });

    it('returns Bearer for base64 with empty username', () => {
        const encoded = Buffer.from(':password').toString('base64');
        const result = detectAuthType(encoded);
        assert(result.scheme === 'Bearer', 'Empty username should not trigger Basic');
    });

    it('returns Bearer for base64 with empty password', () => {
        const encoded = Buffer.from('user:').toString('base64');
        const result = detectAuthType(encoded);
        assert(result.scheme === 'Bearer', 'Empty password should not trigger Basic');
    });

    it('returns Bearer for an empty string', () => {
        const result = detectAuthType('');
        assert(result.scheme === 'Bearer', 'Empty string should default to Bearer');
    });
});

// --- pickResponseFields ---

describe('pickResponseFields', () => {
    it('picks specified fields from a flat object', () => {
        const obj = { name: 'test', language: 'js', forks_url: 'https://...', id: 123 };
        const result = pickResponseFields(obj, ['name', 'language']) as Record<string, unknown>;
        assert(result.name === 'test', 'Should include name');
        assert(result.language === 'js', 'Should include language');
        assert(!('forks_url' in result), 'Should not include forks_url');
        assert(!('id' in result), 'Should not include id');
    });

    it('picks fields from each item in an array', () => {
        const arr = [
            { name: 'repo1', language: 'ts', forks_url: 'https://...' },
            { name: 'repo2', language: 'py', forks_url: 'https://...' },
        ];
        const result = pickResponseFields(arr, ['name', 'language']) as Record<string, unknown>[];
        assert(result.length === 2, 'Should have 2 items');
        assert(result[0].name === 'repo1', 'First item name');
        assert(!('forks_url' in result[0]), 'Should not include forks_url');
    });

    it('recurses into nested arrays when no fields match the outer object', () => {
        const nested = {
            total_count: 100,
            items: [
                { name: 'repo1', language: 'ts', forks_url: 'https://...' },
                { name: 'repo2', language: 'py', forks_url: 'https://...' },
            ],
        };
        const result = pickResponseFields(nested, ['name', 'language']) as Record<string, unknown>;
        assert(result.total_count === 100, 'Should preserve scalar fields');
        const items = result.items as Record<string, unknown>[];
        assert(items.length === 2, 'Should have 2 items');
        assert(items[0].name === 'repo1', 'Nested item name');
        assert(!('forks_url' in items[0]), 'Should not include forks_url in nested items');
    });

    it('returns primitives unchanged', () => {
        assert(pickResponseFields('hello', ['name']) === 'hello', 'String should pass through');
        assert(pickResponseFields(42, ['name']) === 42, 'Number should pass through');
        assert(pickResponseFields(null, ['name']) === null, 'Null should pass through');
    });
});

// --- decodeBase64Content ---

describe('decodeBase64Content', () => {
    it('decodes base64 content when encoding field is present', () => {
        const encoded = Buffer.from('Hello, World!').toString('base64');
        const obj = { content: encoded, encoding: 'base64', name: 'test.txt' };
        const result = decodeBase64Content(obj) as Record<string, unknown>;
        assert(result.content === 'Hello, World!', `Expected decoded content, got: ${String(result.content)}`);
        assert(result.encoding === 'utf-8', 'Encoding should be updated to utf-8');
        assert(result.name === 'test.txt', 'Other fields should be preserved');
    });

    it('leaves non-base64 objects unchanged', () => {
        const obj = { content: 'plain text', name: 'test.txt' };
        const result = decodeBase64Content(obj) as Record<string, unknown>;
        assert(result.content === 'plain text', 'Should not modify non-base64 content');
    });

    it('leaves arrays unchanged', () => {
        const arr = [{ content: 'test', encoding: 'base64' }];
        const result = decodeBase64Content(arr);
        assert(Array.isArray(result), 'Arrays should pass through');
    });

    it('leaves primitives unchanged', () => {
        assert(decodeBase64Content('hello') === 'hello', 'Strings should pass through');
        assert(decodeBase64Content(null) === null, 'Null should pass through');
    });
});

// --- truncateResponse ---

describe('truncateResponse', () => {
    it('does not truncate small arrays', () => {
        const arr = [{ name: 'a' }, { name: 'b' }];
        const result = truncateResponse(arr, 50_000);
        assert(result.truncated === false, 'Should not be truncated');
        assert(result.totalItems === 2, 'Total should be 2');
        assert(result.returnedItems === 2, 'Returned should be 2');
    });

    it('truncates arrays that exceed the limit', () => {
        const arr = Array.from({ length: 1000 }, (_, i) => ({
            name: `item-${i}`,
            description: 'A'.repeat(200),
        }));
        const result = truncateResponse(arr, 5_000);
        assert(result.truncated === true, 'Should be truncated');
        assert(result.totalItems === 1000, 'Total should be 1000');
        assert(result.returnedItems < 1000, `Returned (${result.returnedItems}) should be less than total`);
        assert(result.returnedItems > 0, 'Should return at least 1 item');
        assert(JSON.stringify(result.body).length <= 5_000, 'Result should fit within limit');
    });

    it('returns non-arrays unchanged', () => {
        const obj = { name: 'test' };
        const result = truncateResponse(obj, 50_000);
        assert(result.truncated === false, 'Objects should not be truncated');
        assert((result.body as Record<string, unknown>).name === 'test', 'Object should pass through');
    });

    it('handles empty arrays', () => {
        const result = truncateResponse([], 50_000);
        assert(result.truncated === false, 'Empty arrays should not be truncated');
        assert(result.totalItems === 0, 'Total should be 0');
    });
});

// --- Audit logging ---

describe('Audit logging', () => {
    it('logMcpAuditEvent does not throw', () => {
        const event: McpAuditEvent = {
            schema_version: '1.0',
            category: 'McpAgentAccess',
            timestamp: new Date().toISOString(),
            tool: 'search_vault',
            status: 'success',
            query: 'github',
            result_count: 1,
        };
        assert.doesNotThrow(() => logMcpAuditEvent(event), 'logMcpAuditEvent should never throw');
    });

    it('readLastAuditLogs returns an array', async () => {
        const logs = await readLastAuditLogs(10);
        assert(Array.isArray(logs), 'Should return an array');
    });

    it('logMcpAuditEvent followed by readLastAuditLogs round-trips', async () => {
        const event: McpAuditEvent = {
            schema_version: '1.0',
            category: 'McpAgentAccess',
            timestamp: new Date().toISOString(),
            tool: 'search_vault',
            status: 'success',
            query: 'test-round-trip',
            result_count: 42,
        };
        logMcpAuditEvent(event);

        const logs = await readLastAuditLogs(1);
        assert(logs.length >= 1, 'Should have at least 1 log entry');
        const latest = logs[0];
        assert(latest.tool === 'search_vault', `Expected search_vault, got ${latest.tool}`);
        assert(latest.status === 'success', `Expected success, got ${latest.status}`);
    });
});

// --- HTTP bearer auth ---

describe('HTTP bearer auth', () => {
    it('generateHttpToken returns a 32-byte base64url string', () => {
        const token = generateHttpToken();
        assert(typeof token === 'string' && token.length > 0, 'token should be a non-empty string');
        assert(Buffer.from(token, 'base64url').length === 32, 'token should decode to 32 bytes');
    });

    it('generateHttpToken returns distinct tokens', () => {
        assert(generateHttpToken() !== generateHttpToken(), 'tokens should differ');
    });

    it('timingSafeBearerCompare matches identical tokens', () => {
        assert(timingSafeBearerCompare('abc123', 'abc123') === true, 'identical tokens should match');
    });

    it('timingSafeBearerCompare rejects different same-length tokens', () => {
        assert(timingSafeBearerCompare('abcdef', 'abcxyz') === false, 'different tokens should not match');
    });

    it('timingSafeBearerCompare rejects different-length tokens without throwing', () => {
        assert.doesNotThrow(() => timingSafeBearerCompare('short', 'a-much-longer-token'));
        assert(timingSafeBearerCompare('short', 'a-much-longer-token') === false, 'shorter vs longer');
        assert(timingSafeBearerCompare('a-much-longer-token', 'short') === false, 'longer vs shorter');
        assert(timingSafeBearerCompare('', 'x') === false, 'empty vs non-empty');
    });

    it('checkBearerAuth classifies header states', () => {
        assert(checkBearerAuth(undefined, 'tok') === 'missing_token', 'no header should be missing_token');
        assert(checkBearerAuth('Basic xyz', 'tok') === 'missing_token', 'non-bearer scheme should be missing_token');
        assert(checkBearerAuth('Bearer wrong', 'tok') === 'invalid_token', 'wrong token should be invalid_token');
        assert(checkBearerAuth('Bearer tok', 'tok') === 'ok', 'correct token should be ok');
    });
});

// --- Search rate limiter ---

describe('createSearchRateLimiter', () => {
    it('allows the first searches then trips the per-minute limit', () => {
        const limiter = createSearchRateLimiter();
        for (let i = 0; i < MAX_SEARCHES_PER_MINUTE; i++) {
            assert(limiter.check() === null, `call ${i + 1} should be allowed`);
        }
        assert(limiter.check() === 'minute', 'should trip the per-minute limit');
    });

    it('trips the session limit once the session cap is exceeded', () => {
        const limiter = createSearchRateLimiter();
        let last = limiter.check();
        for (let i = 0; i < MAX_SEARCHES_PER_SESSION; i++) {
            last = limiter.check();
        }
        assert(last === 'session', `expected session limit, got ${JSON.stringify(last)}`);
    });
});

// --- Host header allow-list (DNS-rebinding protection) ---

describe('isAllowedHost', () => {
    it('accepts loopback and container hostnames (any port)', () => {
        assert(isAllowedHost('127.0.0.1:3277') === true, '127.0.0.1 should be allowed');
        assert(isAllowedHost('localhost:3277') === true, 'localhost should be allowed');
        assert(isAllowedHost('host.docker.internal:3277') === true, 'host.docker.internal should be allowed');
        assert(isAllowedHost('host.containers.internal:3277') === true, 'host.containers.internal should be allowed');
        assert(isAllowedHost('[::1]:3277') === true, 'IPv6 loopback should be allowed');
    });

    it('rejects unknown or missing hosts', () => {
        assert(isAllowedHost('evil.com') === false, 'arbitrary host should be rejected');
        assert(isAllowedHost('evil.com:3277') === false, 'arbitrary host with port should be rejected');
        assert(isAllowedHost('169.254.169.254') === false, 'metadata IP should be rejected');
        assert(isAllowedHost(undefined) === false, 'missing host should be rejected');
        assert(isAllowedHost('') === false, 'empty host should be rejected');
    });
});

// --- HTTP transport (integration) ---

const HTTP_TEST_TOKEN = 'integration-test-token';

const VAULT_TOOL_NAMES = ['search_vault', 'call_api', 'call_api_batch', 'sync_vault', 'get_audit_logs'];

// A minimal server with the same tool names, to exercise the transport without
// pulling the command-handler (and its dependencies) into the test type-check.
const testServerFactory = (): McpServer => {
    const server = new McpServer({ name: 'test-vault-mcp', version: '0.0.0' });
    for (const name of VAULT_TOOL_NAMES) {
        server.registerTool(name, { description: name, inputSchema: { q: z.string().optional() } }, () => ({
            content: [{ type: 'text', text: 'ok' }],
        }));
    }
    return server;
};

interface RawHttpResult {
    status: number;
    headers: http.IncomingHttpHeaders;
    body: string;
}

const rawRequest = (
    baseUrl: string,
    opts: { method?: string; headers?: Record<string, string>; body?: unknown }
): Promise<RawHttpResult> =>
    new Promise((resolve, reject) => {
        const u = new URL(baseUrl);
        const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
        const req = http.request(
            {
                hostname: u.hostname,
                port: u.port,
                path: u.pathname,
                method: opts.method ?? 'POST',
                headers: opts.headers,
                agent: false,
            },
            (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });
                res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data }));
            }
        );
        req.on('error', reject);
        if (payload !== undefined) {
            req.write(payload);
        }
        req.end();
    });

const initBody = {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } },
};

const jsonHeaders = (extra: Record<string, string> = {}): Record<string, string> => ({
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    ...extra,
});

describe('Vault MCP HTTP transport', function () {
    this.timeout(10000);
    let server: http.Server | undefined;
    let baseUrl = '';
    let canBindSocket = true;

    // Some sandboxed environments forbid binding sockets; detect once and skip if so.
    before((done) => {
        const probe = http.createServer();
        probe.once('error', () => {
            canBindSocket = false;
            done();
        });
        probe.listen(0, '127.0.0.1', () => {
            probe.close(() => done());
        });
    });

    beforeEach(function (done) {
        if (!canBindSocket) {
            this.skip();
            return;
        }
        const candidate = buildHttpServer(testServerFactory, HTTP_TEST_TOKEN);
        candidate.listen(0, '127.0.0.1', () => {
            server = candidate;
            baseUrl = `http://127.0.0.1:${(candidate.address() as AddressInfo).port}/mcp`;
            done();
        });
    });

    afterEach((done) => {
        if (server) {
            const s = server;
            server = undefined;
            s.close(() => done());
        } else {
            done();
        }
    });

    it('binds to loopback only', () => {
        const address = server?.address();
        assert(
            !!address && typeof address === 'object' && address.address === '127.0.0.1',
            `expected 127.0.0.1, got ${JSON.stringify(address)}`
        );
    });

    it('rejects requests with no token (401)', async () => {
        const res = await rawRequest(baseUrl, { headers: jsonHeaders(), body: initBody });
        assert(res.status === 401, `expected 401, got ${res.status}`);
    });

    it('rejects requests with a wrong token (401)', async () => {
        const res = await rawRequest(baseUrl, {
            headers: jsonHeaders({ Authorization: 'Bearer nope' }),
            body: initBody,
        });
        assert(res.status === 401, `expected 401, got ${res.status}`);
    });

    it('accepts initialize with the correct token and returns server info', async () => {
        const res = await rawRequest(baseUrl, {
            headers: jsonHeaders({ Authorization: `Bearer ${HTTP_TEST_TOKEN}` }),
            body: initBody,
        });
        assert(res.status === 200, `expected 200, got ${res.status}: ${res.body}`);
        const parsed = JSON.parse(res.body) as { result?: { serverInfo?: unknown } };
        assert(!!parsed.result?.serverInfo, 'response should include serverInfo');
        assert(typeof res.headers['mcp-session-id'] === 'string', 'should return a session id');
    });

    it('lists the four vault tools over an initialized session', async () => {
        const init = await rawRequest(baseUrl, {
            headers: jsonHeaders({ Authorization: `Bearer ${HTTP_TEST_TOKEN}` }),
            body: initBody,
        });
        const sessionId = init.headers['mcp-session-id'] as string;

        // Complete the MCP handshake before issuing operations.
        await rawRequest(baseUrl, {
            headers: jsonHeaders({ Authorization: `Bearer ${HTTP_TEST_TOKEN}`, 'mcp-session-id': sessionId }),
            body: { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
        });

        const res = await rawRequest(baseUrl, {
            headers: jsonHeaders({ Authorization: `Bearer ${HTTP_TEST_TOKEN}`, 'mcp-session-id': sessionId }),
            body: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
        });
        assert(res.status === 200, `expected 200, got ${res.status}: ${res.body}`);
        const parsed = JSON.parse(res.body) as { result?: { tools?: { name: string }[] } };
        const names = (parsed.result?.tools ?? []).map((t) => t.name).sort();
        assert(
            JSON.stringify(names) ===
                JSON.stringify(['call_api', 'call_api_batch', 'get_audit_logs', 'search_vault', 'sync_vault']),
            `unexpected tools: ${JSON.stringify(names)}`
        );
    });

    it('rejects a forged Host header (403)', async () => {
        const res = await rawRequest(baseUrl, {
            headers: jsonHeaders({ Authorization: `Bearer ${HTTP_TEST_TOKEN}`, Host: 'evil.com' }),
            body: initBody,
        });
        assert(res.status === 403, `expected 403, got ${res.status}`);
    });

    it('allows the host.docker.internal alias (dev container reachability)', async () => {
        const port = new URL(baseUrl).port;
        const res = await rawRequest(baseUrl, {
            headers: jsonHeaders({ Authorization: `Bearer ${HTTP_TEST_TOKEN}`, Host: `host.docker.internal:${port}` }),
            body: initBody,
        });
        assert(res.status === 200, `expected 200, got ${res.status}: ${res.body}`);
    });
});

// --- HTTP idle shutdown ---

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe('Vault MCP HTTP idle shutdown', function () {
    this.timeout(10000);
    const IDLE_MS = 50;
    let server: http.Server | undefined;
    let baseUrl = '';
    let idleCallCount = 0;
    // A function, so TypeScript does not narrow the count across the awaits below.
    const idleCalls = (): number => idleCallCount;
    let canBindSocket = true;

    before((done) => {
        const probe = http.createServer();
        probe.once('error', () => {
            canBindSocket = false;
            done();
        });
        probe.listen(0, '127.0.0.1', () => {
            probe.close(() => done());
        });
    });

    const start = (timeoutMs: number): Promise<void> =>
        new Promise((resolve) => {
            idleCallCount = 0;
            const candidate = buildHttpServer(testServerFactory, HTTP_TEST_TOKEN, {
                timeoutMs,
                onIdle: () => {
                    idleCallCount += 1;
                },
            });
            candidate.listen(0, '127.0.0.1', () => {
                server = candidate;
                baseUrl = `http://127.0.0.1:${(candidate.address() as AddressInfo).port}/mcp`;
                resolve();
            });
        });

    const authedRequest = () =>
        rawRequest(baseUrl, { headers: jsonHeaders({ Authorization: `Bearer ${HTTP_TEST_TOKEN}` }), body: initBody });

    beforeEach(function () {
        if (!canBindSocket) {
            this.skip();
        }
    });

    afterEach((done) => {
        if (server) {
            const s = server;
            server = undefined;
            s.close(() => done());
            s.closeAllConnections();
        } else {
            done();
        }
    });

    it('calls onIdle once after the timeout with no requests', async () => {
        await start(IDLE_MS);
        await sleep(IDLE_MS * 4);
        assert(idleCalls() === 1, `expected onIdle to fire once, fired ${idleCalls()} times`);
    });

    it('does not fire while authenticated requests keep arriving', async () => {
        // Requests every IDLE_MS against a 10x timeout leaves a wide margin for slow CI machines.
        await start(IDLE_MS * 10);
        for (let i = 0; i < 6; i++) {
            await sleep(IDLE_MS);
            const res = await authedRequest();
            assert(res.status === 200, `expected 200, got ${res.status}`);
        }
        assert(idleCalls() === 0, 'onIdle fired although requests were still arriving');
        await sleep(IDLE_MS * 14);
        assert(idleCalls() === 1, `expected onIdle to fire after the requests stopped, fired ${idleCalls()} times`);
    });

    it('does not restart the timer for requests with a wrong token', async () => {
        await start(IDLE_MS * 3);
        for (let i = 0; i < 6; i++) {
            await sleep(IDLE_MS);
            const res = await rawRequest(baseUrl, {
                headers: jsonHeaders({ Authorization: 'Bearer nope' }),
                body: initBody,
            });
            assert(res.status === 401, `expected 401, got ${res.status}`);
        }
        assert(idleCalls() === 1, `expected onIdle to fire despite rejected requests, fired ${idleCalls()} times`);
    });

    it('never fires when the timeout is 0', async () => {
        await start(0);
        await sleep(IDLE_MS * 4);
        assert(idleCalls() === 0, 'onIdle should never fire with a timeout of 0');
    });

    it('does not fire after the server has been closed', async () => {
        await start(IDLE_MS * 2);
        const s = server as http.Server;
        server = undefined;
        await new Promise<void>((resolve) => s.close(() => resolve()));
        await sleep(IDLE_MS * 5);
        assert(idleCalls() === 0, 'onIdle should not fire once the server is closed');
    });

    it('does not start the timer until the server is listening', async () => {
        idleCallCount = 0;
        const unstarted = buildHttpServer(testServerFactory, HTTP_TEST_TOKEN, {
            timeoutMs: IDLE_MS,
            onIdle: () => {
                idleCallCount += 1;
            },
        });
        await sleep(IDLE_MS * 4);
        assert(idleCalls() === 0, 'onIdle should not fire for a server that never listened');
        assert(!unstarted.listening, 'sanity: server should not be listening');
    });
});

describe('runHttpTransport idle shutdown', function () {
    this.timeout(10000);

    it('stops the server, runs onShutdown and writes the message to stderr', async function () {
        const writes: string[] = [];
        const realWrite = process.stderr.write.bind(process.stderr);
        process.stderr.write = ((chunk: string | Uint8Array) => {
            writes.push(String(chunk));
            return true;
        }) as typeof process.stderr.write;

        const signalListeners = () => process.listenerCount('SIGINT') + process.listenerCount('SIGTERM');
        const listenersBefore = signalListeners();
        let shutdownCalls = 0;
        try {
            // 0.001 minutes = 60 ms. Port 0 lets the OS pick a free port.
            await runHttpTransport(testServerFactory, {
                port: 0,
                idleTimeoutMinutes: 0.001,
                onShutdown: () => {
                    shutdownCalls += 1;
                },
            });
        } catch (error) {
            process.stderr.write = realWrite;
            if (
                (error as NodeJS.ErrnoException).code === 'EPERM' ||
                (error as NodeJS.ErrnoException).code === 'EACCES'
            ) {
                this.skip();
            }
            throw error;
        } finally {
            process.stderr.write = realWrite;
        }

        assert(shutdownCalls === 1, `expected onShutdown once, called ${shutdownCalls} times`);
        assert(signalListeners() === listenersBefore, 'SIGINT/SIGTERM listeners should be removed after shutdown');
        const expected = `${idleShutdownMessage(0.001)}\n`;
        assert(writes.includes(expected), `stderr should contain the idle message, got ${JSON.stringify(writes)}`);
    });
});

describe('runHttpTransport with an open SSE stream', function () {
    this.timeout(10000);

    const getFreePort = (): Promise<number> =>
        new Promise((resolve, reject) => {
            const probe = http.createServer();
            probe.once('error', reject);
            probe.listen(0, '127.0.0.1', () => {
                const { port } = probe.address() as AddressInfo;
                probe.close(() => resolve(port));
            });
        });

    it('still stops when an idle GET /mcp stream is open, and runs onShutdown once', async function () {
        let port: number;
        try {
            port = await getFreePort();
        } catch {
            this.skip();
            return;
        }
        const baseUrl = `http://127.0.0.1:${port}/mcp`;
        const authHeaders = { Authorization: `Bearer ${HTTP_TEST_TOKEN}` };

        const previousToken = process.env[HTTP_TOKEN_ENV_VAR];
        process.env[HTTP_TOKEN_ENV_VAR] = HTTP_TEST_TOKEN;
        const realWrite = process.stderr.write.bind(process.stderr);
        process.stderr.write = (() => true) as typeof process.stderr.write;

        let shutdownCalls = 0;
        try {
            // 0.01 minutes = 600 ms: long enough to open the stream, short enough for a fast test.
            const stopped = runHttpTransport(testServerFactory, {
                port,
                idleTimeoutMinutes: 0.01,
                onShutdown: () => {
                    shutdownCalls += 1;
                },
            });

            // The server has no "ready" signal: retry until it accepts the initialize request.
            let init: RawHttpResult | undefined;
            for (let attempt = 0; attempt < 40 && !init; attempt++) {
                init = await rawRequest(baseUrl, { headers: jsonHeaders(authHeaders), body: initBody }).catch(
                    () => undefined
                );
                if (!init) {
                    await sleep(25);
                }
            }
            assert(init?.status === 200, `expected 200 from initialize, got ${init?.status}`);
            const sessionId = init?.headers['mcp-session-id'] as string;

            // Open the SSE stream like Claude Code does, and never send anything else.
            let streamStatus = 0;
            let streamOpened!: () => void;
            const opened = new Promise<void>((resolve) => {
                streamOpened = resolve;
            });
            const streamClosed = new Promise<void>((resolve) => {
                const req = http.request(
                    {
                        hostname: '127.0.0.1',
                        port,
                        path: '/mcp',
                        method: 'GET',
                        agent: false,
                        headers: { ...authHeaders, Accept: 'text/event-stream', 'mcp-session-id': sessionId },
                    },
                    (res) => {
                        streamStatus = res.statusCode ?? 0;
                        res.resume();
                        res.on('close', resolve);
                        streamOpened();
                    }
                );
                req.on('error', () => resolve());
                req.end();
            });
            await opened;
            assert(streamStatus === 200, `expected the SSE stream to open (200), got ${streamStatus}`);

            await stopped;
            await streamClosed;
            assert(shutdownCalls === 1, `expected onShutdown once, called ${shutdownCalls} times`);
        } catch (error) {
            if (['EPERM', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '')) {
                this.skip();
            }
            throw error;
        } finally {
            process.stderr.write = realWrite;
            if (previousToken === undefined) {
                delete process.env[HTTP_TOKEN_ENV_VAR];
            } else {
                process.env[HTTP_TOKEN_ENV_VAR] = previousToken;
            }
        }
    });
});

describe('parseIdleTimeoutMinutes', () => {
    it('accepts 0, whole and fractional minutes', () => {
        assert(parseIdleTimeoutMinutes('0') === 0);
        assert(parseIdleTimeoutMinutes('30') === 30);
        assert(parseIdleTimeoutMinutes('0.5') === 0.5);
    });

    it('rejects negative, non-numeric, empty and too-large values', () => {
        for (const bad of ['-1', 'abc', '', ' ', 'NaN', 'Infinity', String(MAX_IDLE_TIMEOUT_MINUTES + 1)]) {
            assert.throws(() => parseIdleTimeoutMinutes(bad), undefined, undefined, `should reject "${bad}"`);
        }
    });
});

describe('idleShutdownMessage', () => {
    it('matches the documented message for the default timeout', () => {
        assert(
            idleShutdownMessage(30) ===
                'Stopped after 30 minutes without activity. Run dcli mcp --http again to continue.'
        );
    });

    it('uses the singular for one minute', () => {
        assert(idleShutdownMessage(1).startsWith('Stopped after 1 minute without activity.'));
    });
});

// --- HTTP auth audit events ---

describe('http_auth audit events', () => {
    it('isValidAuditEvent accepts an http_auth event (VALID_TOOLS extended)', () => {
        const event = {
            schema_version: '1.0',
            category: 'McpAgentAccess',
            timestamp: new Date().toISOString(),
            tool: 'http_auth',
            status: 'blocked',
            reason: 'invalid_token',
        };
        assert(isValidAuditEvent(event) === true, 'http_auth should be accepted as a valid audit tool');
        assert(isValidAuditEvent({ ...event, tool: 'bogus_tool' }) === false, 'unknown tools should be rejected');
    });

    it('logMcpAuditEvent does not throw for an http_auth event', () => {
        const event: McpAuditEvent = {
            schema_version: '1.0',
            category: 'McpAgentAccess',
            timestamp: new Date().toISOString(),
            tool: 'http_auth',
            status: 'blocked',
            reason: 'invalid_token',
        };
        assert.doesNotThrow(() => logMcpAuditEvent(event), 'logging an http_auth event should not throw');
    });
});

// --- Credential policy ---

describe('credentialPolicy', () => {
    const login = 'user@example.com';
    const item = { id: '{AAAA-1111}', title: 'GitHub PAT' };
    const newDb = () => {
        const db = new Database(':memory:');
        prepareDB({ db });
        return db;
    };
    const insertRaw = (db: Database.Database, id: string, allowedDomains: string, authScheme: string | null) =>
        db
            .prepare('INSERT INTO mcpPolicy (login, itemId, title, allowedDomains, authScheme) VALUES (?, ?, ?, ?, ?)')
            .run(login, id, 'GitHub PAT', allowedDomains, authScheme);

    it('returns null when there is no rule', () => {
        assert.isNull(getCredentialPolicy(newDb(), login, item));
    });

    it('returns null for a rule on another item', () => {
        const db = newDb();
        insertRaw(db, 'BBBB-2222', '["api.github.com"]', null);
        assert.isNull(getCredentialPolicy(db, login, item));
    });

    it('returns null for empty or malformed allowedDomains', () => {
        const db = newDb();
        insertRaw(db, 'AAAA-1111', '[]', null);
        assert.isNull(getCredentialPolicy(db, login, item));
        db.prepare('UPDATE mcpPolicy SET allowedDomains = ?').run('not json');
        assert.isNull(getCredentialPolicy(db, login, item));
        db.prepare('UPDATE mcpPolicy SET allowedDomains = ?').run('{"a":1}');
        assert.isNull(getCredentialPolicy(db, login, item));
    });

    it('reads allowedDomains and authScheme, drops an unknown scheme', () => {
        const db = newDb();
        insertRaw(db, 'AAAA-1111', '["api.github.com"]', 'Basic');
        assert.deepEqual(getCredentialPolicy(db, login, item), {
            allowedDomains: ['api.github.com'],
            authScheme: 'Basic',
        });
        db.prepare('UPDATE mcpPolicy SET authScheme = ?').run('Bad Scheme');
        assert.deepEqual(getCredentialPolicy(db, login, item), { allowedDomains: ['api.github.com'] });
    });

    it('matches exact hosts case-insensitively only', () => {
        assert.isTrue(isDomainAllowed('API.GitHub.com', ['api.github.com']));
        assert.isFalse(isDomainAllowed('github.com', ['api.github.com']));
        assert.isFalse(isDomainAllowed('api.github.com.evil.com', ['api.github.com']));
    });

    it('does not support wildcards', () => {
        assert.isFalse(isDomainAllowed('a.example.com', ['*.example.com']));
        assert.isFalse(isDomainAllowed('evil.com', ['*.com']));
        assert.isFalse(isDomainAllowed('evil.com', ['*']));
        assert.throws(() => normalizeDomain('*.github.io'));
    });

    it('ignores one trailing dot on the host', () => {
        assert.isTrue(isDomainAllowed('api.github.com.', ['api.github.com']));
        assert.isFalse(isDomainAllowed('api.github.com..', ['api.github.com']));
    });

    it('normalizeDomain converts IDN to ASCII', () => {
        assert.equal(normalizeDomain('münchen.de'), 'xn--mnchen-3ya.de');
    });

    it('drops invalid entries when reading rules', () => {
        const db = newDb();
        insertRaw(db, 'AAAA-1111', '["*.github.io","API.github.com","https://x.com",5]', null);
        assert.deepEqual(getCredentialPolicy(db, login, item), { allowedDomains: ['api.github.com'] });
    });

    it('blocks and allows the right URLs', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'api.github.com');
        const blocked = [
            'https://api.github.com@evil.com/',
            'https://api.github.com%2eevil.com/',
            'https://evil-github.com/',
            'https://api.github.com.evil.com/',
        ];
        for (const url of blocked) {
            assert.equal(checkCredentialPolicy(db, login, item, url).status, 'blocked', url);
        }
        for (const url of ['https://API.GITHUB.COM/x', 'https://api.github.com:8443/x', 'https://api.github.com./x']) {
            assert.equal(checkCredentialPolicy(db, login, item, url).status, 'allowed', url);
        }
    });

    it('quotes the title and host in the suggested command', () => {
        const message = buildPolicyBlockMessage({ id: 'x', title: '$(touch /tmp/x)' }, 'a.com', null);
        assert.include(message, "--title '$(touch /tmp/x)'");
        assert.include(message, 'Do not run it yourself');
        assert.notInclude(message, '--auth-scheme');
        const quoted = buildPolicyBlockMessage({ id: 'x', title: "it's" }, 'a.com', null);
        assert.include(quoted, "--title 'it'\\''s'");
    });

    it('keeps rules per item, not per title', () => {
        const db = newDb();
        const note = { id: '{BBBB-2222}', title: item.title };
        saveCredentialPolicy(db, login, item, 'api.github.com');
        assert.isNull(getCredentialPolicy(db, login, note));
        assert.equal(checkCredentialPolicy(db, login, note, 'https://api.github.com/').status, 'blocked');
        assert.isNotNull(getCredentialPolicy(db, login, { id: 'AAAA-1111', title: 'renamed' }));
    });

    it('drops an old title-keyed table so old rules are blocked', () => {
        const db = new Database(':memory:');
        db.prepare(
            'CREATE TABLE mcpPolicy (login VARCHAR(255), title VARCHAR(255), allowedDomains TEXT NOT NULL, authScheme VARCHAR(255), PRIMARY KEY (login, title))'
        ).run();
        prepareDB({ db });
        assert.isNull(getCredentialPolicy(db, login, item));
        saveCredentialPolicy(db, login, item, 'a.com');
        assert.isNotNull(getCredentialPolicy(db, login, item));
    });

    it('ignores the port when matching', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'api.github.com');
        assert.equal(checkCredentialPolicy(db, login, item, 'https://api.github.com:8443/x').status, 'allowed');
    });

    it('blocks httpbin.org with a helpful message', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'api.github.com');
        const result = checkCredentialPolicy(db, login, item, 'https://httpbin.org/get');
        assert.equal(result.status, 'blocked');
        if (result.status === 'blocked') {
            assert.include(result.message, 'GitHub PAT');
            assert.include(result.message, 'httpbin.org');
            assert.include(result.message, 'Allowed: api.github.com.');
            assert.include(result.message, 'dcli configure mcp-allow');
        }
    });

    it('blocks when there is no rule and the message has no Allowed line', () => {
        const result = checkCredentialPolicy(newDb(), login, item, 'https://httpbin.org/get');
        assert.equal(result.status, 'blocked');
        assert.notInclude(buildPolicyBlockMessage(item, 'httpbin.org', null), 'Allowed:');
    });

    it('returns the rule for an allowed host', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'api.github.com', 'Bearer');
        const result = checkCredentialPolicy(db, login, item, 'https://api.github.com/user');
        assert.deepEqual(result, {
            status: 'allowed',
            policy: { allowedDomains: ['api.github.com'], authScheme: 'Bearer' },
        });
    });

    it('saveCredentialPolicy adds domains without duplicates and updates the scheme', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'API.github.com');
        saveCredentialPolicy(db, login, item, 'uploads.github.com');
        saveCredentialPolicy(db, login, item, 'uploads.github.com');
        assert.deepEqual(getCredentialPolicy(db, login, item), {
            allowedDomains: ['api.github.com', 'uploads.github.com'],
        });
        saveCredentialPolicy(db, login, item, 'api.github.com', 'Basic');
        assert.equal(getCredentialPolicy(db, login, item)?.authScheme, 'Basic');
        saveCredentialPolicy(db, login, item, 'x.github.com');
        assert.equal(getCredentialPolicy(db, login, item)?.authScheme, 'Basic');
    });

    it('saveCredentialPolicy rejects bad domains', () => {
        const db = newDb();
        for (const bad of [
            'https://api.github.com',
            'api.github.com/path',
            'api.github.com:8443',
            '*.com',
            '*.github.io',
            '*',
            '',
        ]) {
            assert.throws(() => saveCredentialPolicy(db, login, item, bad), Error, undefined, bad);
        }
    });

    it('accepts any simple scheme word and rejects unsafe ones', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'a.com', 'Token');
        assert.equal(getCredentialPolicy(db, login, item)?.authScheme, 'Token');
        for (const bad of ['Bad Scheme', 'Bearer\r\nX-Evil: 1', '', 'a'.repeat(65)]) {
            assert.throws(() => saveCredentialPolicy(db, login, item, 'a.com', bad), Error, undefined, bad);
        }
    });

    it('keeps rules separate per login', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'api.github.com');
        assert.isNull(getCredentialPolicy(db, 'other@example.com', item));
    });

    it('listCredentialPolicies lists valid rules of this login, sorted', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, { id: 'b', title: 'B' }, 'b.com', 'Bearer');
        saveCredentialPolicy(db, login, { id: 'a', title: 'A' }, 'a.com');
        saveCredentialPolicy(db, 'other@example.com', { id: 'c', title: 'C' }, 'c.com');
        insertRaw(db, 'broken', 'not json', null);
        assert.deepEqual(listCredentialPolicies(db, login), [
            { id: 'a', title: 'A', allowedDomains: ['a.com'] },
            { id: 'b', title: 'B', allowedDomains: ['b.com'], authScheme: 'Bearer' },
        ]);
    });

    it('removeCredentialPolicy removes one domain, then the whole rule', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'a.com', 'Bearer');
        saveCredentialPolicy(db, login, item, 'b.com');
        assert.isFalse(removeCredentialPolicy(db, login, item.id, 'zzz.com'));
        assert.isTrue(removeCredentialPolicy(db, login, item.id, 'A.com'));
        assert.deepEqual(getCredentialPolicy(db, login, item), { allowedDomains: ['b.com'], authScheme: 'Bearer' });
        assert.isTrue(removeCredentialPolicy(db, login, item.id, 'b.com'));
        assert.isNull(getCredentialPolicy(db, login, item));
        assert.isFalse(removeCredentialPolicy(db, login, item.id));
    });

    it('removeCredentialPolicy without a domain deletes the rule, only for this login', () => {
        const db = newDb();
        saveCredentialPolicy(db, login, item, 'a.com');
        saveCredentialPolicy(db, 'other@example.com', item, 'a.com');
        assert.isTrue(removeCredentialPolicy(db, login, item.id));
        assert.isNull(getCredentialPolicy(db, login, item));
        assert.isNotNull(getCredentialPolicy(db, 'other@example.com', item));
    });

    it('buildAuthHeader sets the scheme and overrides detectAuthType', () => {
        assert.equal(buildAuthHeader('Bearer', 'abc').headerValue, 'Bearer abc');
        const b64 = Buffer.from('user:pass').toString('base64');
        assert.equal(detectAuthType(b64).scheme, 'Basic');
        assert.equal(buildAuthHeader('Bearer', b64).headerValue, `Bearer ${b64}`);
        assert.equal(buildAuthHeader('Basic', b64).headerValue, `Basic ${b64}`);
        assert.equal(buildAuthHeader('Token', 'abc').headerValue, 'Token abc');
    });
});

// --- stdio safety ---

describe('stdio safety', () => {
    // disablePrompts and useStderrForLogs change global state: reset it so other tests are not affected
    afterEach(() => {
        enablePrompts();
        initLogger({ debugLevel: 'info' });
    });

    it('sends every log level to stderr', () => {
        initLogger({ debugLevel: 'info' });
        useStderrForLogs();
        // winston types stderrLevels as string[], but the Console transport stores it as a lookup object
        const consoleTransport = logger.transports.find((t) => t instanceof winston.transports.Console) as unknown as
            | { stderrLevels: Record<string, boolean> }
            | undefined;
        assert(consoleTransport, 'Console transport missing');
        for (const level of ['error', 'warn', 'info', 'success', 'content', 'debug']) {
            assert(consoleTransport.stderrLevels[level], `Level "${level}" would go to stdout`);
        }
    });

    it('fails with a reason that names the question instead of prompting', async () => {
        disablePrompts((question) => `cannot ask "${question}" in MCP mode`);
        let message = '';
        try {
            await askMasterPassword();
        } catch (error) {
            message = (error as Error).message;
        }
        assert(
            message === 'cannot ask "Please enter your master password" in MCP mode',
            `Expected the question in the reason, got: "${message}"`
        );
    });
});

// --- vault sync (sync_vault tool) ---

describe('createVaultSyncer', () => {
    it('runs the sync and returns the number of changes', async () => {
        const syncer = createVaultSyncer(() => Promise.resolve(3));
        const result = await syncer.sync();
        assert(result.status === 'synced' && result.changes === 3, JSON.stringify(result));
    });

    it('shares one sync between calls made while it is running', async () => {
        let runs = 0;
        let finish: (changes: number) => void = () => undefined;
        const syncer = createVaultSyncer(() => {
            runs++;
            return new Promise<number>((resolve) => (finish = resolve));
        });
        const first = syncer.sync();
        const second = syncer.sync();
        finish(1);
        await Promise.all([first, second]);
        assert(runs === 1, `Expected 1 sync, got ${runs}`);
    });

    it('skips a new sync during the cooldown and says when to retry', async () => {
        let clock = 1_000_000;
        let runs = 0;
        const syncer = createVaultSyncer(
            () => {
                runs++;
                return Promise.resolve(0);
            },
            () => clock
        );
        await syncer.sync();
        clock += 10_000;
        const skipped = await syncer.sync();
        assert(skipped.status === 'skipped', JSON.stringify(skipped));
        assert(skipped.status === 'skipped' && skipped.retryAfterSeconds === (MIN_SYNC_INTERVAL_MS - 10_000) / 1000);
        clock += MIN_SYNC_INTERVAL_MS;
        const again = await syncer.sync();
        assert(again.status === 'synced' && runs === 2, JSON.stringify(again));
    });

    it('does not start the cooldown when the sync fails', async () => {
        let fail = true;
        const syncer = createVaultSyncer(() => (fail ? Promise.reject(new Error('offline')) : Promise.resolve(2)));
        let message = '';
        try {
            await syncer.sync();
        } catch (error) {
            message = (error as Error).message;
        }
        assert(message === 'offline', `Expected the sync error, got "${message}"`);
        fail = false;
        const result = await syncer.sync();
        assert(result.status === 'synced' && result.changes === 2, JSON.stringify(result));
    });
});

// --- security fixes ---

describe('search matches titles only', () => {
    it('matches the title, case-insensitive', () => {
        assert(matchesTitle('GitHub PAT - personal', 'github pat'));
        assert(!matchesTitle('GitHub PAT', 'gitlab'));
    });

    it('treats "field=value" as plain text, so other fields cannot be searched', () => {
        assert(!matchesTitle('GitHub PAT', 'content=ghp_'), 'content= must not search the secret content');
        assert(!matchesTitle('GitHub PAT', 'id={7278'), 'id= must not search the vault ID');
        assert(matchesTitle('a=b token', 'a=b'), 'a title with "=" can still be found');
    });

    it('ignores items without a string title', () => {
        assert(!matchesTitle(undefined, 'git'));
    });
});

describe('credential with control characters', () => {
    it('detects line breaks and other control characters', () => {
        assert(hasControlCharacters('-----BEGIN KEY-----\nMIIsecret\n-----END KEY-----'));
        assert(hasControlCharacters('token\r'));
        assert(hasControlCharacters('tab\tinside'));
        assert(!hasControlCharacters('ghp_abcDEF123'));
        assert(!hasControlCharacters('dXNlcjpwYXNz'));
    });
});

describe('buildRequestHeaders', () => {
    it('drops agent auth headers whatever their case, and keeps our Authorization', () => {
        const headers = buildRequestHeaders(
            { authorization: 'Bearer agent', 'PROXY-AUTHORIZATION': 'x', Cookie: 'c', host: 'evil.com', 'X-Ok': '1' },
            'Bearer real',
            false
        );
        const names = Object.keys(headers).map((name) => name.toLowerCase());
        assert(names.filter((name) => name === 'authorization').length === 1, JSON.stringify(headers));
        assert(headers.Authorization === 'Bearer real');
        for (const blocked of ['proxy-authorization', 'cookie', 'host']) {
            assert(!names.includes(blocked), `${blocked} should be dropped`);
        }
        assert(headers['X-Ok'] === '1', 'other agent headers are kept');
    });

    it('keeps the agent content-type whatever its case', () => {
        const headers = buildRequestHeaders({ 'content-type': 'text/plain' }, 'Bearer real', true);
        const contentTypes = Object.keys(headers).filter((name) => name.toLowerCase() === 'content-type');
        assert(contentTypes.length === 1 && headers['content-type'] === 'text/plain', JSON.stringify(headers));
    });

    it('adds a JSON content-type for a body when the agent sets none', () => {
        assert(buildRequestHeaders(undefined, 'Bearer real', true)['Content-Type'] === 'application/json');
    });
});

describe('describeRequestError', () => {
    it('never includes the error message, which can contain header values', () => {
        const err = new TypeError('Headers.append: "Bearer secret\nvalue" is an invalid header value.');
        assert(describeRequestError(err) === 'request_failed');
    });

    it('keeps the network error code', () => {
        const err = new TypeError('fetch failed', { cause: { code: 'ENOTFOUND' } });
        assert(describeRequestError(err) === 'request_failed: ENOTFOUND');
    });
});

describe('SessionTokenManager short tokens', () => {
    it('rejects tokens too short to hold a full 16-byte tag', () => {
        const manager = new SessionTokenManager();
        const short = Buffer.alloc(16).toString('base64url'); // 12-byte IV + 4-byte tag
        assert(manager.decrypt(short) === null);
    });
});

describe('audit log permissions', () => {
    it('is readable by the user only', function () {
        if (process.platform === 'win32') {
            this.skip();
        }
        logMcpAuditEvent({
            schema_version: '1.0',
            category: 'McpAgentAccess',
            timestamp: new Date().toISOString(),
            tool: 'get_audit_logs',
            status: 'success',
            count: 1,
        });
        const userDataPath =
            process.platform === 'darwin'
                ? nodePath.join(os.homedir(), 'Library/Application Support')
                : nodePath.join(os.homedir(), '.local/share');
        const mode = fs.statSync(
            nodePath.join(process.env.APPDATA || userDataPath, 'dashlane-cli', 'mcp-audit.log')
        ).mode;
        assert((mode & 0o777) === 0o600, `Expected 0600, got ${(mode & 0o777).toString(8)}`);
    });
});
