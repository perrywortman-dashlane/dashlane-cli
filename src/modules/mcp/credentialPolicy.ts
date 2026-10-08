import { domainToASCII } from 'node:url';
import Database from 'better-sqlite3';

/** Any word the user chooses (e.g. Bearer, Basic, Token). Auto-detect is used when unset. */
export type AuthScheme = string;

export interface CredentialPolicy {
    allowedDomains: string[];
    authScheme?: AuthScheme;
}

/** A rule belongs to the item id. The title is only used for messages and `mcp-list`. */
export interface PolicyItem {
    id: string;
    title: string;
}

/** Same item with or without curly braces gives the same key. */
const policyKey = (id: string): string => id.replace(/^\{/, '').replace(/\}$/, '');

export type PolicyCheckResult =
    | { status: 'allowed'; policy: CredentialPolicy }
    | { status: 'blocked'; message: string };

const AUTH_SCHEME_PATTERN = /^[A-Za-z0-9._~+-]{1,64}$/;

interface PolicyRow {
    allowedDomains: string;
    authScheme: string | null;
}

/** One simple word: no spaces or line breaks, so it cannot alter the header. */
export const isAuthScheme = (value: unknown): boolean => typeof value === 'string' && AUTH_SCHEME_PATTERN.test(value);

/**
 * Read the rule for a secret. The only function that reads rules.
 * Fails closed: no rule, empty list or unreadable data returns null.
 */
export const getCredentialPolicy = (
    db: Database.Database,
    login: string,
    item: PolicyItem
): CredentialPolicy | null => {
    let row: PolicyRow | undefined;
    try {
        row = db
            .prepare('SELECT allowedDomains, authScheme FROM mcpPolicy WHERE login = ? AND itemId = ?')
            .get(login, policyKey(item.id)) as PolicyRow | undefined;
    } catch {
        return null;
    }
    if (!row) {
        return null;
    }

    let parsed: unknown;
    try {
        parsed = JSON.parse(row.allowedDomains);
    } catch {
        return null;
    }
    if (!Array.isArray(parsed)) {
        return null;
    }
    const allowedDomains = parsed.flatMap((d) => {
        try {
            return typeof d === 'string' ? [normalizeDomain(d)] : [];
        } catch {
            return [];
        }
    });
    if (allowedDomains.length === 0) {
        return null;
    }

    return {
        allowedDomains,
        ...(row.authScheme && isAuthScheme(row.authScheme) ? { authScheme: row.authScheme } : {}),
    };
};

/** Exact match only. Case-insensitive, port ignored, one trailing dot ignored. */
export const isDomainAllowed = (hostname: string, allowedDomains: string[]): boolean => {
    const host = hostname.toLowerCase().replace(/\.$/, '');
    return allowedDomains.some((entry) => host === entry.toLowerCase());
};

/** Wrap in single quotes so the shell runs nothing inside. */
const shellQuote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`;

export const buildPolicyBlockMessage = (
    item: PolicyItem,
    hostname: string,
    policy: CredentialPolicy | null
): string => {
    const lines = [
        `"${item.title}" has no rule, so it cannot be sent to ${hostname}.`,
        'Ask the user to run this command in their own terminal. Do not run it yourself:',
        `dcli configure mcp-allow --title ${shellQuote(item.title)} --website ${shellQuote(hostname)}`,
    ];
    if (policy) {
        lines[0] = `"${item.title}" is not allowed to be sent to ${hostname}.`;
        lines.push(`Allowed: ${policy.allowedDomains.join(', ')}.`);
    }
    return lines.join('\n');
};

export const checkCredentialPolicy = (
    db: Database.Database,
    login: string,
    item: PolicyItem,
    url: string
): PolicyCheckResult => {
    let hostname: string;
    try {
        hostname = new URL(url).hostname;
    } catch {
        return { status: 'blocked', message: 'Invalid URL.' };
    }

    const policy = getCredentialPolicy(db, login, item);
    if (!policy || !isDomainAllowed(hostname, policy.allowedDomains)) {
        return { status: 'blocked', message: buildPolicyBlockMessage(item, hostname, policy) };
    }
    return { status: 'allowed', policy };
};

/** Lowercase, trim and convert to ASCII; exact hostnames only. Throws on bad input. */
export const normalizeDomain = (input: string): string => {
    const trimmed = input.trim().toLowerCase();
    if (trimmed.includes('*')) {
        throw new Error(`Invalid domain "${input}". Wildcards are not supported; list each host.`);
    }
    // domainToASCII silently drops a path, port or userinfo, so refuse them first.
    const domain = /[\s/\\:?#@%[\]]/.test(trimmed) ? '' : domainToASCII(trimmed);
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(domain)) {
        throw new Error(`Invalid domain "${input}". Use a hostname only, without scheme, path or port.`);
    }
    return domain;
};

/** Add a domain to the rule for a secret (no duplicates). Updates authScheme only if one is given. */
export const saveCredentialPolicy = (
    db: Database.Database,
    login: string,
    item: PolicyItem,
    domain: string,
    authScheme?: AuthScheme
): CredentialPolicy => {
    const normalized = normalizeDomain(domain);
    if (authScheme !== undefined && !isAuthScheme(authScheme)) {
        throw new Error(
            `Invalid auth scheme "${authScheme}". Use one word with letters, digits or . _ ~ + - (for example Bearer, Basic or Token).`
        );
    }

    const existing = getCredentialPolicy(db, login, item);
    const allowedDomains = existing?.allowedDomains ?? [];
    if (!allowedDomains.includes(normalized)) {
        allowedDomains.push(normalized);
    }
    const scheme = authScheme ?? existing?.authScheme;

    db.prepare(
        `INSERT INTO mcpPolicy (login, itemId, title, allowedDomains, authScheme) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(login, itemId) DO UPDATE SET
            title = excluded.title, allowedDomains = excluded.allowedDomains, authScheme = excluded.authScheme`
    ).run(login, policyKey(item.id), item.title, JSON.stringify(allowedDomains), scheme ?? null);

    return { allowedDomains, ...(scheme ? { authScheme: scheme } : {}) };
};

/** List all valid rules for a login, sorted by title. Unreadable rules are skipped. */
export const listCredentialPolicies = (db: Database.Database, login: string): Array<PolicyItem & CredentialPolicy> => {
    const rows = db
        .prepare('SELECT itemId AS id, title FROM mcpPolicy WHERE login = ? ORDER BY title, itemId')
        .all(login) as PolicyItem[];
    return rows.flatMap(({ id, title }) => {
        const policy = getCredentialPolicy(db, login, { id, title });
        return policy ? [{ id, title, ...policy }] : [];
    });
};

/**
 * Remove one domain from a rule, or the whole rule when no domain is given.
 * A rule left with no domain is deleted. Returns false when nothing was removed.
 */
export const removeCredentialPolicy = (
    db: Database.Database,
    login: string,
    itemId: string,
    domain?: string
): boolean => {
    const key = policyKey(itemId);
    const deleteRule = () =>
        db.prepare('DELETE FROM mcpPolicy WHERE login = ? AND itemId = ?').run(login, key).changes > 0;

    if (domain === undefined) {
        return deleteRule();
    }

    const existing = getCredentialPolicy(db, login, { id: key, title: '' });
    let target: string;
    try {
        target = normalizeDomain(domain);
    } catch {
        return false;
    }
    if (!existing || !existing.allowedDomains.includes(target)) {
        return false;
    }
    const remaining = existing.allowedDomains.filter((d) => d !== target);
    if (remaining.length === 0) {
        return deleteRule();
    }
    db.prepare('UPDATE mcpPolicy SET allowedDomains = ? WHERE login = ? AND itemId = ?').run(
        JSON.stringify(remaining),
        login,
        key
    );
    return true;
};
