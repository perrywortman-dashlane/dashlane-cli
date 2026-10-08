import Database from 'better-sqlite3';
import { decryptTransactions } from '../crypto/index.js';
import {
    BackupEditTransaction,
    LocalConfiguration,
    SecretTransactionContent,
    SecureNoteTransactionContent,
    VaultNote,
    VaultSecret,
} from '../../types.js';
import { SessionTokenManager } from './sessionTokens.js';

/** Only these fields are safe to return to the agent. */
const ALLOWED_FIELDS = new Set([
    'id',
    'title',
    'creationDate',
    'creationDateTime',
    'lastBackupTime',
    'updateDate',
    'type',
    'itemType',
    'localeFormat',
]);

export const pickAllowedFields = (records: Record<string, unknown>[]): Record<string, unknown>[] =>
    records.map((record) => Object.fromEntries(Object.entries(record).filter(([key]) => ALLOWED_FIELDS.has(key))));

/** Strip surrounding curly braces from vault IDs (e.g. {UUID} → UUID). */
export const stripBraces = (id: string): string => id.replace(/^\{/, '').replace(/\}$/, '');

/** Ensure ID has curly braces for DB lookups (e.g. UUID → {UUID}). */
export const ensureBraces = (id: string): string => {
    const clean = stripBraces(id);
    return `{${clean}}`;
};

/**
 * Query and decrypt all secrets from the vault.
 */
export const getAllSecrets = async (
    db: Database.Database,
    localConfiguration: LocalConfiguration
): Promise<VaultSecret[]> => {
    const transactions = db
        .prepare(`SELECT * FROM transactions WHERE login = ? AND type = 'SECRET' AND action = 'BACKUP_EDIT'`)
        .bind(localConfiguration.login)
        .all() as BackupEditTransaction[];

    const decrypted = await decryptTransactions<SecretTransactionContent>(transactions, localConfiguration);

    return decrypted.map(
        (item) =>
            Object.fromEntries(
                item.root.KWSecret.KWDataItem.map((entry) => [
                    entry._attributes.key[0].toLowerCase() + entry._attributes.key.slice(1),
                    entry._cdata,
                ])
            ) as unknown as VaultSecret
    );
};

/**
 * Query and decrypt all secure notes from the vault.
 */
export const getAllNotes = async (
    db: Database.Database,
    localConfiguration: LocalConfiguration
): Promise<VaultNote[]> => {
    const transactions = db
        .prepare(`SELECT * FROM transactions WHERE login = ? AND type = 'SECURENOTE' AND action = 'BACKUP_EDIT'`)
        .bind(localConfiguration.login)
        .all() as BackupEditTransaction[];

    const decrypted = await decryptTransactions<SecureNoteTransactionContent>(transactions, localConfiguration);

    return decrypted.map(
        (item) =>
            Object.fromEntries(
                item.root.KWSecureNote.KWDataItem.map((entry) => [
                    entry._attributes.key[0].toLowerCase() + entry._attributes.key.slice(1),
                    entry._cdata,
                ])
            ) as unknown as VaultNote
    );
};

/**
 * Search the vault for secrets and secure notes matching a query.
 * Returns metadata only — only allowlisted fields are included.
 * Real IDs are replaced with session-scoped opaque tokens.
 */
export const findVaultItems = async (
    db: Database.Database,
    localConfiguration: LocalConfiguration,
    query: string,
    tokenManager: SessionTokenManager,
    maxResults: number
): Promise<Record<string, unknown>[]> => {
    const [allSecrets, allNotes] = await Promise.all([
        getAllSecrets(db, localConfiguration),
        getAllNotes(db, localConfiguration),
    ]);

    const matchedSecrets = allSecrets.filter((secret) => matchesTitle(secret.title, query));
    const matchedNotes = allNotes.filter((note) => matchesTitle(note.title, query));

    const combined = [
        ...matchedSecrets.map((s) => ({ ...s, itemType: 'secret' })),
        ...matchedNotes.map((n) => ({ ...n, itemType: 'note' })),
    ];

    const allowed = pickAllowedFields(combined as unknown as Record<string, unknown>[]);

    // Replace real IDs with session-scoped opaque tokens and cap results
    return allowed.slice(0, maxResults).map((record) => {
        if (typeof record.id === 'string') {
            record.id = tokenManager.encrypt(record.id);
        }
        return record;
    });
};

/**
 * Case-insensitive substring match on the item title only.
 * Do not use filterMatches here: it reads "field=value" queries, which would let an agent
 * test guesses against the secret content (e.g. "content=ghp_a") one character at a time.
 */
export const matchesTitle = (title: unknown, query: string): boolean =>
    typeof title === 'string' && title.toLowerCase().includes(query.toLowerCase());

/**
 * Read a specific field from a vault item (secret or note) by ID.
 * The returned value must NEVER appear in any MCP response, error message, or log.
 */
export const readVaultItemField = async (
    db: Database.Database,
    localConfiguration: LocalConfiguration,
    itemId: string,
    field: string
): Promise<string> => {
    const bracedId = ensureBraces(itemId);

    const transaction = db
        .prepare(`SELECT * FROM transactions WHERE login = ? AND identifier = ? AND action = 'BACKUP_EDIT'`)
        .bind(localConfiguration.login, bracedId)
        .get() as BackupEditTransaction | undefined;

    if (!transaction) {
        throw new Error('Vault item not found');
    }

    let beautified: Record<string, string | undefined>;

    if (transaction.type === 'SECURENOTE') {
        const [decrypted] = await decryptTransactions<SecureNoteTransactionContent>([transaction], localConfiguration);
        beautified = Object.fromEntries(
            decrypted.root.KWSecureNote.KWDataItem.map((entry) => [
                entry._attributes.key[0].toLowerCase() + entry._attributes.key.slice(1),
                entry._cdata,
            ])
        );
    } else {
        const [decrypted] = await decryptTransactions<SecretTransactionContent>([transaction], localConfiguration);
        beautified = Object.fromEntries(
            decrypted.root.KWSecret.KWDataItem.map((entry) => [
                entry._attributes.key[0].toLowerCase() + entry._attributes.key.slice(1),
                entry._cdata,
            ])
        );
    }

    const value = beautified[field];
    if (!value) {
        throw new Error('Field not found');
    }
    return value;
};
