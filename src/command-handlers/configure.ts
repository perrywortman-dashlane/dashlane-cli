import { encryptAesCbcHmac256 } from '../modules/crypto/encrypt.js';
import { deleteLocalKey, setLocalKey, warnUnreachableKeychainDisabled } from '../modules/crypto/keychainManager.js';
import { connectAndPrepare } from '../modules/database/index.js';
import { parseBooleanString } from '../utils/index.js';
import { DeviceConfiguration } from '../types.js';
import { logger } from '../logger.js';
import { askConfirmMcpAllow } from '../utils/dialogs.js';
import { getAllNotes, getAllSecrets, stripBraces } from '../modules/mcp/vaultSearch.js';
import {
    type AuthScheme,
    type PolicyItem,
    listCredentialPolicies,
    normalizeDomain,
    removeCredentialPolicy,
    saveCredentialPolicy,
} from '../modules/mcp/credentialPolicy.js';

export const configureSaveMasterPassword = async (boolean: string) => {
    let shouldNotSaveMasterPassword = !parseBooleanString(boolean);
    const { db, localConfiguration } = await connectAndPrepare({
        autoSync: false,
        shouldNotSaveMasterPasswordIfNoDeviceKeys: shouldNotSaveMasterPassword,
    });

    if (shouldNotSaveMasterPassword) {
        // Forget the local key stored in the OS keychain because the master password and the DB are enough to retrieve the
        // local key
        try {
            deleteLocalKey(localConfiguration.login);
        } catch (error) {
            // Errors are ignored because the OS keychain may be unreachable
            let errorMessage = 'unknown error';
            if (error instanceof Error) {
                errorMessage = error.message;
            }
            logger.warn(`Unable to delete the local key from the keychain: ${errorMessage}`);
        }
    }

    let masterPasswordEncrypted: string | null;
    if (shouldNotSaveMasterPassword) {
        masterPasswordEncrypted = null;
    } else {
        // Set encrypted master password in the DB
        masterPasswordEncrypted = encryptAesCbcHmac256(
            localConfiguration.localKey,
            Buffer.from(localConfiguration.masterPassword)
        );

        if (!shouldNotSaveMasterPassword) {
            // Set local key in the OS keychain
            setLocalKey(localConfiguration.login, localConfiguration.localKey, (errorMessage: string) => {
                warnUnreachableKeychainDisabled(errorMessage);
                shouldNotSaveMasterPassword = true;
            });
        }
    }

    db.prepare('UPDATE device SET masterPasswordEncrypted = ?, shouldNotSaveMasterPassword = ? WHERE login = ?')
        .bind(masterPasswordEncrypted, shouldNotSaveMasterPassword ? 1 : 0, localConfiguration.login)
        .run();

    db.close();
};

export const configureDisableAutoSync = async (boolean: string) => {
    const disableAutoSync = parseBooleanString(boolean);
    const { db, localConfiguration } = await connectAndPrepare({ autoSync: false });

    db.prepare('UPDATE device SET autoSync = ? WHERE login = ?')
        .bind(disableAutoSync ? 0 : 1, localConfiguration.login)
        .run();

    db.close();
};

export const configureUserPresenceVerification = async (options: {
    method: DeviceConfiguration['userPresenceVerification'];
}) => {
    const { method } = options;
    const { db, localConfiguration } = await connectAndPrepare({ autoSync: false });

    if (method === 'biometrics') {
        if (process.platform === 'darwin') {
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            const nodemacauth = require('node-mac-auth') as typeof import('node-mac-auth');
            if (!nodemacauth.canPromptTouchID()) {
                throw new Error('Biometrics are not supported on your device.');
            }
        }
    }

    db.prepare('UPDATE device SET userPresenceVerification = ? WHERE login = ?')
        .bind(method, localConfiguration.login)
        .run();

    db.close();
};

/** Find the one vault item (secret or note) with this exact title, or the one with this id. */
const findPolicyItem = async (
    db: Parameters<typeof getAllSecrets>[0],
    localConfiguration: Parameters<typeof getAllSecrets>[1],
    title: string,
    id?: string
): Promise<PolicyItem> => {
    const [secrets, notes] = await Promise.all([
        getAllSecrets(db, localConfiguration),
        getAllNotes(db, localConfiguration),
    ]);
    const items = [...secrets, ...notes].filter((item) => (id ? stripBraces(item.id) === stripBraces(id) : true));
    const matches = items.filter((item) => item.title === title);
    if (matches.length === 0) {
        throw new Error(
            `No secret or secure note titled "${title}"${id ? ` with id ${id}` : ''}. Run "dcli sync" and check the title.`
        );
    }
    if (matches.length > 1) {
        throw new Error(
            `${matches.length} items are titled "${title}". Pass --id with one of: ${matches.map((m) => stripBraces(m.id)).join(', ')}`
        );
    }
    return { id: matches[0].id, title: matches[0].title };
};

export const configureMcpAllow = async (options: {
    title: string;
    website: string;
    id?: string;
    authScheme?: AuthScheme;
}) => {
    const { title, website, id, authScheme } = options;
    if (!process.stdin.isTTY) {
        throw new Error('Run "dcli configure mcp-allow" yourself in a terminal. Scripts and AI agents cannot run it.');
    }
    const normalized = normalizeDomain(website);
    const { db, localConfiguration } = await connectAndPrepare({ autoSync: false });

    try {
        const item = await findPolicyItem(db, localConfiguration, title, id);
        if (!(await askConfirmMcpAllow({ title, website: normalized }))) {
            return;
        }
        const policy = saveCredentialPolicy(db, localConfiguration.login, item, normalized, authScheme);
        logger.success(
            `"${title}" can now be sent to: ${policy.allowedDomains.join(', ')}${policy.authScheme ? ` (auth: ${policy.authScheme})` : ''}`
        );
    } finally {
        db.close();
    }
};

/** Draw a boxed table. Each cell is a list of lines, so a cell can span several lines. */
const renderTable = (headers: string[], rows: string[][][]): string => {
    const widths = headers.map((header, col) =>
        Math.max(header.length, ...rows.flatMap((row) => row[col].map((line) => line.length)))
    );
    const line = (left: string, middle: string, right: string) =>
        `${left}${widths.map((width) => '─'.repeat(width + 2)).join(middle)}${right}`;
    const textLine = (cells: string[]) => `│${cells.map((cell, col) => ` ${cell.padEnd(widths[col])} `).join('│')}│`;

    const output = [line('┌', '┬', '┐'), textLine(headers), line('├', '┼', '┤')];
    rows.forEach((row, rowIndex) => {
        const height = Math.max(...row.map((cell) => cell.length));
        for (let i = 0; i < height; i++) {
            output.push(textLine(row.map((cell) => cell[i] ?? '')));
        }
        output.push(rowIndex < rows.length - 1 ? line('├', '┼', '┤') : line('└', '┴', '┘'));
    });
    return output.join('\n');
};

export const configureMcpList = async () => {
    const { db, localConfiguration } = await connectAndPrepare({ autoSync: false });

    try {
        const policies = listCredentialPolicies(db, localConfiguration.login);
        if (policies.length === 0) {
            logger.content('No MCP rules. Add one with: dcli configure mcp-allow --title <title> --website <website>');
            return;
        }
        logger.content(
            renderTable(
                ['Index', 'Title', 'Id', 'Websites', 'Auth scheme'],
                policies.map(({ id, title, allowedDomains, authScheme }, index) => [
                    [String(index)],
                    [title],
                    [stripBraces(id)],
                    allowedDomains,
                    [authScheme ?? 'auto-detect'],
                ])
            )
        );
    } finally {
        db.close();
    }
};

export const configureMcpRevoke = async (options: { title?: string; index?: string; website?: string }) => {
    const { index, website } = options;
    if ((options.title === undefined) === (index === undefined)) {
        throw new Error('Provide either --title or --index.');
    }
    if (index !== undefined && !/^\d+$/.test(index)) {
        throw new Error('--index must be a number shown by "dcli configure mcp-list".');
    }
    const { db, localConfiguration } = await connectAndPrepare({ autoSync: false });

    try {
        const policies = listCredentialPolicies(db, localConfiguration.login);
        let rule = policies[Number(index)];
        if (index === undefined) {
            const matches = policies.filter((policy) => policy.title === options.title);
            if (matches.length > 1) {
                logger.warn(`Several rules are titled "${options.title}". Use --index from "dcli configure mcp-list".`);
                return;
            }
            rule = matches[0];
        }
        if (!rule) {
            logger.warn(
                index !== undefined
                    ? `No rule at index ${index}. Run "dcli configure mcp-list" to see the indexes.`
                    : `No matching rule found for "${options.title}".`
            );
            return;
        }
        const { id, title } = rule;
        if (removeCredentialPolicy(db, localConfiguration.login, id, website)) {
            logger.success(
                website ? `"${title}" can no longer be sent to ${website}.` : `Rule for "${title}" removed.`
            );
        } else {
            logger.warn(`No matching rule found for "${title}"${website ? ` and ${website}` : ''}.`);
        }
    } finally {
        db.close();
    }
};
