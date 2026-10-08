import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

/**
 * Session-scoped token manager. Encrypts real vault IDs into opaque tokens
 * that are only valid for the lifetime of this MCP server process.
 * Prevents agents from harvesting real vault IDs for use in other sessions.
 */
export class SessionTokenManager {
    private key: Buffer;
    private readonly algorithm = 'aes-256-gcm' as const;

    constructor() {
        this.key = randomBytes(32);
    }

    /** Encrypt a real vault ID into a session-scoped opaque token. */
    encrypt(realId: string): string {
        const iv = randomBytes(12);
        const cipher = createCipheriv(this.algorithm, this.key, iv);
        const encrypted = Buffer.concat([cipher.update(realId, 'utf-8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, tag, encrypted]).toString('base64url');
    }

    /** Invalidate every token issued so far by replacing the encryption key. */
    clear(): void {
        this.key.fill(0);
        this.key = randomBytes(32);
    }

    /** Decrypt a session token back to the real vault ID. Returns null if invalid. */
    decrypt(token: string): string | null {
        try {
            const data = Buffer.from(token, 'base64url');
            // 12-byte IV + 16-byte tag + at least 1 byte. Without this check, a short token gives a short
            // tag, and GCM accepts tags down to 4 bytes, which makes forging a token much easier.
            if (data.length < 29) {
                return null;
            }
            const iv = data.subarray(0, 12);
            const tag = data.subarray(12, 28);
            const encrypted = data.subarray(28);
            const decipher = createDecipheriv(this.algorithm, this.key, iv, { authTagLength: 16 });
            decipher.setAuthTag(tag);
            return decipher.update(encrypted, undefined, 'utf-8') + decipher.final('utf-8');
        } catch {
            return null;
        }
    }
}
