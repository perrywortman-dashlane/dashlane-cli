/**
 * Auto-detect auth type from the credential value.
 * If the value is valid base64 encoding of "username:password", use Basic auth.
 * Otherwise, use Bearer.
 *
 * Note: Raw "user:password" values are NOT auto-detected because some Bearer
 * tokens contain colons (e.g., AWS keys, custom API keys). Users who need
 * Basic auth should store their credentials as base64-encoded "user:password".
 */
export function detectAuthType(value: string): { scheme: 'Basic' | 'Bearer'; headerValue: string } {
    try {
        const decoded = Buffer.from(value, 'base64').toString('utf-8');
        if (Buffer.from(decoded).toString('base64') === value) {
            const parts = decoded.split(':');
            if (parts.length === 2 && parts[0].length > 0 && parts[1].length > 0) {
                return { scheme: 'Basic', headerValue: `Basic ${value}` };
            }
        }
    } catch {
        // not base64
    }
    return { scheme: 'Bearer', headerValue: `Bearer ${value}` };
}

/**
 * Build the Authorization header for an auth scheme chosen by the user.
 * The stored value is used as is (no re-encoding).
 */
export function buildAuthHeader(scheme: string, value: string): { scheme: string; headerValue: string } {
    return { scheme, headerValue: `${scheme} ${value}` };
}
