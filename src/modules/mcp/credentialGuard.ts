/**
 * Redaction guard for call_api responses.
 * If a server echoes the credential back (e.g. an echo service that returns request headers),
 * the value is masked before the response reaches the agent.
 */

export const REDACTED = '[REDACTED]';

/**
 * Mask every occurrence of the credential in a response.
 * Covers the raw value and, for Basic auth, the decoded "user:password" form,
 * because an echo service may return either one.
 */
export function redactCredential(text: string, credential: string): string {
    if (!credential) return text;

    const secrets = new Set<string>([credential]);
    try {
        const decoded = Buffer.from(credential, 'base64').toString('utf-8');
        if (Buffer.from(decoded).toString('base64') === credential && decoded.includes(':')) {
            secrets.add(decoded);
        }
    } catch {
        // not base64, only the raw value is masked
    }

    // Longest first, so a secret that contains another one is masked in full
    return [...secrets].sort((a, b) => b.length - a.length).reduce((out, s) => out.split(s).join(REDACTED), text);
}

/** Redact the credential in every string of a parsed response (objects, arrays, plain text). */
export function redactDeep(value: unknown, credential: string): unknown {
    if (typeof value === 'string') return redactCredential(value, credential);
    if (Array.isArray(value)) return value.map((v) => redactDeep(v, credential));
    if (typeof value === 'object' && value !== null) {
        return Object.fromEntries(
            Object.entries(value).map(([k, v]) => [redactCredential(k, credential), redactDeep(v, credential)])
        );
    }
    return value;
}
