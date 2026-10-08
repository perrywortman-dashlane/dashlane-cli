import { randomBytes, timingSafeEqual } from 'node:crypto';

/** Generate a 256-bit bearer token for the HTTP transport (URL-safe, no padding). */
export const generateHttpToken = (): string => randomBytes(32).toString('base64url');

/**
 * Constant-time comparison of a provided bearer token against the expected token.
 * `crypto.timingSafeEqual` throws on length mismatch, so we length-check first while
 * still doing a comparison to keep timing roughly flat.
 */
export const timingSafeBearerCompare = (provided: string, expected: string): boolean => {
    const providedBuf = Buffer.from(provided);
    const expectedBuf = Buffer.from(expected);
    if (providedBuf.length !== expectedBuf.length) {
        timingSafeEqual(expectedBuf, expectedBuf);
        return false;
    }
    return timingSafeEqual(providedBuf, expectedBuf);
};

export type BearerAuthResult = 'ok' | 'missing_token' | 'invalid_token';

/**
 * Validate an `Authorization` header value against the expected bearer token.
 * Returns a discriminated result so callers can audit-log the failure reason.
 */
export const checkBearerAuth = (authHeader: string | undefined, expectedToken: string): BearerAuthResult => {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return 'missing_token';
    }
    return timingSafeBearerCompare(authHeader.slice('Bearer '.length), expectedToken) ? 'ok' : 'invalid_token';
};
