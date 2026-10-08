/**
 * Search rate limiting for the vault MCP server.
 *
 * State lives in a single object created once per server process and shared across
 * all transports (stdio, or every HTTP session). This keeps the session-wide and
 * per-minute caps meaningful no matter how many MCP clients/requests connect.
 */

export const MAX_SEARCHES_PER_SESSION = 100;
export const MAX_SEARCHES_PER_MINUTE = 10;

const WINDOW_MS = 60_000;

export type RateLimitReason = 'session' | 'minute';

export interface SearchRateLimiter {
    /** Record a search attempt; returns the limit reason if exceeded, otherwise null. */
    check(): RateLimitReason | null;
}

export const createSearchRateLimiter = (): SearchRateLimiter => {
    let searchCount = 0;
    const searchTimestamps: number[] = [];

    return {
        check(): RateLimitReason | null {
            // Session-wide rate limit
            searchCount++;
            if (searchCount > MAX_SEARCHES_PER_SESSION) {
                return 'session';
            }

            // Sliding window rate limit (per minute)
            const now = Date.now();
            searchTimestamps.push(now);
            while (searchTimestamps.length > 0 && searchTimestamps[0] < now - WINDOW_MS) {
                searchTimestamps.shift();
            }
            if (searchTimestamps.length > MAX_SEARCHES_PER_MINUTE) {
                return 'minute';
            }

            return null;
        },
    };
};
