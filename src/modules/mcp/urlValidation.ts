import { resolve as dnsResolve } from 'dns/promises';

/**
 * Check if an IP address (v4 or v6) is private/reserved.
 */
export function isPrivateIp(ip: string): boolean {
    // IPv4 private ranges
    const v4Match = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (v4Match) {
        const [, a, b] = v4Match.map(Number);
        return (
            a === 10 || // 10.0.0.0/8
            (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
            (a === 192 && b === 168) || // 192.168.0.0/16
            (a === 169 && b === 254) || // 169.254.0.0/16 (link-local / cloud metadata)
            a === 127 || // 127.0.0.0/8 (loopback)
            a === 0 // 0.0.0.0
        );
    }

    // IPv6 private/reserved ranges
    const lower = ip.toLowerCase();
    return (
        lower === '::1' || // loopback
        lower.startsWith('fe80') || // link-local
        lower.startsWith('fc') || // unique local (fc00::/7)
        lower.startsWith('fd') || // unique local (fc00::/7)
        lower.startsWith('::ffff:127.') || // IPv4-mapped loopback
        lower.startsWith('::ffff:10.') || // IPv4-mapped private
        lower.startsWith('::ffff:192.168.') || // IPv4-mapped private
        lower.startsWith('::ffff:169.254.') // IPv4-mapped link-local
    );
}

/**
 * Validates that a URL is safe for external API calls.
 * Blocks private/reserved IPs, localhost, non-HTTPS, and resolves DNS to prevent rebinding.
 */
export async function validateUrl(url: string): Promise<{ safe: boolean; reason?: string }> {
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        return { safe: false, reason: 'Invalid URL' };
    }

    if (parsed.protocol !== 'https:') {
        return { safe: false, reason: 'Only HTTPS URLs are allowed' };
    }

    const hostname = parsed.hostname.toLowerCase();

    if (hostname === 'localhost' || hostname === '0.0.0.0') {
        return { safe: false, reason: 'Localhost URLs are not allowed' };
    }

    // If hostname is already an IP, check it directly
    if (isPrivateIp(hostname) || isPrivateIp(hostname.replace(/^\[|\]$/g, ''))) {
        return { safe: false, reason: 'Private/reserved IP addresses are not allowed' };
    }

    // Resolve DNS to prevent rebinding attacks
    try {
        const addresses = await dnsResolve(hostname);
        for (const addr of addresses) {
            if (isPrivateIp(addr)) {
                return { safe: false, reason: 'URL resolves to a private/reserved IP address' };
            }
        }
    } catch {
        return { safe: false, reason: 'Could not resolve hostname' };
    }

    return { safe: true };
}
