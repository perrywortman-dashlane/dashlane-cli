/** Minimum time between two agent-triggered syncs, so an agent cannot flood the sync endpoint. */
export const MIN_SYNC_INTERVAL_MS = 30_000;

export type VaultSyncResult =
    | { status: 'synced'; changes: number; syncedAt: string }
    | { status: 'skipped'; lastSyncedAt: string; retryAfterSeconds: number };

export interface VaultSyncer {
    sync(): Promise<VaultSyncResult>;
}

/**
 * Wrap the vault sync for the MCP `sync_vault` tool.
 * - Calls made while a sync is running share that sync instead of starting a second one.
 * - After a sync, new calls within MIN_SYNC_INTERVAL_MS are skipped and say when to retry.
 * - A failed sync does not start the cooldown, so the agent can retry after the user fixes the cause.
 *
 * @param runSync performs the sync and returns the number of changes received from the server
 */
export const createVaultSyncer = (runSync: () => Promise<number>, now: () => number = Date.now): VaultSyncer => {
    let inFlight: Promise<VaultSyncResult> | null = null;
    let lastSyncedAt: number | null = null;

    return {
        sync() {
            if (inFlight) {
                return inFlight;
            }

            if (lastSyncedAt !== null) {
                const elapsed = now() - lastSyncedAt;
                if (elapsed < MIN_SYNC_INTERVAL_MS) {
                    return Promise.resolve({
                        status: 'skipped',
                        lastSyncedAt: new Date(lastSyncedAt).toISOString(),
                        retryAfterSeconds: Math.ceil((MIN_SYNC_INTERVAL_MS - elapsed) / 1000),
                    });
                }
            }

            inFlight = runSync()
                .then((changes): VaultSyncResult => {
                    lastSyncedAt = now();
                    return { status: 'synced', changes, syncedAt: new Date(lastSyncedAt).toISOString() };
                })
                .finally(() => {
                    inFlight = null;
                });
            return inFlight;
        },
    };
};
