import Database from 'better-sqlite3';
import { DeviceConfiguration } from '../../types.js';

interface PrepareDB {
    db: Database.Database;
}

export const prepareDB = (params: PrepareDB): DeviceConfiguration | null => {
    const { db } = params;

    db.prepare(
        `CREATE TABLE IF NOT EXISTS syncUpdates (
            login VARCHAR(255) PRIMARY KEY,
            lastServerSyncTimestamp INT,
            lastClientSyncTimestamp INT
        );`
    ).run();
    db.prepare(
        `CREATE TABLE IF NOT EXISTS transactions (
            login VARCHAR(255),
            identifier VARCHAR(255),
            type VARCHAR(255) NOT NULL,
            action VARCHAR(255) NOT NULL,
            content BLOB,
            PRIMARY KEY (login, identifier)
        );`
    ).run();
    db.prepare(
        `CREATE TABLE IF NOT EXISTS device (
            login VARCHAR(255) PRIMARY KEY,
            version VARCHAR(255) NOT NULL,
            accessKey VARCHAR(255) NOT NULL,
            secretKeyEncrypted VARCHAR(255) NOT NULL,
            masterPasswordEncrypted VARCHAR(255),
            shouldNotSaveMasterPassword BIT NOT NULL,
            localKeyEncrypted VARCHAR(255) NOT NULL,
            autoSync BIT NOT NULL,
            userPresenceVerification VARCHAR(255) NOT NULL,
            authenticationMode VARCHAR(255),
            serverKeyEncrypted VARCHAR(255)
        );`
    ).run();
    // Rules used to be keyed by title. They are now keyed by item id, so old rules are dropped (blocked by default).
    const mcpPolicyColumns = db.prepare('PRAGMA table_info(mcpPolicy)').all() as { name: string }[];
    if (mcpPolicyColumns.length > 0 && !mcpPolicyColumns.some((column) => column.name === 'itemId')) {
        db.prepare('DROP TABLE mcpPolicy').run();
    }
    db.prepare(
        `CREATE TABLE IF NOT EXISTS mcpPolicy (
            login VARCHAR(255),
            itemId VARCHAR(255),
            title VARCHAR(255) NOT NULL,
            allowedDomains TEXT NOT NULL,
            authScheme VARCHAR(255),
            PRIMARY KEY (login, itemId)
        );`
    ).run();

    return db.prepare('SELECT * FROM device LIMIT 1').get() as DeviceConfiguration | null;
};
