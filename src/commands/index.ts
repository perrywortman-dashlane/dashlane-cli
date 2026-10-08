import { Command, Option, InvalidArgumentError } from 'commander';
import { devicesCommands } from './devices.js';
import { teamCommands } from './team/index.js';
import { configureCommands } from './configure.js';
import { accountsCommands } from './accounts.js';
import {
    runSync,
    runPassword,
    runSecureNote,
    runLock,
    runLogout,
    runRead,
    runInject,
    runExec,
    runBackup,
    runSecret,
    runStatus,
    runVaultMcp,
} from '../command-handlers/index.js';
import { DEFAULT_HTTP_PORT, DEFAULT_IDLE_TIMEOUT_MINUTES, parseIdleTimeoutMinutes } from '../modules/mcp/index.js';

const parseHttpPort = (value: string): number => {
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new InvalidArgumentError('Port must be an integer between 1 and 65535.');
    }
    return port;
};

export const rootCommands = (params: { program: Command }) => {
    const { program } = params;

    program
        .command('sync')
        .alias('s')
        .description('Manually synchronize the local vault with Dashlane')
        .action(runSync);

    program.command('status').description('Get the status of the CLI (logged in, locked, etc.)').action(runStatus);

    program
        .command('read')
        .description('Retrieve a secret from the local vault via its path (using <id> is much more efficient)')
        .argument('<path>', 'Path to the secret (dl://<title>/<field> or dl://<id>/<field>)')
        .action(runRead);

    program
        .command('exec')
        .description('Execute a command with secrets injected into the environment variables (-- <command>)')
        .action(runExec);

    program
        .command('inject')
        .description('Inject secrets into a templated string or file (uses stdin and stdout by default)')
        .option('-i, --in <input_file>', 'Input file of a template to inject the credential into')
        .option('-o, --out <output_file>', 'Output file to write the injected template to')
        .action(runInject);

    program
        .command('password')
        .alias('p')
        .description('Retrieve a password from the local vault and copy it to the clipboard')
        .addOption(
            new Option(
                '-o, --output <type>',
                'How to print the passwords. The JSON option outputs all the matching credentials'
            )
                .choices(['clipboard', 'console', 'json'])
                .default('clipboard')
        )
        .addOption(
            new Option('-f, --field <type>', 'What type of field to retrieve (login, email, password, otp)')
                .choices(['login', 'email', 'otp', 'password'])
                .default('password')
        )
        .argument(
            '[filters...]',
            'Filter credentials based on any parameter using <param>=<value>; if <param> is not specified in the filter, will default to url and title'
        )
        .action(runPassword);

    program
        .command('note')
        .alias('n')
        .description('Retrieve a secure note from the local vault and open it')
        .addOption(
            new Option('-o, --output <type>', 'How to print the notes. The JSON option outputs all the matching notes')
                .choices(['text', 'json'])
                .default('text')
        )
        .argument(
            '[filters...]',
            'Filter notes based on any parameter using <param>=<value>; if <param> is not specified in the filter, will default to title only'
        )
        .action(runSecureNote);

    program
        .command('secret')
        .description('Retrieve a secret from the local vault and open it')
        .addOption(
            new Option(
                '-o, --output <type>',
                'How to print the secrets. The JSON option outputs all the matching secrets'
            )
                .choices(['text', 'json'])
                .default('text')
        )
        .argument(
            '[filters...]',
            'Filter secrets based on any parameter using <param>=<value>; if <param> is not specified in the filter, will default to title only'
        )
        .action(runSecret);

    accountsCommands({ program });

    devicesCommands({ program });

    teamCommands({ program });

    configureCommands({ program });

    program
        .command('mcp')
        .description('Start the vault MCP server for AI agent credential brokering')
        .option('--no-sync', 'Skip vault sync at startup')
        .option('--http', 'Expose the server over localhost HTTP instead of stdio (for dev containers)')
        .option('--port <number>', 'HTTP port to listen on (use with --http)', parseHttpPort, DEFAULT_HTTP_PORT)
        .option(
            '--idle-timeout <minutes>',
            'Stop the HTTP server after this many minutes without authenticated requests, 0 = never (use with --http)',
            parseIdleTimeoutMinutes,
            DEFAULT_IDLE_TIMEOUT_MINUTES
        )
        .action(runVaultMcp);

    program
        .command('backup')
        .option('--directory <directory>', 'Output directory of the backup ("." by default)')
        .option('--filename <filename>', 'Filename of the backup ("dashlane-backup-<unix_timestamp>.db by default")')
        .description('Backup your local vault (will use the current directory by default)')
        .action(runBackup);

    program
        .command('lock')
        .description('Lock the vault, next commands will request the master password to unlock it)')
        .action(runLock);

    program
        .command('logout')
        .option('--ignore-revocation', "Device credentials won't be revoked on Dashlane's servers")
        .description('Logout and clean your local database and OS keychain')
        .action(runLogout);
};
