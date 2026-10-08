import { Command, Option } from 'commander';
import {
    configureDisableAutoSync,
    configureMcpAllow,
    configureMcpList,
    configureMcpRevoke,
    configureSaveMasterPassword,
    configureUserPresenceVerification,
} from '../command-handlers/index.js';

export const configureCommands = (params: { program: Command }) => {
    const { program } = params;

    const configureGroup = program.command('configure').alias('c').description('Configure the CLI');

    configureGroup
        .command('disable-auto-sync <boolean>')
        .description('Disable automatic synchronization which is done once per hour (default: false)')
        .action(configureDisableAutoSync);

    configureGroup
        .command('save-master-password <boolean>')
        .description('Should the encrypted master password be saved and the OS keychain be used (default: true)')
        .action(configureSaveMasterPassword);

    configureGroup
        .command('user-presence')
        .description(
            'Configure the method used to verify user presence (prevent access to vault without selected method)'
        )
        .addOption(
            new Option('-m, --method <type>', 'Method used to verify user presence')
                .choices(['none', 'biometrics'])
                .makeOptionMandatory(true)
        )
        .action(configureUserPresenceVerification);

    configureGroup
        .command('mcp-allow')
        .description('Allow the MCP broker to send a secret (matched by exact title, saved by item id) to a website')
        .addOption(new Option('-t, --title <title>', 'Exact title of the secret').makeOptionMandatory(true))
        .addOption(
            new Option(
                '-w, --website <website>',
                'Website that can receive the secret, e.g. api.github.com'
            ).makeOptionMandatory(true)
        )
        .option('--id <id>', 'Item id, only needed when several items have the same title')
        .option(
            '--auth-scheme <scheme>',
            'Word before the secret in the Authorization header, e.g. Bearer, Basic or Token (default: auto-detect)'
        )
        .action(configureMcpAllow);

    configureGroup
        .command('mcp-list')
        .description('List the websites each secret is allowed to be sent to by the MCP broker')
        .action(configureMcpList);

    configureGroup
        .command('mcp-revoke')
        .description('Remove one website from a secret rule, or the whole rule if no website is given')
        .addOption(new Option('-t, --title <title>', 'Exact title of the secret').conflicts('index'))
        .addOption(new Option('-i, --index <index>', 'Index of the rule shown by mcp-list').conflicts('title'))
        .option('-w, --website <website>', 'Website to remove from the rule (default: remove the whole rule)')
        .action(configureMcpRevoke);
};
