# `neurai.conf` Configuration File

The configuration file is used by `neuraid`, `neurai-qt` and `neurai-cli`.

All command-line options (except for `-?`, `-help`, `-version` and `-conf`) may be specified in a configuration file, and all configuration file options may also be specified on the command line. Command-line options override values set in the configuration file.

## Configuration File Format

The configuration file is a plain text file and consists of `option=value` entries, one per line. Leading and trailing whitespaces are removed.

In contrast to the command-line usage:
- an option must be specified without leading `-`;
- a value of the given option is mandatory; e.g., `testnet=1` (for chain selection options), `noconnect=1` (for negated options).

### Blank lines

Blank lines are allowed and ignored by the parser.

### Comments

A comment starts with a number sign (`#`) and extends to the end of the line. All comments are ignored by the parser.

Comments may appear in two ways:
- on their own on an otherwise empty line (_preferable_);
- after an `option=value` entry.

### Network specific options

Network-specific options are **not** supported: there is no `regtest.` /
`test.` prefix and no `[regtest]` / `[test]` section. Such lines are read as
unknown options and ignored. Every option in the file applies to whichever
network is selected, so use a separate data directory (`-datadir`) or
configuration file (`-conf`) per network. Note that testnet and regtest
already store their data in the `testnet` and `regtest` subdirectories, but
they read the same `neurai.conf` from the base data directory.

## Configuration File Path

The configuration file is not automatically created; you can create it using your favorite text editor. By default, the configuration file name is `neurai.conf` and it is located in the Neurai data directory, but both the Neurai data directory and the configuration file path may be changed using the `-datadir` and `-conf` command-line options.

### Default configuration file locations

Operating System | Data Directory | Example Path
-- | -- | --
Windows | `%APPDATA%\Neurai\` | `C:\Users\username\AppData\Roaming\Neurai\neurai.conf`
Linux | `$HOME/.neurai/` | `/home/username/.neurai/neurai.conf`
macOS | `$HOME/Library/Application Support/Neurai/` | `/Users/username/Library/Application Support/Neurai/neurai.conf`

You can find an example neurai.conf file in [contrib/debian/examples/neurai.conf](../contrib/debian/examples/neurai.conf).
