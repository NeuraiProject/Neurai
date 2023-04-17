Sample init scripts and service configuration for neuraid
==========================================================

Sample scripts and configuration files for systemd, Upstart and OpenRC
can be found in the contrib/init folder.

    contrib/init/neuraid.service:    systemd service unit configuration
    contrib/init/neuraid.openrc:     OpenRC compatible SysV style init script
    contrib/init/neuraid.openrcconf: OpenRC conf.d file
    contrib/init/neuraid.conf:       Upstart service configuration file
    contrib/init/neuraid.init:       CentOS compatible SysV style init script

Service User
---------------------------------

All three Linux startup configurations assume the existence of a "neurai" user
and group.  They must be created before attempting to use these scripts.
The OS X configuration assumes neuraid will be set up for the current user.

Configuration
---------------------------------

At a bare minimum, neuraid requires that the rpcpassword setting be set
when running as a daemon.  If the configuration file does not exist or this
setting is not set, neuraid will shutdown promptly after startup.

This password does not have to be remembered or typed as it is mostly used
as a fixed token that neuraid and client programs read from the configuration
file, however it is recommended that a strong and secure password be used
as this password is security critical to securing the wallet should the
wallet be enabled.

If neuraid is run with the "-server" flag (set by default), and no rpcpassword is set,
it will use a special cookie file for authentication. The cookie is generated with random
content when the daemon starts, and deleted when it exits. Read access to this file
controls who can access it through RPC.

By default the cookie is stored in the data directory, but it's location can be overridden
with the option '-rpccookiefile'.

This allows for running neuraid without having to do any manual configuration.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

For an example configuration file that describes the configuration settings,
see `contrib/debian/examples/neurai.conf`.

Paths
---------------------------------

### Linux

All three configurations assume several paths that might need to be adjusted.

Binary:              `/usr/bin/neuraid`  
Configuration file:  `/etc/neurai/neurai.conf`  
Data directory:      `/var/lib/neuraid`  
PID file:            `/var/run/neuraid/neuraid.pid` (OpenRC and Upstart) or `/var/lib/neuraid/neuraid.pid` (systemd)  
Lock file:           `/var/lock/subsys/neuraid` (CentOS)  

The configuration file, PID directory (if applicable) and data directory
should all be owned by the neurai user and group.  It is advised for security
reasons to make the configuration file and data directory only readable by the
neurai user and group.  Access to neurai-cli and other neuraid rpc clients
can then be controlled by group membership.

NOTE: When using the systemd .service file, the creation of the aforementioned
directories and the setting of their permissions is automatically handled by
systemd. Directories are given a permission of 710, giving the neurai group
access to files under it _if_ the files themselves give permission to the
neurai group to do so (e.g. when `-sysperms` is specified). This does not allow
for the listing of files under the directory.

NOTE: It is not currently possible to override `datadir` in
`/etc/neurai/neurai.conf` with the current systemd, OpenRC, and Upstart init
files out-of-the-box. This is because the command line options specified in the
init files take precedence over the configurations in
`/etc/neurai/neurai.conf`. However, some init systems have their own
configuration mechanisms that would allow for overriding the command line
options specified in the init files (e.g. setting `NEURAID_DATADIR` for
OpenRC).

### macOS

Binary:              `/usr/local/bin/neuraid`  
Configuration file:  `~/Library/Application Support/Neurai/neurai.conf`  
Data directory:      `~/Library/Application Support/Neurai`  
Lock file:           `~/Library/Application Support/Neurai/.lock`  

Installing Service Configuration
-----------------------------------

### systemd

Installing this .service file consists of just copying it to
/usr/lib/systemd/system directory, followed by the command
`systemctl daemon-reload` in order to update running systemd configuration.

To test, run `systemctl start neuraid` and to enable for system startup run
`systemctl enable neuraid`

### OpenRC

Rename neuraid.openrc to neuraid and drop it in /etc/init.d.  Double
check ownership and permissions and make it executable.  Test it with
`/etc/init.d/neuraid start` and configure it to run on startup with
`rc-update add neuraid`

### Upstart (for Debian/Ubuntu based distributions)

Drop neuraid.conf in /etc/init.  Test by running `service neuraid start`
it will automatically start on reboot.

NOTE: This script is incompatible with CentOS 5 and Amazon Linux 2014 as they
use old versions of Upstart and do not supply the start-stop-daemon utility.

### CentOS

Copy neuraid.init to /etc/init.d/neuraid. Test by running `service neuraid start`.

Using this script, you can adjust the path and flags to the neuraid program by
setting the NEURAID and FLAGS environment variables in the file
/etc/sysconfig/neuraid. You can also use the DAEMONOPTS environment variable here.

### Mac OS X

Copy org.neurai.neuraid.plist into ~/Library/LaunchAgents. Load the launch agent by
running `launchctl load ~/Library/LaunchAgents/org.neurai.neuraid.plist`.

This Launch Agent will cause neuraid to start whenever the user logs in.

NOTE: This approach is intended for those wanting to run neuraid as the current user.
You will need to modify org.neurai.neuraid.plist if you intend to use it as a
Launch Daemon with a dedicated neurai user.

Auto-respawn
-----------------------------------

Auto respawning is currently only configured for Upstart and systemd.
Reasonable defaults have been chosen but YMMV.
