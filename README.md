# intrasploit
A framework to exploit DNS rebinding vulnerabilities.

## Development Status

In alpha-stage, see overview of TODO-list below:

- [x] Finish demo
- [ ] Finish script for testing modules without going through DNS rebinding
  process
- [ ] Finish HTML- and JS-code.

## Demo

A live demo of intrasploit can be found at [intrasploit.com](http://intrasploit.com)


## Install

The program run as 7 different services, two of them require root privileges.
Mixing between root and non-root will cause problems with logging and ownership
of log files, therefore we must either run all as non-root or all as root.

### Run as non-root

This is the setup I use, so this is the setup that is best tested.

Install autbind, on Ubuntu:

```
$ sudo apt-get install authbind
```

Run the build script with your root domain and your public IP address. This
script will create the necessary files in the build/ directory.

```
$ bash build.sh <root domain> <public IP address>
```

Install script performs the following:

1. Allow the current user to bind ports 1 - 1023 (authbind)
2. Copy iptables binary to $HOME/bin and allow current user to use it
3. Creates directory /var/run/intrasploit so that user is allowed to create Unix
   domain sockets there
4. Copy config to $HOME/.config/intrasploit.ini
5. Copy service files to /etc/systemd/system/

The install-script must be run as the user who should be the owner of the
processes. The script will use sudo when necessary.

```
$ bash install.sh
```

Start all services

```
$ sudo sudo systemctl daemon-reload
$ sudo bash control.sh start
```

### Run as root

Not been tested, but you need to take the following steps before following the
procedure above:

1. In install.sh remove commands that copy iptables and loop that create files
   for authbind
2. Remove reference to authbind in build.sh
3. Change to root user before running install.sh (sudo -s)
