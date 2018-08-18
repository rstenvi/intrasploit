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

## Browsers and Times

Browsers implement DNS pinning, so DNS rebinding doesn't work instantly. An
experiment was performed to get an understanding of how quickly it can be
performed. The test below was done 18. August 2018 with the newest available
version at the time. All the numbers have been rounded to the closest 5.

| Browser | Version | OS | Seconds |
| ------- | ------- | -- | ------- |
| Chrome  | 68.0.3440.106 | Linux | 60s |
| Chrome  | 68.0.3440.106 | Windows 10 | 60s |
| Firefox | 61.0.1 | Linux | 60s |
| Firefox | 61.0.2 | Windows 10 | 5s - 15s |
| Edge    | 42.17134.10 | Windows 10 | 15s |
| IE      | 11.1.17134.0 | Windows 10 | 10s |
| Opera   | 55.0.2994.37 | Windows 10 | 60s |
| Vivaldi | 1.15.1147.64 | Windows 10 | 60s |
| Samsung Internet | 7.2.10.33 | Android | 60s |

***NB!*** When testing with the demo, the times will be a little higher, there
are a couple of reasons for this:

- The time is measured from start of rebinding and until first request is sent
  to target service. Additional service detection takes some time.
- In the demo, the client must poll the server to find out if rebinding has
  finished. This may add an additional 10 seconds.

***NB!*** Most tests were performed once, as I got results similar to what I had
seen during development. The exception was Firefox for Windows, which I tested about
10 times. I got similar, but slightly different results every time. Most of my
testing during development was on Firefox for Linux where I also saw similarly
low times, but this only happened occasionally.

***NB!*** The table only represent setups I have tested, it does not represent
which setups are vulnerable.

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
