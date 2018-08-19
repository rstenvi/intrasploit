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
$ sudo sudo systemctl daemon-reload
```

Start all services

```
$ sudo bash control.sh start
```

Stop all services:

```
$ sudo bash control.sh stop
```

To restart individual services (usually after a change):

```
$ sudo bash control.sh restart <isfconfig | isfwebserver | isfservice_detection | isfrshell | isfimport_modules | isfdns | isfdatabase>
```

### Run as root

Not been tested, but you need to take the following steps before following the
procedure above:

1. In install.sh remove commands that copy iptables and loop that create files
   for authbind
2. Remove reference to authbind in build.sh
3. Change to root user before running install.sh (sudo -s)


## Design

The following is a high-level description of the design goals:

1. Modular design where components can work relatively independently
2. Each exploit should run as a seperate module indpended of the main program.
3. The program should allow for automatic exploitation when a user has visited a
web site

### 1. Modular design

Each substantial function is running as a different service and process.
Communication between them happens via Unix domain sockets and each service
exposes a HTTP REST API.

The following services exist:

- config - holds configuration information
- webserver - publicly exposed web server and an internal process to control the
  public web server
- DNS - publicly exposed DNS server and internal process to control DNS server
- import_modules
- service_detection - try and detect which service the target service is
  running.
- database - hold information about all the clients.
- rshell - receive and manage remote reverse shells

All the services are under [services/](services/).

### 2. Exploit modules

Exploit modules can be written without having an understanding of the inner
workings of intrasploit. It is therefore relatively easy for users to extend
intrasploit to new services.

All modules fall into one of three categories:

1. Exploits - Anything that accomplishes a goal in and of itself, i.e. it
doesn't need to be what is traditionally called an exploit, it's just a module
that performs some action.
2. Payloads - Payloads helps exploits modules perform some action. Payloads are
not necessary in most exploits, but in some cases, it is useful. One example is
the exploit for [MSFD](modules/exploits/msfd_rce.py) where the payload is a
reverse shell.
3. Encoder - Encode some payload according to defined bad characters. This is
again, usually not used, but is used in the exploit for MSFD.

All the modules are under [modules/](modules/).

### 3. Automatic exploitation

The basic exploit requires the user to visit a web site and when the user leaves
the web site, there is no more possibility for exploitation. As a result,
exploitation should be performed as quickly as possible.

To achieve this, several design choices have been made.

#### Service detection

After DNS rebinding has been performed, the result will be sent back to the
server for service detection. Service detection matches the result against
nmap's database of probes as well as other self-defined probes to find out what
type of service is running.

Each module can define which service is "vulnerable" and therefore decide when
to be triggered. The services defined can be generic, like a web site using
basic authentication to specific, like a specific version of CouchDB.

#### User-defined options

Before starting the program, the user must decide on most options that are
relevant for modules, this could be options like:

1. IP and port to be used when spawning a reverse shell.
2. IPs to use when hijacking a router's DNS setings.
3. List of usernames and password to use when attempting to brute force
password.

#### Re-use of module-output

A module will gather two types of information, (1) loot and (2) data. Data is
arbitrary and can be whatever information doesn't fall into one specific
category. Loot should be more actionable and should be data that is useful for
an attacker. Loot can again be divided into two categories:

1. Information that is useful, but cannot be used by this tool, like WPA
password for wireless access points.
2. Information that can be re-used by this tool, like username and password for
a web site.

While the user-defined options is global for all modules, loot is specific for
each service and will be set when loading the module. This design allows us to
re-use passwortds we have discovered. The typical way this will look like is:

1. DNS rebinding is done and page returns HTTP 401 because we don't know the
password.
2. Module which performs a password dictionary attack is loaded and reports back failure
or success.
3. If module is successful, service detection is performed again, but with the
found username and password.
4. This time, a router is found and the appropriate modules is loaded with the
correct username and password.

#### When to launch a module

To further restrict when modules should be launched, the user can define safety-
and intrusiveness-levels. Both levels are numerically ordered, so that the user
defines the top-most acceptable level for each.
