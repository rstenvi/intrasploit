# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Control each of services started

services=(isfconfig isfwebserver isfservice_detection isfrshell isfimport_modules isfdns isfdatabase)

usage()	{
	echo "Usage  ${0} <start|stop|restart> [service]"
}

control_one()	{
	echo "Running ${1} on service ${2}"
	sudo systemctl ${1} ${2}
}

control_all()	{
	for service in "${services[@]}"; do
		control_one $1 ${service}
	done
}

if [ $# -ge 1 ]; then
	if [[ "$1" != "start" ]] && [[ "$1" != "restart" ]] && [[ "$1" != "stop" ]]; then
		echo "Wrong action: ${1}"
		usage
		exit 1
	fi

	if [ $# -eq 2 ]; then
		control_one $1 $2
	else
		control_all $1
	fi
else
	echo "Not enough parameters"
	usage
	exit 1
fi
