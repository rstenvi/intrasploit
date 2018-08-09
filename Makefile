# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

all:
	bash build.sh

test:
	authbind python3 -m unittest discover tests/

clean:
	-rm -f logfile.log
	-rm -rf modules/__pycache__/ lib/__pycache__/ services/__pycache__/ tests/__pycache__/
	-rm -rf build/

install:
	sudo mkdir -p /var/run/intrasploit/ && sudo chown ${USER}:${USER} /var/run/intrasploit
	cp build/intrasploit.ini ${HOME}/.config/
	sudo cp build/isfconfig.service /etc/systemd/system/
	sudo cp build/isfdatabase.service /etc/systemd/system/
	sudo cp build/isfdns.service /etc/systemd/system/
	sudo cp build/isfimport_modules.service /etc/systemd/system/
	sudo cp build/isfrshell.service /etc/systemd/system/
	sudo cp build/isfservice_detection.service /etc/systemd/system/
	sudo cp build/isfwebserver.service /etc/systemd/system/

