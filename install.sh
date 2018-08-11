# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


for port in $(seq 1 1023); do
	sudo touch /etc/authbind/byport/${port} && sudo chown ${USER}:${USER} /etc/authbind/byport/${port} && chmod 500 /etc/authbind/byport/${port};
done

mkdir -p ~/bin/ && cp $(which iptables) ~/bin/iptables
sudo setcap CAP_NET_RAW,CAP_NET_ADMIN+ep ~/bin/iptables

sudo mkdir -p /var/run/intrasploit/ && sudo chown ${USER}:${USER} /var/run/intrasploit
cp build/intrasploit.ini ${HOME}/.config/
for port in $(seq 1 1023); do sudo touch /etc/authbind/byport/${port} && sudo chown ${USER}:${USER} /etc/authbind/byport/${port} && chmod 500 /etc/authbind/byport/${port}; done
sudo cp build/isfconfig.service /etc/systemd/system/
sudo cp build/isfdatabase.service /etc/systemd/system/
sudo cp build/isfdns.service /etc/systemd/system/
sudo cp build/isfimport_modules.service /etc/systemd/system/
sudo cp build/isfrshell.service /etc/systemd/system/
sudo cp build/isfservice_detection.service /etc/systemd/system/
sudo cp build/isfwebserver.service /etc/systemd/system/

