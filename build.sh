# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


mkdir -p build

root=$1
publicip=$2

python3 gen_file.py --json "{\"demo\":\"False\",\"root\":\"${root}\", \"publicip\":\"${publicip}\", \"webport\":80, \"storage\":\"${HOME}/intrasploit.json\"}" --template config.tmpl --output build/intrasploit.ini

FILES=(config database webserver import_modules rshell dns service_detection)
for file in "${FILES[@]}"; do
	# Base config that will be overwritten in some cases
	user=$(id -u -n)
	group=$(id -g -n)
	tmpl="service_after"

	# Config service has no dependencies
	if [[ "$file" == "config" ]]; then
		tmpl="service"
	fi

	authbind=""
	# webserver and dns must run with authbind
	if [[ "$file" == "webserver" ]] || [[ "$file" == "dns" ]]; then
		authbind="/usr/bin/authbind --depth 4 "
	fi
	python3 gen_file.py --template templates/${tmpl}.tmpl --output build/isf${file}.service --json "{\"homebin\":\"${HOME}/bin\",\"authbind\":\"${authbind}\", \"name\":\"${file}\",\"user\":\"${user}\",\"group\":\"${group}\",\"home\":\"${PWD}\"}"
done

