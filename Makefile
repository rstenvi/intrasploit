# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

test:
	authbind python3 -m unittest discover tests/

clean:
	-rm -f logfile.log
	-rm -rf modules/__pycache__/ lib/__pycache__/ services/__pycache__/ tests/__pycache__/
	-rm -rf build/

