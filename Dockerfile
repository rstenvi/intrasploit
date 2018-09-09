FROM python:3

RUN apt-get update && apt-get install iptables -y

WORKDIR /usr/src/app

copy requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt


COPY . .

RUN mkdir -p ${HOME}/.config && cp build/intrasploit.ini ${HOME}/.config/


ENTRYPOINT [ "python", "./intrasploit.py" ]

