FROM python:3

WORKDIR /usr/src/app

COPY . .

RUN apt-get update && apt-get install iptables -y
RUN mkdir -p ${HOME}/.config && cp build/intrasploit.ini ${HOME}/.config/

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python", "./intrasploit.py" ]

