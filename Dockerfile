FROM debian:bullseye

RUN apt update
RUN apt install -y nmap
RUN apt install -y python3 python3-pip

WORKDIR /app

COPY requirements.txt .
RUN ls -ah1l
RUN pip3 install -r requirements.txt
COPY . .
