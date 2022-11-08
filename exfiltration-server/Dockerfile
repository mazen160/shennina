FROM alpine

RUN apk update
RUN apk add python3
RUN apk add py-pip

RUN pip install flask

WORKDIR /app

COPY server.py .
COPY agent.sh .
COPY agent.ps1 .
COPY ransomware-simulation.sh .
COPY ransomware-simulation.ps1 .

USER nobody

CMD python3 server.py
