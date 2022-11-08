#!/bin/bash
docker build --rm -t exfiltration-server .
docker run --rm -p 8040:8040 exfiltration-server
