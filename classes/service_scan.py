#!/usr/bin/env python3
import nmap
import sys


def run(host):
    nm = nmap.PortScanner()
    result = nm.scan(host, arguments='-n -Pn --open --top-ports 500 -O -T4 -sV')
    if len(result["scan"].keys()) == 0:
        print("Service Scan error")
        sys.exit(1)
    nhost = list(result["scan"].keys())[0]
    try:
        osname = result["scan"][nhost]["osmatch"][0]["osclass"][0]["vendor"].lower()
    except Exception:
        print("Service Scan error")
        sys.exit(1)

    output = {"scanstats_elapsed": result["nmap"]["scanstats"]["elapsed"],
              "ports": list(result["scan"][nhost]["tcp"].keys()),
              "osmatch": result["scan"][nhost]["osmatch"][0]["name"],
              "osname": osname,
              "service_details": {}
              }
    for port in output["ports"]:
        info = {"name": result["scan"][nhost]["tcp"][port]["name"],
                "product": result["scan"][nhost]["tcp"][port]["product"],
                "version": result["scan"][nhost]["tcp"][port]["version"],
                "extrainfo": result["scan"][nhost]["tcp"][port]["extrainfo"],
                "cpe": result["scan"][nhost]["tcp"][port]["cpe"]
                }
        output["service_details"][port] = info
    return output
