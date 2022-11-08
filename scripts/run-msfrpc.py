#!/usr/bin/env python3
import json
import os
import sys
PROJECT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_PATH)
MSFRPC_CONFIG = open(PROJECT_PATH + "/config/" + "msfrpc-config.json")
MSFRPC_CONFIG = json.loads(MSFRPC_CONFIG.read())


def main():
    launching_option = "msfconsole"
    if len(sys.argv) < 2:
        launching_option = "msfconsole"
    elif sys.argv[1] == "msfrpcd":
        launching_option = "msfrpcd"

    if launching_option == "msfconsole":
        cmd = "msfconsole -x 'load msgrpc ServerHost={host} User={user} Pass={password} ServerPort={port} SSL=true'".format(password=MSFRPC_CONFIG["password"],
                                                                                                                            user=MSFRPC_CONFIG["user"],
                                                                                                                            host=MSFRPC_CONFIG["host"],
                                                                                                                            port=MSFRPC_CONFIG["port"])
    elif launching_option == "msfrpcd":
        cmd = "msfrpcd -p {port} -P {password} -U {user} -a {host}".format(password=MSFRPC_CONFIG["password"],
                                                                           user=MSFRPC_CONFIG["user"],
                                                                           host=MSFRPC_CONFIG["host"],
                                                                           port=MSFRPC_CONFIG["port"])

    print(cmd)
    os.system(cmd)
    sys.exit(0)


if __name__ == "__main__":
    main()
