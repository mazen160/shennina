#!/usr/bin/env python3
import config
from datetime import datetime
import json
import random
from termcolor import colored
import ipaddress
import os
import uuid
import requests
import subprocess

banner = """  ____  _                      _
 / ___|| |__   ___ _ __  _ __ (_)_ __   __ _
 \___ \| '_ \ / _ \ '_ \| '_ \| | '_ \ / _` |
  ___) | | | |  __/ | | | | | | | | | | (_| |
 |____/|_| |_|\___|_| |_|_| |_|_|_| |_|\__,_|

v0.3
"""


def current_date():
    return datetime.now().strftime("%d-%m-%Y")


def current_time():
    return datetime.now().strftime("%H:%M:%S")


def uuidgen():
    return str(uuid.uuid4())


def generate_ip_addresses_from_ip_range(ip_range):
    return [str(_) for _ in ipaddress.IPv4Network(ip_range)]


def generate_random_port():
    return str(random.randint(4096, 65535))


def generate_scan_path(host):
    output_path = "{SCANS_PATH}info_{host}.json".format(SCANS_PATH=config.SCANS_PATH, host=host)
    return(output_path)


def generate_exploitation_result_path(host):
    output_path = "{SCANS_PATH}info_exploitation_scan_{host}.json".format(SCANS_PATH=config.SCANS_PATH, host=host)
    return(output_path)


def check_if_cached_scan_exists(host):
    return os.path.exists(generate_scan_path(host))


def check_if_filename_exists(filename):
    file_path = "data/{}.json".format(filename)
    return os.path.exists(file_path)


def load_scan(host):
    f = open(generate_scan_path(host), "r")
    output = json.loads(f.read())
    f.close()
    return output


def load_exploitation_result(host):
    f = open(generate_exploitation_result_path(host), "r")
    output = json.loads(f.read())
    f.close()
    return output


def get_successful_ports(host):
    result = load_exploitation_result(host)
    return len(list(set([i['port'] for i in result['results']])))


def get_exploit_and_port_reward(host, exploit, port):
    try:
        result = load_exploitation_result(host)
        for i in result['results']:
            if i['exploit_name'] == exploit and i['port'] == port:
                return 1
        return -1
    except Exception as e:
        print(e)
        return -1


def get_exploit_reward(input_data, action):
    try:
        result = load_exploitation_result(input_data['host'])
        for i in result['results']:
            if i['exploit_name'] == action and i['name'] == input_data['name'] and i['platform'] == input_data['platform']:
                return i
        return {"host": None}
    except Exception as e:
        print(e)
        return {"host": None}


def generate_exploitation_scan(host):
    output_path = "{SCANS_PATH}info_exploitation_scan_{host}.json".format(SCANS_PATH=config.SCANS_PATH, host=host)
    return(output_path)


def generate_exploitation_report_path(host):
    output_path = "{REPORTS_PATH}report_{host}.md".format(REPORTS_PATH=config.REPORTS_PATH, host=host)
    return(output_path)


def generate_exploitation_report(host, exploitation_result, exfiltration_output):
    report_path = generate_exploitation_report_path(host)
    exploit_details = get_exploit_details(exploitation_result["exploit_name"])
    references = "\n".join(["-".join([b for b in a]) for a in exploit_details["references"]])
    references = references.replace("URL-http", "http")  # URLs are received from MSF in a different format

    output = """
# Shennina Exploitation Report

## Target: `{target}`

#### The target has been compromised using the following:


## Exploit: `{exploit_name}`

## Exploit Details

### Name

```
{exploit_detailed_name}
```

### Description

```
{exploit_description}
```

### References

```
{exploit_references}
```

## Shell Type: `{shell}`

## Payload: `{payload}`


""".format(target=host, exploit_name=exploitation_result["exploit_name"],
           exploit_detailed_name=exploit_details["name"],
           exploit_description=exploit_details["description"],
           exploit_references=references,
           shell=exploitation_result["type"],
           payload=exploitation_result["payload"])

    if len(exfiltration_output) == 0:
        f = open(report_path, "w")
        f.write(output)
        f.close()
        return report_path
    output += """
---

# Data Obtained From Target via Exfiltration Server
"""

    for _ in exfiltration_output.keys():
        output += """### {name}\n\n```\n{data}\n```\n\n""".format(name=_, data=exfiltration_output[_])

    f = open(report_path, "w")
    f.write(output)
    f.close()
    return report_path


def generate_vulnerability_scan_report_path(host):
    output_path = "{REPORTS_PATH}vulnerability_scan_report_{host}.md".format(REPORTS_PATH=config.REPORTS_PATH, host=host)
    return(output_path)


def check_access_to_exfiltration_server():
    ping_url = "http://{}/ping".format(config.EXFILTRATION_SERVER)
    try:
        if requests.get(ping_url).text == "pong\n":
            return True
        else:
            return False
    except KeyboardInterrupt:
        return False


def check_if_current_user_is_root():
    if os.getuid() == 0:
        return True
    else:
        return False


def generate_vulnerability_scan_report(host, results_list, failed_list):
    output = """# Shennina Vulnerability Scan Report

## Target: `{target}`

""".format(target=host)
    output += "\n\n## Total Number of Successful Exploits: `{}`".format(len(results_list))
    output += "\n\n## Total Number of Tested Exploits: `{}`".format(len(results_list) + len(failed_list))
    output += "\n\n## Results\n\n"
    if len(results_list) == 0:
        output += "No automated remote exploit was identified to be working against the host.\n\n"
        report_path = generate_vulnerability_scan_report_path(host)
        f = open(report_path, "w")
        f.write(output)
        f.close()
        return report_path
    output += "\n\n---\n\n"

    for result in results_list:
        exploit_details = get_exploit_details(result["exploit_name"])
        references = "\n".join(["-".join([b for b in a]) for a in exploit_details["references"]])
        references = references.replace("URL-http", "http")  # URLs are received from MSF in a different format

        output += """\n\n## Exploit: `{exploit_name}`
#### Port: `{port}`

#### Service Name: `{name}`

#### Product: `{product}` `{version}`

#### Exploit Details

##### Name

```
{exploit_detailed_name}
```

##### Description

```
{exploit_description}
```

##### References

```
{exploit_references}
```


#### Shell Type: `{shell}`

#### Payload: `{payload}`

---
""".format(exploit_name=result["exploit_name"],
           name=result["name"],
           product=result["product"],
           exploit_detailed_name=exploit_details["name"],
           exploit_description=exploit_details["description"],
           exploit_references=references,
           version=result["version"],
           shell=result["type"],
           payload=result["payload"],
           port=result["port"])
    report_path = generate_vulnerability_scan_report_path(host)
    f = open(report_path, "w")
    f.write(output)
    f.close()
    return report_path


def save_exploitation_scan(host, results_list, failed_list):
    output_path = generate_exploitation_scan(host)
    data = {"target": host,
            "results": results_list,
            "failed_tests": failed_list}
    f = open(output_path, "w")
    f.write(json.dumps(data, indent=4))
    f.close()


def save_file(filename, json_result):
    output_path = "data/{}.json".format(filename)
    f = open(output_path, "w")
    f.write(json.dumps(json_result, indent=4))
    f.close()


def load_exploitation_scan(host):
    f = open(generate_exploitation_scan(host), "r")
    output = json.loads(f.read())
    f.close()
    return output


def load_file(filename):
    file_path = "data/{}.json".format(filename)
    f = open(file_path, "r")
    output = json.loads(f.read())
    f.close()
    return output


def check_if_exploit_is_in_exploits_tree(exploit):
    for _ in config.EXPLOITS_TREE:
        if _["exploit"] == exploit:
            return True
    return False


def get_value(array, ind):
    if (ind - 1) < len(array):
        return array[ind - 1]
    return None


def get_index(array, item):
    # preventing negative values
    return array.index(item) + 1 if item in array else 0


def get_exploit_details(exploit_name):
    if not exploit_name.startswith("exploit/"):
        exploit_name = "exploit/" + exploit_name
    exploit_name = exploit_name[8:]
    for exploit in config.EXPLOITS_TREE:
        if exploit["exploit"] == exploit_name:
            return exploit
    return None


def execute_linux_exploit_suggester_tool(uname_output):
    LINUX_EXPLOIT_SUGGESTER_PATH = "{PROJECT_PATH}/thirdparty/linux-exploit-suggester.sh".format(PROJECT_PATH=config.PROJECT_PATH)
    uname_output = uname_output.replace("'", "INVALID").replace("\n", "INVALID").replace("\\", "INVALID")
    cmd = """bash '{LINUX_EXPLOIT_SUGGESTER_PATH}' -u '{uname_output}' """.format(LINUX_EXPLOIT_SUGGESTER_PATH=LINUX_EXPLOIT_SUGGESTER_PATH,
                                                                                  uname_output=uname_output)
    output = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
    if type(output) == bytes:
        output = output.decode("utf-8")
    return output


def generate_chunks(seq, num):
    # This method takes an array and divides it into
    # an n number of arrays
    avg = len(seq) / float(num)
    out = []
    last = 0.0
    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg
    return out


class PPrint(object):
    def error(self, text):
        print("{} [{}] {}".format(colored("[!]", 'red', attrs=['bold']),
                                  colored(current_time(), "magenta"),
                                  text))

    def success(self, text):
        print("{} [{}] {}".format(colored("[$]", 'green', attrs=['bold']),
                                  colored(current_time(), "magenta"),
                                  text))

    def info(self, text):
        print("{} [{}] {}".format(colored('[*]', 'cyan', attrs=['bold']),
                                  colored(current_time(), "magenta"),
                                  text))

    def testing_exploit(self, text):
        print("{} [{}] {}".format(colored('[.]', attrs=['bold']),
                                  colored(current_time(), "magenta"),
                                  text))

    def initial_message(self):
        starting_time = "{} / {}".format(current_time(), current_date())
        print("{}".format(colored(banner, 'green', attrs=["bold", "dark"])))
        print("{} Starting at {}".format(colored('[%]', 'cyan', attrs=['bold']),
                                         colored(starting_time, "magenta")))

    def finishing_message(self):
        finishing_time = "{} / {}".format(current_time(), current_date())
        print("{} Finished at {}".format(colored('[%]', 'cyan', attrs=['bold']),
                                         colored(finishing_time, "magenta")))
