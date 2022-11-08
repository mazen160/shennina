#!/usr/bin/env python3
import argparse
import utils
import sys
import config
import os
import itertools
from utils import PPrint
sys.path.append(config.PROJECT_PATH + "/classes/")
import generate_exploits_tree
import a3c_classes
import workers
import msf_wrapper
import msf_wrapper_alpha
import time


def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target",
                        dest="target",
                        help="The target host.",
                        action='store')
    parser.add_argument("--lhost",
                        dest="lhost",
                        help="Lhost Address.",
                        action='store')
    parser.add_argument("--reinforcement-training-mode",
                        dest="reinforcement_training_mode",
                        help="Reinforcment training mode.",
                        action='store_true')
    parser.add_argument("--initialize-exploits-tree",
                        dest="initialize_exploits_tree",
                        help="Initialize exploits tree.",
                        action='store_true')
    parser.add_argument("--service-scan-only",
                        dest="service_scan_only",
                        help="Perform a service scan only.",
                        action='store_true')
    parser.add_argument("--use-cached-service-scan",
                        dest="use_cached_service_scan",
                        help="Use cached service scan, if any.",
                        action='store_true')
    parser.add_argument("--training-mode",
                        dest="training_mode",
                        help="Training mode.",
                        action='store_true')
    parser.add_argument("--secondary-mode",
                        dest="secondary_mode",
                        help="Use secondary mode for exploitation (Heuristics).",
                        action='store_true')
    parser.add_argument("--exploitation-mode",
                        dest="exploitation_mode",
                        help="Exploitation mode.",
                        action='store_true')
    parser.add_argument("--vulnerability-scan-mode",
                        dest="vulnerability_scan_mode",
                        help="Vulnerability scan mode.",
                        action='store_true')
    parser.add_argument("--ransomware-simulation",
                        dest="ransomware_simulation",
                        help="Run ransomware simulation (option for exploitation mode).",
                        action='store_true')
    parser.add_argument("--deception-detection",
                        dest="deception_detection",
                        help="Use Deception Detection mode that verifies if the compromised machine is a deception box, and terminate post-exploitation upon detection to prevent compromise of operation. (option for exploitation mode).",
                        action='store_true')
    parser.add_argument("--alpha-functionalities",
                        dest="alpha_functionalities",
                        help="Use Alpha functionalities and prototypes of Shennina.",
                        action='store_true')
    args = parser.parse_args()
    return args, parser


def main():

    PPrint().initial_message()

    args, parser = parseArgs()
    if len(sys.argv) <= 1:
        parser.print_help(sys.stdout)
        sys.exit(0)

    client = config.getClient()
    if client is None:
        PPrint().error("Error connecting to MSFRPC server.")
        sys.exit(1)

    if not utils.check_access_to_exfiltration_server():
        PPrint().error("Unable to connect to exfiltration server.")
        sys.exit(1)

    if args.initialize_exploits_tree:
        generate_exploits_tree.run()
        PPrint().finishing_message()
        sys.exit(0)
    if not os.path.exists(config.EXPLOITS_TREE_PATH):
        PPrint().info("Exploits tree is not initialized. It will be automatically initialized now.")
        generate_exploits_tree.run()
    config.EXPLOITS_TREE = config.loadExploitsTree()
    config.EXPLOITS_ARRAY = config.loadExploitsTree(detailed=False)

    if not args.target:
        PPrint().error("Target not specified.")
        sys.exit(1)
    if not args.lhost:
        PPrint().error("Lhost not specified.")
        sys.exit(1)
    os.environ["LHOST"] = args.lhost

    if not utils.check_if_current_user_is_root():
        PPrint().error("The project requires root access on the host machine.")
        sys.exit(1)
    target = args.target
    targets_ = target.replace(" ", "").split(",")
    targets = []
    for target_ in targets_:
        if "/" in target_:
            targets.extend(utils.generate_ip_addresses_from_ip_range(targets_))
        else:
            targets.append(target_)
    del target
    del targets_

    if args.use_cached_service_scan:
        for target in targets:
            if not utils.check_if_cached_scan_exists(target):
                PPrint().error("Cached Scan for {target} does not exist.".format(target=target))
                sys.exit(1)

    if args.service_scan_only:
        PPrint().info("Service Scan only mode launched.")
    if args.training_mode or args.reinforcement_training_mode:
        PPrint().info("Training mode launched.")
    if args.exploitation_mode:
        PPrint().info("Exploitation mode launched.")
        if args.ransomware_simulation:
            PPrint().info("Ransomware Simulation for exploitation mode activated.")
    if args.alpha_functionalities:
        # This changes reflect functionalities that may be unstable.
        PPrint().info("Using Alpha functionalities. It may be unstable. Should not used for production purposes.")
        msf_wrapper.check_if_exploit_executed_successfully_and_returned_shell = msf_wrapper_alpha.check_if_exploit_executed_successfully_and_returned_shell_alpha
        msf_wrapper.run_exploit = msf_wrapper_alpha.run_exploit_alpha

        # Reducing the amount of threads to work with the MSF alpha wrapper.
        config.MAX_TESTING_THREADS = 5
        config.TTL_FOR_EXPLOIT_VALIDATION = 20
        config.CLIENTS = []
        for _ in range(config.MAX_TESTING_THREADS):
            client = config.getClient()
            cid = client.consoles.console().cid
            config.CLIENTS.append(client.consoles.console(cid))
            time.sleep(0.5)
        config.CLIENTS_CYCLE = itertools.cycle(config.CLIENTS)

    for target in targets:
        if args.service_scan_only:
            PPrint().info("Service Scan started at [{target}]".format(target=target))
            workers.service_scan_task(target)
            PPrint().success("Service Scan finished at [{target}]".format(target=target))

        if args.training_mode or args.reinforcement_training_mode:
            results_list, failed_list = workers.scan_target(target, use_cached_service_scan=args.use_cached_service_scan)
            utils.save_exploitation_scan(target, results_list, failed_list)
            service_scan_results = utils.load_scan(target)
            utils.load_exploitation_scan(target)
            master = a3c_classes.MasterAgent(target)
            master.train(service_scan_results)
            PPrint().info("Total number of Shells: [{}]".format(len(results_list)))

        if args.exploitation_mode:
            for target in targets:
                workers.exploitation_mode(target,
                                          use_cached_service_scan=args.use_cached_service_scan,
                                          ransomware_simulation=args.ransomware_simulation,
                                          deception_detection=args.deception_detection,
                                          secondary_mode=args.secondary_mode)
        if args.vulnerability_scan_mode:
            for target in targets:
                workers.vulnerability_scan_target(target,
                                                  use_cached_service_scan=args.use_cached_service_scan)

    # Finishing
    PPrint().finishing_message()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        PPrint().info("SIGINT received.")
        PPrint().info("Exiting...")
        os._exit(1)
