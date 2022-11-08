#!/usr/bin/env python3
import os
import sys
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PATH)
import config
import exploits_cluster
import msf_wrapper


def match_service_with_exploits(service_scan_results):
    output = service_scan_results
    for port in service_scan_results["ports"]:
        # First: Match ports+platform by exploits
        exploits_candidates = exploits_cluster.map_port_to_exploits(port, service_scan_results["osname"])

        output["service_details"][port]["exploits"] = exploits_candidates

        # Second: Match product by exploits
        product = service_scan_results["service_details"][port]["product"]

        exploits_candidates = msf_wrapper.search_for_exploits(product)
        if product.lower() == "apache httpd":
            exploits_candidates.extend(exploits_cluster.map_port_to_exploits(80, "unix"))

        if config.SCANNING_THROUGH_TEST:
            # Third: Match by name for Thorough test - unreliable and generates a lot of FPs.
            # Disabled by default.
            name = service_scan_results["service_details"][port]["name"]
            exploits_candidates.extend(msf_wrapper.search_for_exploits(name, product=False))

        output["service_details"][port]["exploits"].extend(exploits_candidates)
        output["service_details"][port]["exploits"] = list(set(output["service_details"][port]["exploits"]))

    return output


def post_process_exploit_suggestion(port_number, osname, product_name, exploit):
    exploits_candidates = []
    exploits_candidates.extend(exploits_cluster.map_port_to_exploits(port_number, osname))
    exploits_candidates.extend(msf_wrapper.search_for_exploits(product_name))

    if exploit in exploits_candidates and exploit in config.EXPLOITS_ARRAY:
        return True
    else:
        return False
