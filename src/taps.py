import json
import random
from typing import List, Dict
from models import (
    TorNode,
    InputConfig,
    Alliance,
    Bandwidth,
    ExitRule,
    Params,
    Result,
    parse_input_config,
    parse_tor_nodes,
)
from GeoLocator import IPGeolocation
import logging as log
from auxFunctions import (
    __is_node_safe,
    __is_node_acceptable,
)
import argparse

# region Configuration
log.basicConfig(
    level=log.ERROR,
    format="%(levelname)s - %(message)s",
)

GEOLITE_DB_PATH = "../GeoLite2-Country_20250610/GeoLite2-Country.mmdb"
DEFAULT_NODES_DATA_PATH = "../inputs/tor_consensus.json"
DEFAULT_CONFIG_PATH = "../inputs/input1.json"

# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument(
    "--nodes",
    dest="nodes_data_path",
    default=DEFAULT_NODES_DATA_PATH,
    help="Path to the Tor nodes consensus JSON file",
)
parser.add_argument(
    "--config",
    dest="config_path",
    default=DEFAULT_CONFIG_PATH,
    help="Path to the client input config JSON file",
)
args = parser.parse_args()

NODES_DATA_PATH = args.nodes_data_path
CONFIG_PATH = args.config_path

GUARD_PARAMS = {
    "safe_upper": 0.95,
    "safe_lower": 2.0,
    "accept_upper": 0.5,
    "accept_lower": 5.0,
    "bandwidth_frac": 0.2,
}
EXIT_PARAMS = {
    "safe_upper": 0.95,
    "safe_lower": 2.0,
    "accept_upper": 0.1,
    "accept_lower": 10.0,
    "bandwidth_frac": 0.2,
}
DEFAULT_TRUST_SCORE_GUARD = (
    1  # Default trust score for guard nodes countries not in any alliance
)

DEFAULT_TRUST_SCORE_EXIT = (
    1  # Default trust score for exit nodes countries not in any alliance
)
# endregion


# region Aux functions
def _filter_exit_nodes(all_nodes: List[TorNode], destination_ip: str) -> List[TorNode]:
    """Returns a list of nodes that can be used as exits.
    Filters nodes based on if they have exit rules that allow the destination IP or if they accept all (*).
    """
    valid_exits = []
    for node in all_nodes:
        is_valid = any(
            (rule.address == "*" or rule.address == destination_ip)
            and rule.action == "accept"
            for rule in node.exit
        )
        if is_valid:
            valid_exits.append(node)

    return valid_exits


def _get_country_trust_map(config: InputConfig) -> Dict[str, float]:
    """
    Creates a map of {country_code: trust_score}.
    If a country is in multiple alliances, it gets the minimum trust score.
    """
    trust_map = {}
    for alliance in config.alliances:
        for country in alliance.countries:
            if country in trust_map:
                trust_map[country] = min(trust_map[country], alliance.trust)
            else:
                trust_map[country] = alliance.trust

    return trust_map


def _bandwidth_weighted_choice(nodes: List[TorNode]) -> TorNode | None:
    """Performs a weighted random selection based on measured bandwidth."""
    if not nodes:
        return None

    total_bandwidth = sum(node.bandwidth.measured for node in nodes)

    selection_point = random.uniform(0, total_bandwidth)

    # Here the weight is progressively increased to increase the chance of selecting some node and don't end with no node choosen,
    # otherwise it would need to do a loop and this would be worst in terms of performance.
    current_weight = 0
    for node in nodes:
        current_weight += node.bandwidth.measured
        if current_weight >= selection_point:
            return node


def _find_secure_relays(
    all_nodes: List[TorNode],
    scores: Dict[str, float],
    alpha_params: Params,
    total_bandwidth: int,
) -> List[TorNode]:
    """
    Identifies safe and acceptable nodes based on scores and bandwidth.
    """
    if not all_nodes:
        return []

    # Sort nodes by their security score in descending order
    sorted_nodes = sorted(
        all_nodes, key=lambda n: scores.get(n.fingerprint, 0), reverse=True
    )

    # Find the maximum score
    s_star = scores.get(sorted_nodes[0].fingerprint, 0)

    safe_nodes = []
    acceptable_nodes = []

    # Separate nodes into safe and acceptable categories
    for node in sorted_nodes:
        score = scores.get(node.fingerprint, 0)

        if __is_node_safe(score, s_star, alpha_params):
            safe_nodes.append(node)
        elif __is_node_acceptable(score, s_star, alpha_params):
            acceptable_nodes.append(node)

    # Build the final set
    secure_set = list(safe_nodes)
    current_bandwidth = sum(n.bandwidth.measured for n in secure_set)
    bandwidth_threshold = total_bandwidth * alpha_params.bandwidth_frac

    # Add acceptable nodes one by one until bandwidth fraction is met
    if current_bandwidth < bandwidth_threshold:
        for node in acceptable_nodes:
            secure_set.append(node)
            current_bandwidth += node.bandwidth.measured
            if current_bandwidth >= bandwidth_threshold:
                break

    return secure_set


# endregion


# region Main functions
def guard_security(
    client_country: str, guard_country: str, trust_map: Dict[str, float]
) -> float:
    """
    Calculates security based on the trust scores of the involved countries.
    """

    involved_countries = {client_country, guard_country}

    security_score = 1.0
    for country in involved_countries:
        trust_score = trust_map.get(country, DEFAULT_TRUST_SCORE_GUARD)
        security_score *= trust_score

    return security_score


def exit_security(
    client_country: str,
    dest_country: str,
    guard_country: str,
    exit_country: str,
    trust_map: Dict[str, float],
) -> float:
    """
    Calculates security based on avoiding untrusted adversaries on both ends.
    """
    entry_countries = {client_country, guard_country}
    exit_countries = {dest_country, exit_country}

    correlating_countries = entry_countries.intersection(exit_countries)

    # If there are no correlating countries => Nice
    if not correlating_countries:
        return 1.0

    # Else the risk is determined by the most untrustworthy adversary in the intersection.
    max_compromise_prob = 0.0
    for country in correlating_countries:
        trust_score = trust_map.get(country, DEFAULT_TRUST_SCORE_EXIT)
        compromise_prob = 1.0 - trust_score
        if compromise_prob > max_compromise_prob:
            max_compromise_prob = compromise_prob

    security_score = 1.0 - max_compromise_prob
    return security_score


def select_guard_node(
    nodes: List[TorNode],
    config: InputConfig,
    alpha_guard: Params,
    trust_map: Dict[str, float],
) -> TorNode | None:
    log.info("Selecting Guard Node...")
    total_guard_bandwidth = sum(n.bandwidth.measured for n in nodes)

    guard_scores = {
        node.fingerprint: guard_security(config.client_country, node.country, trust_map)
        for node in nodes
    }

    secure_guards = _find_secure_relays(
        nodes, guard_scores, alpha_guard, total_guard_bandwidth
    )
    log.info(f"Filtered down to {len(secure_guards)} secure guards.")

    return _bandwidth_weighted_choice(secure_guards)


def select_exit_node(
    nodes: List[TorNode],
    config: InputConfig,
    alpha_exit: Params,
    trust_map: Dict[str, float],
    chosen_guard: TorNode,
    filter_asn_country: bool = False,
) -> TorNode | None:
    log.info("Selecting Exit Node...")

    filtered_exits = _filter_exit_nodes(nodes, config.destination)

    if filter_asn_country:
        filtered_exits = [
            node for node in filtered_exits if node.asn != chosen_guard.asn
        ]

    total_exit_bandwidth = sum(n.bandwidth.measured for n in filtered_exits)

    exit_scores = {
        node.fingerprint: exit_security(
            config.client_country,
            config.destination_country,
            chosen_guard.country,
            node.country,
            trust_map,
        )
        for node in filtered_exits
    }

    secure_exits = _find_secure_relays(
        filtered_exits, exit_scores, alpha_exit, total_exit_bandwidth
    )
    log.info(f"Filtered down to {len(secure_exits)} secure exits.")

    return _bandwidth_weighted_choice(secure_exits)


def select_middle_node(
    nodes: List[TorNode],
    chosen_guard: TorNode,
    chosen_exit: TorNode,
) -> TorNode | None:
    log.info("Selecting Middle Node...")
    middle_candidates = [
        node
        for node in nodes
        if node.fingerprint not in {chosen_guard.fingerprint, chosen_exit.fingerprint}
    ]

    return _bandwidth_weighted_choice(middle_candidates)


# endregion


def select_path(
    nodes: list[TorNode],
    config: InputConfig,
    alpha_guard: Params,
    alpha_exit: Params,
    filter_asn_country: bool = False,
) -> Result | None:
    """
    Main function to select a Guard-Middle-Exit path.
    """

    trust_map = _get_country_trust_map(config)

    # Step 1: Select Guard Node
    chosen_guard = select_guard_node(
        nodes,
        config,
        alpha_guard,
        trust_map,
    )
    if not chosen_guard:
        log.error("Error finding Guard node. Aborting path selection.")
        return None

    # Step 2: Select Exit Node
    chosen_exit = select_exit_node(
        nodes,
        config,
        alpha_exit,
        trust_map,
        chosen_guard,
        filter_asn_country,
    )
    if not chosen_exit:
        log.error("Error finding Exit node. Aborting path selection.")
        return None

    # Step 3: Select Middle Node
    chosen_middle = select_middle_node(
        nodes,
        chosen_guard,
        chosen_exit,
    )
    if not chosen_middle:
        log.error("Error finding Middle node. Aborting path selection.")
        return None

    return Result(
        guard_node=chosen_guard,
        middle_node=chosen_middle,
        exit_node=chosen_exit,
    )


if __name__ == "__main__":
    try:
        with open(NODES_DATA_PATH, "r") as f:
            all_nodes_data = json.load(f)
        with open(CONFIG_PATH, "r") as f:
            input_config_data = json.load(f)

    except FileNotFoundError as e:
        log.error(f"ERROR: Could not find a required file: {e.filename}")
        exit()

    geo_locator = IPGeolocation(GEOLITE_DB_PATH)
    if not geo_locator.reader:
        exit()

    GUARD_PARAMS = Params(**GUARD_PARAMS)
    EXIT_PARAMS = Params(**EXIT_PARAMS)

    input_config = parse_input_config(input_config_data, geo_locator)
    all_nodes_data = parse_tor_nodes(all_nodes_data, geo_locator)

    selected_path = select_path(
        all_nodes_data,
        input_config,
        GUARD_PARAMS,
        EXIT_PARAMS,
        filter_asn_country=False,
    )

    if selected_path:
        ("\nFinal Selected Path:")
        print(
            f"  Guard: {selected_path.guard_node.fingerprint} | {selected_path.guard_node.country} | {selected_path.guard_node.asn}"
        )
        print(
            f"  Middle: {selected_path.middle_node.fingerprint} | {selected_path.middle_node.country} | {selected_path.middle_node.asn}"
        )
        print(
            f"  Exit: {selected_path.exit_node.fingerprint} | {selected_path.exit_node.country} | {selected_path.exit_node.asn}"
        )
    else:
        log.error("No valid path could be selected.")
        exit(1)
