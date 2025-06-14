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

# region Configuration
log.basicConfig(
    level=log.INFO,
    format="%(levelname)s - %(message)s",
)

GEOLITE_DB_PATH = "../GeoLite2-Country_20250610/GeoLite2-Country.mmdb"
NODES_DATA_PATH = "../inputs/tor_consensus.json"
CONFIG_PATH = "../inputs/input1.json"

GUARD_PARAMS = {
    "safe_upper": 0.95,  # Security score must be >= 95% of the BEST score
    "safe_lower": 2.0,  # Compromise score can be at most 2x the BEST compromise
    "accept_upper": 0.5,  # Security score must be >= 50% of the BEST score
    "accept_lower": 5.0,  # Compromise score can be at most 5x the BEST compromise
    "bandwidth_frac": 0.2,  # The final pool must represent at least 20% of network bandwidth
}
EXIT_PARAMS = {
    "safe_upper": 0.95,  # Security score must be >= 95% of the BEST score
    "safe_lower": 2.0,  # Compromise score can be at most 2x the BEST compromise
    "accept_upper": 0.1,  # Security score must be >= 10% of the BEST score
    "accept_lower": 10.0,  # Compromise score can be at most 10x the BEST compromise
    "bandwidth_frac": 0.2,  # The final pool must represent at least 20% of network bandwidth
}

# NOTE: When testing, when i set this value to:
# 0.5, for input1, i was getting consistently the same country as guard node. (DE)
# 1, for input1, i was gettint different countries as guard node. (Sometimes still got the same country but more often different)

# Another important note, with the test plan i have, i difined a threshold of 0.1 to 0.9 to the adversary.
# When this value was set to 0.5, some tests that checked if the guard node was not an adversary, were failing. (Of course only those where i considered the threshold as 0.8 or above)
# This threshold mean that to be considered an adversary, the security score of the guard node must be below 0.8.

# NOTE When this value was set to 1, all tests passed. From 0.1 to 0.9, all tests passed.

# NOTE when i use 0.1, almost the same failed as with 0.5.

# NOTE Interesting, when using 0.9 they all passed, but when using 0.8, some failed.


## AFTER ADDING MORE INPUT DIVERSE INPUT FILES TO TEST
# NOTE More Interesting, when using 1 as the value, that's where i got less failures. In a total of 540 runs (10 runs for each of the 54 tests), i got 6 failures in total.
# All the failures were related to FAILED unitTest.py::test_guard_node_not_adversary[../inputs/input2.json-../inputs/tor_consensus.json-0.8-7] (Where 0.8 or 0.9 was used)
# This pretty much says that for the guard node, the best trust to have is 1, since this will guarantee that the guard node is not an adversary
# if we consider an adversary to be a node with a security score below 0.8. For 0.8 or 0.9, the best value remains 1 but sometimes it will choose a adversarie.
# IN this particular case, it only failed for the specified input files, but for the other inputs, it passed. (Even when considering adversarie a node with trust below 90% it passed)

DEFAULT_TRUST_SCORE_GUARD = (
    1  # Default trust score for guard nodes countries not in any alliance
)


# Here with a value of 1, it seems that the failure happens at a wider range of adversaries trust scores (from 0.2 to 0.9)
# When using 0.5, the failures happen much more in the 0.9 adversary trust score (Which leads me to believe that the adversary lower values here are better)
# With value = 0.5, in 540, 20 failed, 11 on 0.9 (across many inputs) and the other failed more randomly. (3 on 0.6, 1 in 0.2, 0.3, 0.4, 0.5, 0.7, 0.8)

# WIth 0.1, got the same failure rate, the results distributed (more on the higher trust scores, but still some on the lower ones)

# Now with 1 i got better results then with 0.5 so this probably means the algorithm needs some tuning
# NOTE in failures, more than half of them are in 0.8 and 0.9 adversary trust scores, so this is actually good since for a very small % of the runs ti fails for thos where it shouln't
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
    potential_exits: List[TorNode],
    config: InputConfig,
    alpha_exit: Params,
    trust_map: Dict[str, float],
    chosen_guard: TorNode,
) -> TorNode | None:
    log.info("Selecting Exit Node...")
    total_exit_bandwidth = sum(n.bandwidth.measured for n in potential_exits)

    exit_scores = {
        node.fingerprint: exit_security(
            config.client_country,
            config.destination_country,
            chosen_guard.country,
            node.country,
            trust_map,
        )
        for node in potential_exits
    }

    secure_exits = _find_secure_relays(
        potential_exits, exit_scores, alpha_exit, total_exit_bandwidth
    )
    log.info(f"Filtered down to {len(secure_exits)} secure exits.")

    return _bandwidth_weighted_choice(secure_exits)


# endregion


def select_path(
    nodes: list[TorNode], config: InputConfig, alpha_guard: Params, alpha_exit: Params
) -> Result:
    """
    Main function to select a Guard-Middle-Exit path.
    """

    potential_guards = nodes
    potential_exits = _filter_exit_nodes(nodes, config.destination)

    trust_map = _get_country_trust_map(config)

    # Step 1: Select Guard Node
    chosen_guard = select_guard_node(
        potential_guards,
        config,
        alpha_guard,
        trust_map,
    )

    # Step 2: Select Exit
    chosen_exit = select_exit_node(
        potential_exits,
        config,
        alpha_exit,
        trust_map,
        chosen_guard,
    )

    return Result(
        guard_node=chosen_guard,
        middle_node=None,  # TODO implement
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

    log.debug("Input Config:" + str(input_config))

    selected_path = select_path(all_nodes_data, input_config, GUARD_PARAMS, EXIT_PARAMS)

    if selected_path:
        ("\nFinal Selected Path:")
        print(
            f"  Guard: {selected_path.guard_node.fingerprint} | {selected_path.guard_node.country} | {selected_path.guard_node.nickname}"
        )
        print(f"  Middle: {selected_path.middle_node}")
        print(
            f"  Exit: {selected_path.exit_node.fingerprint} | {selected_path.exit_node.country} | {selected_path.exit_node.nickname}"
        )
