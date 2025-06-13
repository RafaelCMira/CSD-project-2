import json
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

# region Configuration
GEOLITE_DB_PATH = "../GeoLite2-Country_20250610/GeoLite2-Country.mmdb"
NODES_DATA_PATH = "../inputs/tor_consensus.json"
CONFIG_PATH = "../inputs/Project2ClientInput.json"

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
# endregion


# Aux functions
def _filter_exit_nodes(all_nodes: List[TorNode]) -> List[TorNode]:
    """Returns a list of nodes that can be used as exits.
    For now simply filter out nodes that reject all traffic
    TODO: Implement more complex filtering based on exit rules.
    """
    valid_exits = []
    for node in all_nodes:
        is_reject_all = any(
            rule.address == "*" and rule.port == "*" and rule.action == "reject"
            for rule in node.exit
        )
        if not is_reject_all:
            valid_exits.append(node)
    return valid_exits


# Main functions


def select_path(
    nodes: list[TorNode], config: InputConfig, alpha_guard: Params, alpha_exit: Params
) -> Result:
    """
    Main function to select a Guard-Middle-Exit path.
    """
    # --- Initialization ---
    potential_guards = nodes
    potential_exits = _filter_exit_nodes(nodes)
    print(f"\nFound {len(potential_exits)} potential exit nodes.")


if __name__ == "__main__":
    try:
        with open(NODES_DATA_PATH, "r") as f:
            all_nodes_data = json.load(f)
        with open(CONFIG_PATH, "r") as f:
            input_config_data = json.load(f)

    except FileNotFoundError as e:
        print(f"ERROR: Could not find a required file: {e.filename}")
        exit()

    geo_locator = IPGeolocation(GEOLITE_DB_PATH)
    if not geo_locator.reader:
        exit()

    GUARD_PARAMS = Params(**GUARD_PARAMS)
    EXIT_PARAMS = Params(**EXIT_PARAMS)

    input_config = parse_input_config(input_config_data, geo_locator)
    all_nodes_data = parse_tor_nodes(all_nodes_data, geo_locator)

    print("Input Config:" + str(input_config))

    selected_path = select_path(all_nodes_data, input_config, GUARD_PARAMS, EXIT_PARAMS)

    if selected_path:
        print("\nFinal Selected Path:")
        print(f"  Guard: {selected_path.guard_node}")
        print(f"  Middle: {selected_path.middle_node}")
        print(f"  Exit: {selected_path.exit_node}")
