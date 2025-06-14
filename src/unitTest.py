import pytest
import json

GEOLITE_DB_PATH = "../GeoLite2-Country_20250610/GeoLite2-Country.mmdb"
NODES_DATA_PATH = "../inputs/tor_consensus.json"
CONFIG_PATH = "../inputs/inputOriginal.json"

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


@pytest.mark.skip(reason="Temporarily disabled for debugging")
@pytest.mark.parametrize(
    "config_path,nodes_path,adversary_threshold,empty_space",
    [
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.9, ""),
    ]
    * 10,
)
def test_guard_node_not_adversary(
    config_path, nodes_path, adversary_threshold, empty_space
):
    from models import parse_input_config, parse_tor_nodes
    from taps import select_path, _get_country_trust_map
    from GeoLocator import IPGeolocation
    from models import Params

    with open(config_path) as f:
        input_config_data = json.load(f)
    with open(nodes_path) as f:
        all_nodes_data = json.load(f)

    geo_locator = IPGeolocation(GEOLITE_DB_PATH)
    input_config = parse_input_config(input_config_data, geo_locator)
    all_nodes = parse_tor_nodes(all_nodes_data, geo_locator)

    guard_params = Params(**GUARD_PARAMS)
    exit_params = Params(**EXIT_PARAMS)

    trust_map = _get_country_trust_map(input_config)
    adversaries = {
        country for country, trust in trust_map.items() if trust < adversary_threshold
    }

    result = select_path(all_nodes, input_config, guard_params, exit_params)
    guard_country = result.guard_node.country
    assert (
        guard_country not in adversaries
    ), f"Guard node is in adversary country: {guard_country}"


@pytest.mark.parametrize(
    "config_path,nodes_path,adversary_threshold,empty_space",
    [
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.9, ""),
        ############################################################################
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.1, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.2, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.3, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.4, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.5, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.6, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.7, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.8, ""),
        ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.9, ""),
    ]
    * 10,
)
def test_exit_node_not_adversary(
    config_path, nodes_path, adversary_threshold, empty_space
):
    from models import parse_input_config, parse_tor_nodes
    from taps import select_path, _get_country_trust_map
    from GeoLocator import IPGeolocation
    from models import Params

    with open(config_path) as f:
        input_config_data = json.load(f)
    with open(nodes_path) as f:
        all_nodes_data = json.load(f)

    geo_locator = IPGeolocation(GEOLITE_DB_PATH)
    input_config = parse_input_config(input_config_data, geo_locator)
    all_nodes = parse_tor_nodes(all_nodes_data, geo_locator)

    guard_params = Params(**GUARD_PARAMS)
    exit_params = Params(**EXIT_PARAMS)

    trust_map = _get_country_trust_map(input_config)
    adversaries = {
        country for country, trust in trust_map.items() if trust < adversary_threshold
    }

    result = select_path(all_nodes, input_config, guard_params, exit_params)
    exit_country = result.exit_node.country
    assert (
        exit_country not in adversaries
    ), f"Exit node is in adversary country: {exit_country}"
