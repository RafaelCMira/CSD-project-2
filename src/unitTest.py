import pytest
import json


@pytest.mark.parametrize(
    "config_path,nodes_path",
    [
        ("../inputs/Project2ClientInput.json", "../inputs/tor_consensus.json"),
        # TODO Add more tests
    ]
    * 10,
)
def test_guard_node_not_adversary(config_path, nodes_path):
    from models import parse_input_config, parse_tor_nodes
    from taps import select_path, _get_country_trust_map
    from GeoLocator import IPGeolocation
    from models import Params

    with open(config_path) as f:
        input_config_data = json.load(f)
    with open(nodes_path) as f:
        all_nodes_data = json.load(f)

    geo_locator = IPGeolocation("../GeoLite2-Country_20250610/GeoLite2-Country.mmdb")
    input_config = parse_input_config(input_config_data, geo_locator)
    all_nodes = parse_tor_nodes(all_nodes_data, geo_locator)

    guard_params = Params(
        safe_upper=0.95,
        safe_lower=2.0,
        accept_upper=0.5,
        accept_lower=5.0,
        bandwidth_frac=0.2,
    )
    exit_params = Params(
        safe_upper=0.95,
        safe_lower=2.0,
        accept_upper=0.1,
        accept_lower=10.0,
        bandwidth_frac=0.2,
    )

    trust_map = _get_country_trust_map(input_config)
    adversaries = {country for country, trust in trust_map.items() if trust < 0.1}

    result = select_path(all_nodes, input_config, guard_params, exit_params)
    guard_country = result.guard_node.country
    assert (
        guard_country not in adversaries
    ), f"Guard node is in adversary country: {guard_country}"
