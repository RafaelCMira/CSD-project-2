import pytest
import json
from collections import Counter

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

PARAM_LIST = [
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


@pytest.mark.skip(reason="Temporarily disabled for debugging")
@pytest.mark.parametrize(
    "config_path,nodes_path,adversary_threshold,empty_space",
    PARAM_LIST * 10,
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


@pytest.mark.skip(reason="Temporarily disabled for debugging")
@pytest.mark.parametrize(
    "config_path,nodes_path,adversary_threshold,empty_space",
    PARAM_LIST * 10,
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


@pytest.mark.skip(reason="Temporarily disabled for debugging")
@pytest.mark.parametrize(
    "config_path,nodes_path,adversary_threshold,empty_space",
    PARAM_LIST * 10,
)
def test_guard_and_exit_asn(config_path, nodes_path, adversary_threshold, empty_space):
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

    result = select_path(all_nodes, input_config, guard_params, exit_params)
    guard_asn = result.guard_node.asn
    exit_asn = result.exit_node.asn

    assert guard_asn != exit_asn, "Guard and exit nodes should not have the same ASN"


@pytest.mark.skip(reason="Temporarily disabled for debugging")
@pytest.mark.parametrize(
    "config_path,nodes_path,adversary_threshold,empty_space",
    PARAM_LIST * 10,
)
def test_guard_and_exit_country(
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

    result = select_path(all_nodes, input_config, guard_params, exit_params)
    guard_country = result.guard_node.country
    exit_country = result.exit_node.country

    assert (
        guard_country != exit_country
    ), "Guard and exit nodes should not have the same ASN"


@pytest.mark.skip(reason="Temporarily disabled for debugging")
@pytest.mark.parametrize(
    "config_path,nodes_path,adversary_threshold,empty_space",
    PARAM_LIST * 5,
)
def test_all(config_path, nodes_path, adversary_threshold, empty_space):
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
    guard_node = result.guard_node
    exit_node = result.exit_node

    fail_conditions = []

    if guard_node.asn == exit_node.asn:
        fail_conditions.append(f"ASN - {guard_node.asn}")
    if guard_node.country == exit_node.country:
        fail_conditions.append(f"COUNTRY - {guard_node.country}")
    if guard_node.fingerprint == exit_node.fingerprint:
        fail_conditions.append(f"FINGERPRINT - {guard_node.fingerprint}")
    if guard_node.country in adversaries:
        fail_conditions.append(f"GUARD IN ADVERSARY - {guard_node.country}")
    if exit_node.country in adversaries:
        fail_conditions.append(f"EXIT IN ADVERSARY - {exit_node.country}")
    if fail_conditions:
        fail_message = ", ".join(fail_conditions)
        assert False, f"FAILURE: {fail_message}"


N_RUNS = 500
MAX_FAILURE_RATE = 0.1
PARAM_LIST_2 = [
    ("../inputs/inputOriginal.json", "../inputs/tor_consensus.json", 0.5, ""),
    ############################################################################
    ("../inputs/input1.json", "../inputs/tor_consensus.json", 0.5, ""),
    ############################################################################
    ("../inputs/input2.json", "../inputs/tor_consensus.json", 0.5, ""),
    ############################################################################
    ("../inputs/input3.json", "../inputs/tor_consensus.json", 0.5, ""),
    ############################################################################
    ("../inputs/input4.json", "../inputs/tor_consensus.json", 0.5, ""),
    ############################################################################
    ("../inputs/input5.json", "../inputs/tor_consensus.json", 0.5, ""),
]


@pytest.mark.parametrize(
    "config_path,nodes_path,adversary_threshold,empty_space",
    PARAM_LIST_2,
)
def test_path_selection_failure_rate(
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

    fail_counter = Counter()
    failed_runs = 0

    asn_failures = 0
    country_failures = 0

    for _ in range(N_RUNS):
        result = select_path(all_nodes, input_config, guard_params, exit_params)
        guard_node = result.guard_node
        exit_node = result.exit_node

        fail_conditions = []

        if guard_node.fingerprint == exit_node.fingerprint:
            fail_conditions.append("FINGERPRINT")  # This is just for a sanity check
        if guard_node.country in adversaries:
            fail_conditions.append("GUARD")
        if exit_node.country in adversaries:
            fail_conditions.append("EXIT")

        if fail_conditions:
            failed_runs += 1
            for cond in fail_conditions:
                fail_counter[cond] += 1

        if guard_node.asn == exit_node.asn:
            asn_failures += 1
        if guard_node.country == exit_node.country:
            country_failures += 1

    failure_rate = failed_runs / N_RUNS
    asn_failure_rate = asn_failures / N_RUNS
    country_failure_rate = country_failures / N_RUNS

    print(f"\nResults for {config_path} (adversary_threshold={adversary_threshold}):")
    for cause, count in fail_counter.items():
        print(f"  {cause}: {count} times ({count/N_RUNS:.2%})")
    print(f"  TOTAL failed runs: {failed_runs} out of {N_RUNS} ({failure_rate:.2%})")
    print(f"  ASN failures: {asn_failures} out of {N_RUNS} ({asn_failure_rate:.2%})")
    print(
        f"  COUNTRY failures: {country_failures} out of {N_RUNS} ({country_failure_rate:.2%})"
    )

    assert (
        failure_rate < MAX_FAILURE_RATE
    ), f"Failure rate {failure_rate:.2%} exceeds allowed {MAX_FAILURE_RATE:.2%}"

    assert (
        asn_failure_rate < MAX_FAILURE_RATE
    ), f"ASN failure rate {asn_failure_rate:.2%} exceeds allowed {MAX_FAILURE_RATE:.2%}"

    assert (
        country_failure_rate < MAX_FAILURE_RATE
    ), f"Country failure rate {country_failure_rate:.2%} exceeds allowed {MAX_FAILURE_RATE:.2%}"
