import json

from models import parse_input_config, parse_tor_nodes
from taps import select_path, _get_country_trust_map
from GeoLocator import IPGeolocation
from models import Params
from collections import Counter


GEOLITE_DB_PATH = "../GeoLite2-Country_20250610/GeoLite2-Country.mmdb"
NODES_DATA_PATH = "../inputs/tor_consensus.json"
CONFIG_PATH = "../inputs/inputOriginal.json"

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


def evaluate_adversary_avoidance(
    all_nodes, input_config, guard_params, exit_params, n_runs
):
    ADVERSARY_THRESHOLD = 0.5

    trust_map = _get_country_trust_map(input_config)
    adversaries = {c for c, t in trust_map.items() if t < ADVERSARY_THRESHOLD}

    guard_compromised_count = 0
    middle_compromised_count = 0
    exit_compromised_count = 0

    for _ in range(n_runs):
        path = select_path(all_nodes, input_config, guard_params, exit_params)
        if not path:
            continue

        if path.guard_node.country in adversaries:
            guard_compromised_count += 1
        if path.middle_node.country in adversaries:
            middle_compromised_count += 1
        if path.exit_node.country in adversaries:
            exit_compromised_count += 1

    print(
        f"################# Adversary Avoidance (Threshold: < {ADVERSARY_THRESHOLD}) - (Runs: {n_runs}) #################"
    )
    print(f"Guard in adversary country: {guard_compromised_count / n_runs:.2%}")
    print(f"Middle in adversary country: {middle_compromised_count / n_runs:.2%}")
    print(f"Exit in adversary country: {exit_compromised_count / n_runs:.2%}")
    print("##########################################################################")


def evaluate_correlation_vulnerability(
    all_nodes, input_config, guard_params, exit_params, n_runs
):
    vulnerable_path_count = 0

    for _ in range(n_runs):
        path = select_path(all_nodes, input_config, guard_params, exit_params)
        if not path:
            continue

        entry_countries = {input_config.client_country, path.guard_node.country}
        exit_countries = {path.exit_node.country, input_config.destination_country}

        if entry_countries.intersection(exit_countries):
            vulnerable_path_count += 1

    print(
        f"################# Path Correlation Vulnerability (Runs: {n_runs}) #################"
    )
    print(f"Paths vulnerable to correlation: {vulnerable_path_count / n_runs:.2%}")
    print("##########################################################################")


def evaluate_path_bandwidth(all_nodes, input_config, guard_params, exit_params, n_runs):
    path_bandwidths = []

    for _ in range(n_runs):
        path = select_path(all_nodes, input_config, guard_params, exit_params)
        if not path:
            continue

        effective_bw = min(
            path.guard_node.bandwidth.measured,
            path.middle_node.bandwidth.measured,
            path.exit_node.bandwidth.measured,
        )
        path_bandwidths.append(effective_bw)

    avg_bw = sum(path_bandwidths) / len(path_bandwidths)

    print(
        f" ################# Path Performance (bandwidth) (Runs: {n_runs}) #################"
    )
    print(f"Average path bandwidth: {avg_bw / 1e6:.2f} MB/s")
    print("##########################################################################")


def evaluate_load_distribution(
    all_nodes, input_config, guard_params, exit_params, n_runs
):
    guard_counts = Counter()
    middle_counts = Counter()
    exit_counts = Counter()

    for _ in range(n_runs):
        path = select_path(all_nodes, input_config, guard_params, exit_params)
        if not path:
            continue

        guard_counts[path.guard_node.fingerprint] += 1
        middle_counts[path.middle_node.fingerprint] += 1
        exit_counts[path.exit_node.fingerprint] += 1

    print(f"################# Load Distribution (Runs: {n_runs}) #################")
    print(f"Guard nodes chosen: {len(guard_counts)} unique relays")
    print(f"Most common guard: {guard_counts.most_common(1)}")
    print(f"Exit nodes chosen: {len(exit_counts)} unique relays")
    print(f"Most common exit: {exit_counts.most_common(1)}")
    print("##########################################################################")


if __name__ == "__main__":
    with open(CONFIG_PATH) as f:
        input_config_data = json.load(f)
    with open(NODES_DATA_PATH) as f:
        all_nodes_data = json.load(f)

    geo_locator = IPGeolocation(GEOLITE_DB_PATH)
    input_config = parse_input_config(input_config_data, geo_locator)
    all_nodes = parse_tor_nodes(all_nodes_data, geo_locator)

    guard_params = Params(**GUARD_PARAMS)
    exit_params = Params(**EXIT_PARAMS)

    evaluate_adversary_avoidance(
        all_nodes, input_config, guard_params, exit_params, n_runs=1000
    )

    evaluate_correlation_vulnerability(
        all_nodes, input_config, guard_params, exit_params, n_runs=1000
    )

    evaluate_path_bandwidth(
        all_nodes, input_config, guard_params, exit_params, n_runs=1000
    )

    evaluate_load_distribution(
        all_nodes, input_config, guard_params, exit_params, n_runs=10000
    )

    print("--------------------------------------------------------------------------")
