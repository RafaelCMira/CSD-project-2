from dataclasses import dataclass
from typing import List


@dataclass
class Params:
    """
    Represents the parameters for path selection.
    Attributes:
        safe_upper (float): Upper threshold for safe bandwidth.
        safe_lower (float): Lower threshold for safe bandwidth.
        accept_upper (float): Upper threshold for acceptable bandwidth.
        accept_lower (float): Lower threshold for acceptable bandwidth.
        bandwidth_frac (float): Fraction of bandwidth to consider.
    """

    safe_upper: float
    safe_lower: float
    accept_upper: float
    accept_lower: float
    bandwidth_frac: float


@dataclass
class Alliance:
    """
    Represents an alliance of countries with a trust value.

    Attributes:
        countries (List[str]): List of country codes in the alliance.
        trust (float): Trust value for the alliance.
    """

    countries: List[str]
    trust: float


@dataclass
class InputConfig:
    """
    Represents the input configuration for the client.

    Attributes:
        alliances (List[Alliance]): List of alliances.
        client (str): The client IP address.
        destination (str): The destination IP address.
        client_country (str): The country code of the client IP.
        destination_country (str): The country code of the destination IP.
    """

    alliances: List[Alliance]
    client: str
    destination: str
    client_country: str = ""
    destination_country: str = ""


@dataclass
class Bandwidth:
    """
    Represents bandwidth information for a Tor node.

    Attributes:
        measured (int): The measured bandwidth in bytes per second.
        average (int): The average bandwidth in bytes per second.
        burst (int): The burst bandwidth in bytes per second.
    """

    measured: int
    average: int
    burst: int


@dataclass
class ExitRule:
    """
    Represents an exit policy rule for a Tor node.

    Attributes:
        action (str): The action of the rule, either 'accept' or 'reject'.
        address (str): The IP address or range the rule applies to.
        port (str): The port or port range the rule applies to.
    """

    action: str
    address: str
    port: str


@dataclass
class TorNode:
    fingerprint: str
    nickname: str
    ip: str
    port: int
    bandwidth: Bandwidth
    family: List[str]
    asn: str
    exit: List[ExitRule]
    country: str = ""


@dataclass
class Result:
    """
    Represents the result of the path selection.
    Attributes:
        guard_node (str): The fingerprint of the guard node.
        middle_node (str): The fingerprint of the middle node.
        exit_node (str): The fingerprint of the exit node.
    """

    guard_node: TorNode
    middle_node: TorNode
    exit_node: TorNode


def parse_input_config(config_data, geo_locator):
    alliances = [Alliance(**a) for a in config_data["Alliances"]]
    client_ip = config_data["Client"]
    dest_ip = config_data["Destination"]
    client_country = geo_locator.get_country(client_ip)
    dest_country = geo_locator.get_country(dest_ip)
    return InputConfig(
        alliances=alliances,
        client=client_ip,
        destination=dest_ip,
        client_country=client_country,
        destination_country=dest_country,
    )


def parse_tor_nodes(nodes_data, geo_locator) -> List[TorNode]:
    return [
        TorNode(
            fingerprint=node["fingerprint"],
            nickname=node["nickname"],
            ip=node["ip"],
            country=geo_locator.get_country(node["ip"]),
            port=node["port"],
            bandwidth=Bandwidth(**node["bandwidth"]),
            family=node["family"],
            asn=node["asn"],
            exit=parse_exit_rules(node["exit"]),
        )
        for node in nodes_data
    ]


def parse_exit_rules(exit_str: str) -> List[ExitRule]:
    rules = []
    for rule in exit_str.split(","):
        rule = rule.strip()
        if not rule:
            continue
        parts = rule.split()
        if len(parts) != 2:
            continue
        action, rest = parts
        address, port = rest.split(":")
        rules.append(ExitRule(action=action, address=address, port=port))
    return rules
