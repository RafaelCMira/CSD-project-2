from dataclasses import dataclass
from typing import List


@dataclass
class Alliance:
    countries: List[str]
    trust: float


@dataclass
class InputConfig:
    alliances: List[Alliance]
    client: str
    destination: str
    clientCountry: str = ""
    destinationCountry: str = ""


@dataclass
class Bandwidth:
    measured: int
    average: int
    burst: int


@dataclass
class ExitRule:
    action: str  # "accept" or "reject"
    address: str  # "*", "127.0.0.0/8"
    port: str  # "*", "20-21"


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
        clientCountry=client_country,
        destinationCountry=dest_country,
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
