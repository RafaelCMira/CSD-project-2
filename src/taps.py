import json
import random
import geoip2.database
from pprint import pprint
from dataclasses import dataclass
from typing import List
from models import (
    parse_input_config,
    parse_tor_nodes,
)

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


# region GeoLocator
class IPGeolocation:
    """A wrapper for the GeoIP2 database to handle lookups"""

    def __init__(self, db_path):
        try:
            self.reader = geoip2.database.Reader(db_path)
        except FileNotFoundError:
            print(f"ERROR: GeoLite2 database not found at '{db_path}'.")
            print(
                "Please download it from MaxMind and place it in the correct directory."
            )
            self.reader = None

    def get_country(self, ip_address):
        """Returns the ISO 3166-1 alpha-2 country code for an IP."""
        if not self.reader:
            return "XX"  # Return a dummy code if DB is missing
        try:
            # Localhost or private IPs will raise an error
            if ip_address.startswith(("127.", "192.", "10.")):
                return "LN"  # Local Network
            response = self.reader.country(ip_address)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            # This can happen for reserved or invalid IPs
            return "XX"  # Represents an unknown location
        except Exception as e:
            print(f"Could not look up IP {ip_address}: {e}")
            return "XX"


# endregion


# Aux functions


# Main functions

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

    input_config = parse_input_config(input_config_data, geo_locator)
    all_nodes_data = parse_tor_nodes(all_nodes_data, geo_locator)

    print("Input Config:" + str(input_config))
