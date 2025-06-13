import geoip2.database


GEOLITE_DB_PATH = "../GeoLite2-Country_20250610/GeoLite2-Country.mmdb"


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
