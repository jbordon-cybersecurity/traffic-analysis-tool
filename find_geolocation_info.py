"""
Module for geolocating destination IPs and generating KML files.
"""

import geoip2.database
import simplekml


def geolocate_ips(ip_pairs, geoip_database):
    """
    Geolocate destination IPs using the GeoLite2 database.
    Args:
        ip_pairs (dict): Dictionary of IP pairs and traffic statistics.
        geoip_database (str): Path to the GeoLite2 database.
    Returns:
        list: List of geolocation data dictionaries.
    """
    print("[INFO] Geolocating destination IPs...")
    geolocation_data = []

    try:
        with geoip2.database.Reader(geoip_database) as reader:
            for (_, dst_ip), counts in ip_pairs.items():
                try:
                    response = reader.city(dst_ip)
                    geolocation_data.append({
                        "ip": dst_ip,
                        "packet_count": counts["A->B"],
                        "city": response.city.name or "Unknown",
                        "country": response.country.name or "Unknown",
                        "latitude": response.location.latitude,
                        "longitude": response.location.longitude,
                    })
                except geoip2.errors.AddressNotFoundError:
                    geolocation_data.append({
                        "ip": dst_ip,
                        "packet_count": counts["A->B"],
                        "city": "Unknown",
                        "country": "Unknown",
                        "latitude": None,
                        "longitude": None,
                    })
    except FileNotFoundError as e:
        print(f"[ERROR] GeoLite2 database file not found: {e}")
    except geoip2.errors.GeoIP2Error as e:
        print(f"[ERROR] GeoIP2-specific error: {e}")
    except PermissionError as e:
        # Handle cases where file cannot be opened due to permissions.
        print(
            f"[ERROR] Permission denied when accessing the "
            f"database file: {e}"
        )

    except ValueError as e:
        # Handle value errors, such as malformed IPs or unexpected data.
        print(f"[ERROR] Invalid data encountered: {e}")
    except OSError as e:
        # Handle OS errors, such as issues reading the file.
        print(f"[ERROR] OS error while accessing the database: {e}")

    return geolocation_data


def create_kml(geolocation_data, output_file):
    """
    Create a KML file with geolocation data.
    Args:
        geolocation_data (list): List of geolocation data dictionaries.
        output_file (str): Path to save the KML file.
    """
    print("[INFO] Creating KML file...")
    kml = simplekml.Kml()

    for data in geolocation_data:
        if data["latitude"] is not None and data["longitude"] is not None:
            kml.newpoint(
                name=data["ip"],
                coords=[(data["longitude"], data["latitude"])],
                description=(
                    f"Packet Count: {data['packet_count']}\n"
                    f"City: {data['city']}\n"
                    f"Country: {data['country']}"
                ),
            )

    try:
        kml.save(output_file)
        print(f"[INFO] KML file saved to {output_file}")
    except FileNotFoundError as e:
        print(f"[ERROR] Output directory not found: {e}")
    except PermissionError as e:
        print(f"[ERROR] Permission denied when saving KML file: {e}")
    except OSError as e:
        print(f"[ERROR] OS-related error while saving KML file: {e}")
