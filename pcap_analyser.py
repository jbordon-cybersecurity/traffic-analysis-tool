"""
Integrated script for analysing PCAP files, extracting network data,
and generating outputs including email, image data, traffic plots,
and geolocation information in KML format.
"""

import os
from pcap_parser import parse_pcap, summarise_traffic
from pcap_analysis import (
    extract_emails_and_images,
    extract_ip_pairs,
    prepare_plot_data,
    plot_traffic,
)
from find_geolocation_info import geolocate_ips, create_kml

# File Path Settings
GEOIP_DATABASE = (
    r"C:\Users\40216449\OneDrive - Edinburgh Napier University"
    r"\Desktop\New_PROJECT\GeoLite2-City.mmdb"
)
PCAP_FILE = "evidence-packet-analysis.pcap"
OUTPUT_KML_FILE = "destination_IPs_geolocation.kml"


def parse_and_summarise(pcap_file: str) -> dict:
    """Parse the PCAP file and summarise traffic."""
    traffic_data = parse_pcap(pcap_file)
    summarise_traffic(traffic_data)
    return traffic_data


def extract_and_print_emails_images(traffic_data: dict):
    """Extract and print emails and image URLs."""
    tcp_payloads = list(traffic_data.get("TCP", {}).get("packets", []))
    # Extract email addresses and image URLs from the TCP payloads.
    to_emails, from_emails, _, image_urls = extract_emails_and_images(
        tcp_payloads
    )

    print("\nExtracted To and From Emails:")
    print("To Addresses:", ", ".join(to_emails) if to_emails else "None")
    print("From Addresses:", ", ".join(from_emails) if from_emails else "None")

    print("\nExtracted Image URLs and Filenames:")
    if image_urls:
        for url, filename in image_urls:
            print(
                f"{filename}: {url}" if filename
                else f"[INVALID FILENAME]: {url}"
            )

    else:
        print("No image URLs found.")


def print_ip_pairs(ip_pairs: dict):
    """Print source and destination IP pairs."""
    print(
        "\nSource IP            Destination IP       "
        "A->B       B->A       Total Traffic"
    )

    print("-" * 75)

    # Iterate over sorted IP pairs, sorted by total traffic
    for (src, dst), counts in sorted(
        ip_pairs.items(), key=lambda x: sum(x[1].values()), reverse=True
    ):
        print(
            f"{src:<20} {dst:<20} "
            f"{counts['A->B']:<10} {counts['B->A']:<10} "
            f"{sum(counts.values()):<15}"
        )


def generate_and_plot_traffic(traffic_data: dict):
    """Generate and plot combined traffic data."""
    interval_length = 10
    # Prepare traffic data for plotting by interval and protocol.
    protocol_data = prepare_plot_data(traffic_data, interval_length)

    # Initialise lists to store combined timestamps and packet counts.
    all_timestamps, all_packet_counts = [], []

    # Combine traffic data across all protocols.
    for timestamps, packet_counts, _ in protocol_data.values():
        all_timestamps.extend(timestamps)
        all_packet_counts.extend(packet_counts)

    if all_timestamps and all_packet_counts:
        # Sort combined timestamps and packet counts.
        sorted_data = sorted(
            zip(all_timestamps, all_packet_counts),
            key=lambda x: x[0]
        )

        combined_timestamps, combined_packet_counts = zip(*sorted_data)

        # Calculate traffic statistics: mean, variance, and standard deviation.
        mean = sum(combined_packet_counts) / len(combined_packet_counts)
        variance = sum(
            (x - mean) ** 2 for x in combined_packet_counts
        ) / len(combined_packet_counts)

        std_dev = variance**0.5
        combined_threshold = mean + 2 * std_dev

        # Generates traffic plot with calculated threshold.
        combined_output_file = "all_protocols_traffic_plot.png"
        plot_traffic(
            combined_timestamps,
            combined_packet_counts,
            threshold=combined_threshold,
            output_file=combined_output_file,
        )
        print(
            f"[INFO] Combined traffic plot saved as "
            f"'{combined_output_file}'"
        )

    else:
        print("[INFO] No traffic data available to plot.")


def main():
    """
    Main function to analyse network traffic data from PCAP files,
    geolocate destination IPs, and generate a KML file.
    """
    # Check if the PCAP file exists.
    if not os.path.exists(PCAP_FILE):
        print(f"[ERROR] PCAP file '{PCAP_FILE}' not found.")
        return

    # Parse and summarise traffic data.
    traffic_data = parse_and_summarise(PCAP_FILE)

    # Extract and print emails and image URLs.
    extract_and_print_emails_images(traffic_data)

    # Extract and print IP pairs.
    ip_pairs = extract_ip_pairs(PCAP_FILE)
    print_ip_pairs(ip_pairs)

    # Geolocate destination IPs and create KML file.
    geolocation_data = geolocate_ips(ip_pairs, GEOIP_DATABASE)
    create_kml(geolocation_data, OUTPUT_KML_FILE)

    # Generate and plot traffic data.
    generate_and_plot_traffic(traffic_data)


if __name__ == "__main__":
    main()
