"""
This module handles parsing and summarising traffic data
extracted from PCAP files.
"""

from collections import defaultdict
from datetime import datetime
import dpkt


def parse_pcap(file_path):
    """
    Parse a PCAP file and organise traffic data by protocol.
    Args:
        file_path (str): Path to the PCAP file.
    Returns:
        dict: Traffic data organised by protocol.
    """
    print("[INFO] Parsing PCAP file...")
    traffic_data = defaultdict(lambda: {"packets": [], "timestamps": []})

    try:
        with open(file_path, 'rb') as f:
            for timestamp, buf in dpkt.pcap.Reader(f):
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                protocol = ip.data.__class__.__name__
                traffic_data[protocol]["packets"].append(buf)
                traffic_data[protocol]["timestamps"].append(timestamp)
    except FileNotFoundError:
        print(f"[ERROR] File '{file_path}' not found.")
    except dpkt.UnpackError as e:
        print(f"[ERROR] Could not parse PCAP file: {e}")

    return dict(traffic_data)


def summarise_traffic(traffic_data):
    """
    Summarise traffic data by protocol.
    Args:
        traffic_data (dict): Parsed traffic data.
    Returns:
        list: Summary of traffic data.
    """
    print("[INFO] Summarising traffic data...")
    summary = []

    for protocol, data in traffic_data.items():
        packet_lengths = [len(pkt) for pkt in data["packets"]]
        timestamps = data["timestamps"]

        # Compute the first timestamp
        if timestamps:
            first_timestamp = datetime.fromtimestamp(
                min(timestamps)
            ).strftime('%Y-%m-%d %H:%M:%S')
        else:
            first_timestamp = "N/A"

        # Compute the last timestamp
        if timestamps:
            last_timestamp = datetime.fromtimestamp(
                max(timestamps)
            ).strftime('%Y-%m-%d %H:%M:%S')
        else:
            last_timestamp = "N/A"

        # Compute mean length
        mean_length = (
            sum(packet_lengths) / len(packet_lengths)
            if packet_lengths else 0
        )
        # Append summary
        summary.append({
            "Protocol": protocol,
            "Packet Count": len(data["packets"]),
            "Mean Length": mean_length,
            "First Timestamp": first_timestamp,
            "Last Timestamp": last_timestamp,
        })

    # Print the summary in a formatted table
    print("\nTraffic Summary:")
    print(
        f"{'Protocol':<10} {'Packet Count':<15} {'Mean Length':<12} "
        f"{'First Timestamp':<20} {'Last Timestamp':<20}"
    )

    print("-" * 80)
    for item in summary:
        print(
            f"{item['Protocol']:<10} "
            f"{item['Packet Count']:<15} "
            f"{item['Mean Length']:<12.2f} "
            f"{item['First Timestamp']:<20} "
            f"{item['Last Timestamp']:<20}"
        )

    return summary
