"""
This module analyses network traffic data from PCAP files and performs
the following:
- Extracts email addresses and image URLs from TCP payloads.
- Extracts and analyses source and destination IP pairs.
- Prepares data for visualisation, including calculating statistics.
- Plots traffic data with optional thresholds and saves and displays the plot.
"""


import re
import socket
from collections import defaultdict
from datetime import datetime, timedelta
import dpkt
import matplotlib.pyplot as plt

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
IMAGE_URL_REGEX = r"(https?://[^\s]+(\.jpg|\.jpeg|\.png|\.gif))"


def extract_emails_and_images(tcp_payloads):
    """"
    Extract emails, image URLs, and headers from network traffic data.
    Args:
        tcp_payloads (list): List of TCP payloads as byte strings.
    Returns:
        tuple: Extracted emails, headers, and processed image URLs.
    """
    print("[INFO] Extracting emails, headers, and image URLs...")
    emails = set()
    headers = {"To": set(), "From": set()}
    image_urls = set()  # Stores unique image URLs.

    for payload in tcp_payloads:
        try:
            # Decodes TCP payloads/ignores decoding errors.
            decoded = payload.decode(errors='ignore')

            # Extract emails using regex and add to the set.
            emails.update(re.findall(EMAIL_REGEX, decoded))

            # Extract image URLs and clears any extra characters.
            raw_image_urls = re.findall(IMAGE_URL_REGEX, decoded)

            # Combine parts of each regex match to create and clean full URL.
            for match in raw_image_urls:
                full_url = "".join(match[0])
                image_urls.add(full_url.strip(' "\''))

            # Extract 'To' and 'From' headers using regex patterns.
            to_matches = re.findall(
                r"(?i)^To:\s*<([^>]+)>", decoded, re.MULTILINE
            )
            from_matches = re.findall(
                r"(?i)^From:\s*(.*)<([^>]+)>", decoded, re.MULTILINE
            )

            headers["To"].update(to_matches)
            headers["From"].update(
                [match[1] for match in from_matches]
            )
        except re.error as e:
            print(f"[WARNING] Error processing payload: {e}")
        except TypeError as e:
            print(f"[WARNING] Unexpected type error: {e}")

    # Prepare processed image URLs with their filenames for output.
    processed_image_urls = [
        (url, url.split('/')[-1]) for url in sorted(image_urls)
    ]

    return (
        sorted(headers["To"]),
        sorted(headers["From"]),
        sorted(emails),
        processed_image_urls,
    )


def extract_ip_pairs(pcap_file):
    """
    Extract source and destination IP pairs from a PCAP file.
    Args:
        pcap_file (str): Path to the PCAP file.
    Returns:
        dict: Dictionary with IP pairs and traffic statistics.
    """
    print("[INFO] Extracting IP pairs...")
    ip_pairs = defaultdict(lambda: {"A->B": 0, "B->A": 0})
    try:
        with open(pcap_file, 'rb') as f:
            for _, buf in dpkt.pcap.Reader(f):
                eth = dpkt.ethernet.Ethernet(buf)  # Parse Ethernet frame.
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                # Convert source IP to string.
                src_ip = socket.inet_ntoa(ip.src)

                # Convert destination IP to string.
                dst_ip = socket.inet_ntoa(ip.dst)

                # Used a sorted tuple to store IP's pairs consistently.
                pair_key = tuple(sorted((src_ip, dst_ip)))

                # Increment traffic counters based on source-destination order.
                if src_ip < dst_ip:
                    ip_pairs[pair_key]["A->B"] += 1
                else:
                    ip_pairs[pair_key]["B->A"] += 1
    except OSError as e:
        print(f"[ERROR] Could not extract IP pairs: {e}")

    return dict(ip_pairs)  # Convert defaultdict to regular dict.


def prepare_plot_data(traffic_data, interval_length=60):
    """
    Prepare data for traffic visualisation.
    Args:
        traffic_data (dict): Parsed traffic data.
        interval_length (int): Time interval in seconds.
    Returns:
        dict: Data prepared for plotting.
    """
    print("[INFO] Preparing data for traffic visualisation...")
    protocol_data = {}  # To store plotting data for each protocol.

    for protocol, data in traffic_data.items():
        # Convert timestamps to datetime objects for easier manipulation.
        timestamps = [datetime.fromtimestamp(ts) for ts in data["timestamps"]]

        if not timestamps:
            # Handle case where no timestamps are present.
            protocol_data[protocol] = ([], [], 0)
            continue

        # Determine the time range for the intervals.
        start, end = min(timestamps), max(timestamps)

        # Generate intervals based on the interval length.

        intervals = (
            [
                start + timedelta(seconds=i * interval_length)
                for i in range((end - start).seconds // interval_length + 1)
            ]
            if timestamps
            else []
        )

        # Count the number of packets in each interval.
        packet_counts = [
            sum(
                1 for ts in timestamps
                if intervals[i] <= ts < intervals[i + 1]
            )
            for i in range(len(intervals) - 1)
        ]

        if packet_counts:
            # Calculate mean, variance, and std. dev of packet counts.
            mean = sum(packet_counts) / len(packet_counts)
            deviations = [(x - mean) ** 2 for x in packet_counts]
            variance = sum(deviations) / len(packet_counts)
            std_dev = variance ** 0.5
            # Define threshold as mean + 2*std_dev.
            threshold = mean + 2 * std_dev
        else:
            threshold = 0  # If no packets, set threshold to 0

        # Format intervals as strings for plotting.
        protocol_data[protocol] = (
            [dt.strftime('%Y-%m-%d %H:%M:%S') for dt in intervals[:-1]],
            packet_counts,
            threshold,
        )

    return protocol_data


def plot_traffic(timestamps, packet_counts, threshold=None, output_file=None):
    """
    Plots traffic data with optional threshold and file output.
    Args:
        timestamps (list): Timestamps for traffic data.
        packet_counts (list): Packet counts for each timestamp.
        threshold (float, optional): Threshold for traffic. Defaults to None.
        output_file (str, optional): Path to save the plot. Defaults to None.
    """
    print("[INFO] Plotting traffic data...")
    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, packet_counts, label="Packet Counts", marker="o")
    if threshold is not None:
        # Plot a horizontal line for the threshold.
        plt.axhline(
            y=threshold,
            color="red",
            linestyle="--",
            label=f"Threshold ({threshold})"
        )

    # Set plot titles, labels, and legends.
    plt.title("Packet Traffic Over Time")
    plt.xlabel("Time")
    plt.ylabel("Number of Packets")
    plt.legend()
    plt.xticks(rotation=45)  # Rotate x-axis labels for better readability.
    plt.grid(alpha=0.5)
    plt.tight_layout()
    if output_file:
        plt.savefig(output_file)  # Save the plot to the specified file.
        print(f"[INFO] Plot saved as '{output_file}'")
    plt.show()  # Display the plot.
