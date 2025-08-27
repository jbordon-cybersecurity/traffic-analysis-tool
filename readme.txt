PCAP Network Traffic Analyzer

This project analyses network traffic data from PCAP files.
It extracts and summarises traffic, including email addresses, image URLs, IP pairs, and generates traffic visualisations with statistical thresholds.
It also supports IP geolocation using the GeoLite2 database.

🚀 Features
Parse & Summarize Traffic

Reads PCAP files and organises traffic by protocol.

Summarizes traffic statistics (packet count, mean packet size).

Extracts email addresses, image URLs, and source–destination IP pairs.

Traffic Visualisation

Plots traffic trends with optional thresholds.

Saves plots as PNG files.

IP Geolocation

Uses MaxMind GeoLite2 database to map IPs.

Exports results in .kml format for Google Earth.

📦 Requirements
Python 3.8+

Python Packages
dpkt
matplotlib
scapy
pandas
geoip2


Install with:

pip install -r requirements.txt

▶️ Usage
Step 1: Place Your PCAP File

Ensure your PCAP file is in the project directory.
By default, the tool looks for:

evidence-packet-analysis.pcap


If using a different file, update the PCAP_FILE variable in pcap_analyser.py.

Step 2: Run the Main Script
python pcap_analyser.py

📊 Outputs
Traffic Summary:
By protocol (packet count, mean size, timestamps).

Extracted Information:
Email addresses, image URLs, and source–destination IP pairs (printed in terminal).

Traffic Plots:
PNG file: all_protocols_traffic_plot.png

Geolocation (optional):
destination_IPs_geolocation.kml for Google Earth visualisation.

🌍 GeoLite2 Database
For IP geolocation, you need the GeoLite2-City.mmdb database.
It is not included in this repository (due to size restrictions).

Download it free from MaxMind:
👉 GeoLite2 Free Geolocation Data

Place it in your project root folder.

📂 Project Structure
traffic-analysis-tool/
│── pcap_analyser.py          # Main script
│── pcap_parser.py            # PCAP parsing logic
│── pcap_analysis.py          # Analysis functions
│── find_geolocation_info.py  # IP geolocation + KML
│── requirements.txt
│── README.md
│── .gitignore
└── sample_data/
    └── evidence-packet-analysis.pcap

⚙️ Customisation
Change PCAP File:
Update PCAP_FILE in pcap_analyser.py.

Adjust Visualisation Parameters:
Modify interval_length in prepare_plot_data() (in pcap_analysis.py) to change traffic time intervals.

## ⚠️ License
This repository is provided **for viewing purposes only**.  
No permission is granted to use, copy, modify, or distribute this code without explicit approval from the author.

