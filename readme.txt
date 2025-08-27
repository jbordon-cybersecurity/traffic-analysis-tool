- PCAP Network Traffic Analyser
This project analyses network traffic data from PCAP files. 
It extracts and summarises traffic, including email addresses, image URLs, IP pairs, and displays traffic data with statistical thresholds.


Parse and Summarise Traffic Data:
Reads PCAP files and organises traffic data by protocol.
Summarises traffic statistics such as packet count and mean packet size.
Extracts email addresses, image URLs, and source-destination IP pairs.
Displays Traffic Data:
Plots traffic trends with optional thresholds and saves the plots.

Requiered:

Python 3.8 or higher

Required Python packages:

dpkt
matplotlib

Install the required packages using pip:

pip install dpkt matplotlib

How to run:

Step 1: Place Your PCAP File
Ensure your PCAP file is in the same directory as the scripts. By default, the project looks for a file named evidence-packet-analysis.pcap. 
If you want to use a different file, update the pcap_file variable in the main() function of pcap_analyser.py.

Step 2: Run the Main Script
Execute the pcap_analyser.py script to analyze your PCAP file and extract traffic data.

Outputs Traffic Summary:

Summarises traffic data by protocol, including packet count, mean size, and timestamps.

Extracted Information:

- Displays email addresses, image URLs, and source-destination IP pairs in the terminal.

Traffic Plot:

- Saves a PNG file (all_protocols_traffic_plot.png) and shows traffic over time, with statistical thresholds.

Project Structure

Files:

- pcap_analyser.py

Main script that integrates all functionalities:
Parses PCAP files.
Extracts and prints emails, image URLs, and IP pairs.
Generates and saves traffic visualizations.

- pcap_parser.py

Handles parsing and summarising traffic data:
Organises traffic data by protocol and summarises traffic statistics.

- pcap_analysis.py

Extracts specific information and prepares data for visualisation:
Extracts email addresses and image URLs from TCP payloads, extracts IP pairs and counts traffic between them.
then prepares data for plotting and generates plots.

Customisation:

- Change PCAP File: 
Modify the pcap_file variable in main() (in pcap_analyser.py) to specify a different PCAP file.

- Adjust Visualisation Parameters: 
Update the interval_length parameter in the prepare_plot_data() function (in pcap_analysis.py) 
to change the time intervals for traffic analysis.