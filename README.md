# pcap_connect
This is a complementary tool to pcap_glance . It helps identify suspicious IP addresses, analyze DNS queries, and detect abnormal traffic patterns, such as beaconing. The tool integrates with threat intelligence services to provide insights into potential malicious activity.

Prerequisites

Python 3.6 or higher
Internet access for API queries

Install Dependencies: Ensure you have the required Python libraries installed. Run:

        pip install pyshark requests pandas matplotlib

Obtain API Key:

Sign up for a threat intelligence service like AbuseIPDB and obtain an API key.
Replace 'your_api_key' in the script with your actual API key.

Usage

Save the Script: Save the provided Python script to a file named pcap_connect.py.

Prepare a PCAP File: Ensure you have a PCAP file to analyze. This can be a file you've captured or one from a public dataset.

Run the Script: Execute the script from the command line, specifying the path to your PCAP file:

      python pcap_connect.py --file path/to/yourfile.pcap

View Results: The tool will output detected suspicious IP addresses, DNS queries, and visualize beaconing patterns.

Configuration

API Key: Replace the placeholder API key in the script with your actual key for threat intelligence queries.

PCAP File Path: Modify the pcap_file variable in the script or use command-line arguments to specify the path to your PCAP file.
