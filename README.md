# Network-Packet-Analyzer

This Python-based Packet Sniffer Tool uses the Scapy library to capture and analyze network packets. It provides detailed information about the packets transmitted across a specified network interface, including source and destination IP addresses, protocols, and payload data.


Features :-
- IP Packet Analysis: Captures packets with IP headers and extracts source and destination IP addresses.

- Protocol Identification: Identifies and displays the protocol used (TCP, UDP, ICMP, or other).

- Payload Data: Extracts and displays payload data for TCP, UDP, and ICMP packets.
  
- User-Friendly Output: Provides a clear and organized output of packet details to the console


How It Works :-
- Packet Capture: The tool uses Scapy to sniff packets on the specified network interface.

- Packet Analysis: Each captured packet is analyzed to determine its IP layer, protocol, and additional details.

- Information Display: The tool prints out the source and destination IP addresses, protocol type, and payload data (if available) for each packet.

Usage :-

Ensure Scapy is installed:-

    pip install scapy

Update the network interface in the script to match your environment (e.g., eth0, wlan0, etc.).

Run the script with appropriate permissions:-

    sudo python packet_sniffer.py


Ethical Considerations :- This tool is intended for educational and ethical use only. Ensure you have permission to capture and analyze network traffic on the network you are monitoring. Unauthorized packet sniffing can be illegal and unethical.


Contributing :- Feel free to contribute to this project by submitting issues or pull requests. Contributions and feedback are welcome!


License :- This project is licensed under the MIT License. See the LICENSE file for details.







