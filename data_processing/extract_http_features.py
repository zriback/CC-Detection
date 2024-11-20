from scapy.all import rdpcap
import numpy as np
import os
import pickle
from urllib.parse import urlparse, parse_qsl
from Collections import Counter
import math

X_output = 'X_http.obj'
y_output = 'y_http.obj'

transmitter_ip = '10.30.0.1'
receiver_ip = '10.30.0.2'

# Maximum number of HTTP GET requests to process per pcap file
MAX_REQUESTS = 12

# Analyze all the pcaps in the given directory
# cc_active is the label to assign to those samples in y structure
def analyze_directory(dir_filepath: str, cc_active: int):
    for pcap in sorted([i for i in os.listdir(dir_filepath) if i.endswith('.pcap')]):
        features = analyze_pcap(os.path.join(dir_filepath, pcap))

        # Dump output to files
        with open(X_output, 'ab') as obj_file:
            pickle.dump(features, obj_file)

        with open(y_output, 'ab') as obj_file:
            pickle.dump(cc_active, obj_file)

# Analyze pcap
# pcap_path is the file path for the pcap file
# Returns a list of length 12, each element is the entropy for those http param values
def analyze_pcap(pcap_path: str):
    # Get all packets from pcap file
    packets = rdpcap(pcap_path)

    features_list = []

    for packet in packets:
        entropy = get_entropy(packet)
        if entropy is not None:
            features_list.append(entropy)

    # Collect up to MAX_REQUESTS HTTP GET requests
    if len(features_list) > MAX_REQUESTS:
        features_list = features_list[:MAX_REQUESTS]
    elif len(features_list) < MAX_REQUESTS:
        # If less than MAX_REQUESTS, pad with zeros
        while len(features_list) < MAX_REQUESTS:
            features_list.append(0)

    features_list = np.array(features_list)
    return features_list

# Return the feature vector for this HTTP GET request if it is one we want
# Otherwise, return None
def get_entropy(packet):
    if not packet.haslayer('IP'):
        return None
    ip = packet['IP']
    if not (ip.src == transmitter_ip):
        return None
    if not (ip.dst == receiver_ip):
        return None
    if not packet.haslayer('TCP'):
        return None
    tcp = packet['TCP']

    # Get TCP payload
    tcp_payload = bytes(tcp.payload)
    if len(tcp_payload) == 0:
        return None

    # Decode payload as string
    try:
        tcp_payload_str = tcp_payload.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return None

    # Split payload into lines
    lines = tcp_payload_str.split('\r\n')
    if len(lines) == 0:
        return None

    request_line = lines[0]
    if not request_line.startswith('GET '):
        return None

    # Parse the request line
    parts = request_line.split(' ')
    if len(parts) < 2:
        return None
    path = parts[1]

    parsed_url = urlparse(path)
    query = parsed_url.query
    params_list = parse_qsl(query)  # List of (key, value) tuples
    values = [value for (key, value) in params_list]

    # Concatenate all parameter values into one byte string
    param_data_str = ''.join(values)
    param_data = param_data_str.encode('utf-8', errors='ignore')

    if len(param_data) == 0:
        return None

    # Compute byte value distribution
    byte_counts = Counter(param_data)
    total_bytes = len(param_data)
    byte_frequencies = np.zeros(256)

    for byte_value, count in byte_counts.items():
        byte_frequencies[byte_value] = count / total_bytes

    # Compute Shannon entropy
    entropy = 0.0
    for freq in byte_frequencies:
        if freq > 0:
            entropy -= freq * math.log2(freq)

    return entropy


# Main function
def main():
    # Analyze directories
    analyze_directory('../http-inactive', 0)
    analyze_directory('../http-active', 1)

if __name__ == '__main__':
    main()


