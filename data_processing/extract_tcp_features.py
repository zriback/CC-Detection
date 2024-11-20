from scapy.all import rdpcap
import numpy as np
import os
import pickle

X_output = 'X.obj'
y_output = 'y.obj'

transmitter_ip = '10.30.0.1'
receiver_ip = '10.30.0.2'


# Number of samples to read before pickling to .obj file
SAMPLE_BUFFER_SIZE = 1

# return sequence number if this is a packet we want
# otherwise return None
def get_syn_seq(packet):
    if not packet.haslayer('IP'):  # not an IP packet
        return None
    ip = packet['IP']
    if not (ip.src == transmitter_ip):  # not sent by transmitter
        return None
    if not (ip.dst == receiver_ip):  # not sent to receiver
        return None
    if not (ip.haslayer('TCP')):  # not a TCP packet
        return None
    tcp = ip['TCP']
    if not (tcp.flags & 0x02):  # syn flag not set
        return None
    
    return tcp.seq


# analyze all the pcaps in the given directory
# param is the number to assign to those samples in y structure
def analyze_directory(dir_filepath: str, cc_active: int):
    for pcap in [i for i in os.listdir(dir_filepath) if i.endswith('.pcap')]:
        isn_list = analyze_pcap(os.path.join(dir_filepath, pcap))
        
        # format and dump output to files
        isn_list = np.array(isn_list)
        with open(X_output, '+ab') as obj_file:
            pickle.dump(isn_list, obj_file)

        with open(y_output, '+ab') as obj_file:
            pickle.dump(cc_active, obj_file)


# analyze pcap
# param is file path for the pcap file
# returns list of all ISNs
def analyze_pcap(pcap_path: str):
    # get all packets from pcap file
    packets = rdpcap(pcap_path)

    # empty isn list
    isn_list = []

    for packet in packets:
        seq = get_syn_seq(packet)
        if seq is not None:
            isn_list.append(seq)

    return isn_list


# main function
def main():
    # analyze directories
    analyze_directory('../cc-active2', 1)



if __name__ == '__main__':
    main()


