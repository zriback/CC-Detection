import os
import subprocess
import threading
from datetime import datetime
from scapy.all import sniff, TCP, IP
import signal  # Import the signal module

output_dirname = 'legacy_tcp_inactive'

def main():
    total_captures = 48
    for capture_number in range(1, total_captures + 1):
        # Create the directory if it doesn't exist
        os.makedirs(output_dirname, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        pcap_file = os.path.join(output_dirname, f"capture_{timestamp}.pcap")

        # Start tcpdump to capture packets and save to pcap_file
        tcpdump_cmd = ["tcpdump", "-U", "-w", pcap_file]  # Added '-U' option
        tcpdump_process = subprocess.Popen(
            tcpdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Initialize variables to track connections
        active_connections = set()
        completed_connections = set()

        def packet_handler(pkt):
            nonlocal active_connections, completed_connections
            if IP in pkt and TCP in pkt:
                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = tcp_layer.flags

                # Check if the packet is from the target host
                if src_ip == '10.30.0.3':
                    conn_tuple = (src_ip, src_port, dst_ip, dst_port)
                    # SYN packet (connection start)
                    if 'S' in flags and 'A' not in flags:
                        active_connections.add(conn_tuple)
                    # FIN packet (connection end)
                    elif 'F' in flags:
                        if conn_tuple in active_connections:
                            active_connections.remove(conn_tuple)
                            completed_connections.add(conn_tuple)
                            print(f"Completed connections: {len(completed_connections)}")
                # Check if the packet is to the target host
                elif dst_ip == '10.30.0.3':
                    conn_tuple = (dst_ip, dst_port, src_ip, src_port)
                    if 'F' in flags:
                        if conn_tuple in active_connections:
                            active_connections.remove(conn_tuple)
                            completed_connections.add(conn_tuple)
                            print(f"Completed connections: {len(completed_connections)}")

        # Define a stop condition for sniffing
        def stop_sniff(pkt):
            return len(completed_connections) >= 21

        print(f"Starting capture {capture_number}/{total_captures}")
        # Start sniffing packets in a separate thread
        sniff_thread = threading.Thread(target=sniff, kwargs={
            'filter': "tcp and host 10.30.0.3",
            'prn': packet_handler,
            'store': 0,
            'stop_filter': stop_sniff
        })
        sniff_thread.start()
        sniff_thread.join()

        # Stop tcpdump after the condition is met
        tcpdump_process.send_signal(signal.SIGINT)  # Send SIGINT instead of terminate()
        tcpdump_process.wait()
        print(f"Capture {capture_number} completed and saved to {pcap_file}.")

    print("All captures completed.")

if __name__ == "__main__":
    main()



