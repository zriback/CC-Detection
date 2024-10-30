import os
import subprocess
import random
import time
import threading
from datetime import datetime

def create_tcp_connection(host, port, timeout=1):
    """Create a TCP connection, send random data, and close the connection."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # Send some random data before closing
        data = os.urandom(random.randint(1, 1024))  # Random data between 1 and 1024 bytes
        s.sendall(data)
        s.close()
    except Exception:
        pass  # Ignore exceptions

def make_connections():
    host = '10.30.0.2'
    port = 5555  # Change to the appropriate port if needed
    num_connections = 10
    total_duration = 60  # Total duration in seconds
    elapsed_time = 0

    for i in range(num_connections):
        create_tcp_connection(host, port)
        if i < num_connections - 1:
            # Calculate remaining time and distribute it randomly among remaining connections
            remaining_connections = num_connections - i - 1
            max_delay = total_duration - elapsed_time - 0.1 * remaining_connections
            if max_delay > 0:
                delay = random.uniform(0.1, max_delay)
            else:
                delay = 0.1  # Minimum delay
            time.sleep(delay)
            elapsed_time += delay

def main():
    total_runs = 200
    runs_with_transmitter = 100
    runs_without_transmitter = 100

    # Create a list with 100 True and 100 False values and shuffle it
    run_choices = [True] * runs_with_transmitter + [False] * runs_without_transmitter
    random.shuffle(run_choices)

    for run_num, run_transmitter in enumerate(run_choices):
        print(f"Run {run_num + 1}/{total_runs} - {'With' if run_transmitter else 'Without'} transmitter.elf")

        # Determine the directory based on whether transmitter.elf is running
        directory = 'cc-active' if run_transmitter else 'cc-inactive'
        os.makedirs(directory, exist_ok=True)

        # Start tcpdump and save the capture file to the appropriate directory
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        pcap_file = os.path.join(directory, f"capture_{timestamp}.pcap")
        tcpdump_cmd = ["tcpdump", "-w", pcap_file]
        tcpdump_process = subprocess.Popen(tcpdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Start transmitter.elf if needed
        transmitter_process = None
        if run_transmitter:
            transmitter_process = subprocess.Popen(["./transmitter.elf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Start the thread to create TCP connections
        connection_thread = threading.Thread(target=make_connections)
        connection_thread.start()

        # Wait for one minute
        time.sleep(60)

        # Stop transmitter.elf if it was started
        if transmitter_process:
            transmitter_process.terminate()
            transmitter_process.wait()

        # Stop tcpdump
        tcpdump_process.terminate()
        tcpdump_process.wait()

        # Ensure the connection thread has finished
        connection_thread.join()

if __name__ == "__main__":
    main()

