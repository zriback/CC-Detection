import os
import signal
import subprocess
import random
import time
import threading
from datetime import datetime

cc_active_rules = '/home/user/rules-cc'
cc_inactive_rules = '/home/user/rules-empty'

active_output_dirname = 'active_dir'
inactive_output_dirname = 'inactive_dir'

def toggle_iptables(activate: bool):
    if activate:
        file = cc_active_rules
    else:
        file = cc_inactive_rules

    with open(file, 'r') as f:
        result = subprocess.run(
                ['sudo', 'iptables-restore'],
                stdin=f,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
        )
   

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
    num_connections = 20
    total_duration = 60  # Total duration in seconds
    elapsed_time = 0

    # put random line from all_messages into the message file
    random_line = random.randint(0,14)
    chosen_line = ''
    with open('all_messages.txt', 'r') as f:
        for this_line_num, line in enumerate(f.readlines()):
            if this_line_num == random_line:
                chosen_line = line
                break
    with open('message.txt', 'w') as f:
        f.write(chosen_line)
    
    start_time = int(time.time())
    send_times = random.choices(range(1,59), k=num_connections)
    send_times.sort()
    i = 0
    while True:
        next_time = send_times[i]
        if elapsed_time > next_time:
            create_tcp_connection(host, port)
            i += 1
        if i >= num_connections:
            break
        elapsed_time = int(time.time()) - start_time


def main():
    total_runs = 2000
    runs_with_transmitter = 1000
    runs_without_transmitter = 1000

    # Create a list with 100 True and 100 False values and shuffle it
    run_choices = [True] * runs_with_transmitter + [False] * runs_without_transmitter
    random.shuffle(run_choices)

    for run_num, run_transmitter in enumerate(run_choices):
        print(f"Run {run_num + 1}/{total_runs} - {'With' if run_transmitter else 'Without'} transmitter.elf")

        # Determine the directory based on whether transmitter.elf is running
        directory = f'/home/user/{active_output_dirname}' if run_transmitter else f'/home/user/{inactive_output_dirname}'
        os.makedirs(directory, exist_ok=True)

        # Start tcpdump and save the capture file to the appropriate directory
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        pcap_file = os.path.join(directory, f"capture_{timestamp}.pcap")
        tcpdump_cmd = ["tcpdump", "-w", pcap_file]
        tcpdump_process = subprocess.Popen(tcpdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Start transmitter.elf if needed
        transmitter_process = None
        if run_transmitter:
            transmitter_process = subprocess.Popen(['sudo', './tcp_transmitter_simple.elf'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
            toggle_iptables(True)
        else:
            toggle_iptables(False)


        # Start the thread to create TCP connections
        connection_thread = threading.Thread(target=make_connections)
        connection_thread.start()

        # Wait for one minute
        time.sleep(60)

        # Stop transmitter.elf if it was started
        if transmitter_process:
            toggle_iptables(False)
            os.killpg(os.getpgid(transmitter_process.pid), signal.SIGTERM)
            transmitter_process.wait()


        # Stop tcpdump
        tcpdump_process.terminate()
        tcpdump_process.wait()

        # Ensure the connection thread has finished
        connection_thread.join()

if __name__ == "__main__":
    main()


