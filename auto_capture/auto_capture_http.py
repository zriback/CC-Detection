import os
import signal
import subprocess
import random
import time
import threading
from datetime import datetime

active_output_dirname = 'active_dir'
inactive_output_dirname = 'inactive_dir'

def main():
    total_runs = 2000
    runs_with_transmitter = 1000
    runs_without_transmitter = 1000

    # Create a list with 1000 True and 1000 False values and shuffle it
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

        # start the correct transmitter program 
        transmitter_process = None
        if run_transmitter:
            transmitter_process = subprocess.Popen(['python3', './covert_channels/http_active.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
        else:
            transmitter_process = subprocess.Popen(['python3', './covert_channels/http_inactive.py'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)

        # Wait for one minute
        time.sleep(60)

        # Stop transmitter.elf if it was started
        if transmitter_process:
            os.killpg(os.getpgid(transmitter_process.pid), signal.SIGTERM)
            transmitter_process.wait()


        # Stop tcpdump
        tcpdump_process.terminate()
        tcpdump_process.wait()


if __name__ == "__main__":
    main()


