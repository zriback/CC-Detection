import requests
import random
import time

# Server URL and endpoints shared between normal and covert scripts
server_url = "http://10.30.0.2:5000/"
endpoints = [
    "login", "products", "services", "faq", "support", "news", "user", "account"
]

# Shared query parameter names for both normal and covert traffic
query_params = [
    "data", "info", "code", "msg", "auth", "ref", "temp", "check"
]

# Covert messages to send
covert_messages = [
    "operation_success", "transfer_complete", "server_check", "validate_user",
    "confirm_access", "secure_update", "test_run", "ping_response",
    "session_initiated", "sync_start", "sync_complete", "request_processed",
    "heartbeat_acknowledged", "client_update", "data_received", "system_ready",
    "error_recovery", "reset_acknowledged", "ping_retry", "load_balanced",
    "connection_reset", "auth_request", "auth_granted", "auth_denied",
    "system_alert", "data_sync", "session_closed", "error_logging",
    "maintenance_mode", "backup_complete", "checksum_verified", "connection_established",
    "data_refresh", "resource_allocated", "resource_freed", "load_testing",
    "validation_passed", "validation_failed", "encryption_initialized", "encryption_disabled",
    "decryption_enabled", "decryption_failed", "key_exchange", "signature_verified",
    "secure_handshake", "token_issued", "token_expired", "session_timeout",
    "throttle_applied", "threshold_exceeded", "quota_met", "memory_cleaned"
]

# Headers to make both traffic types look alike
header_options = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept": "text/html"},
    {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3)", "Accept": "application/json"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Accept": "application/xml"},
    {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)", "Accept": "text/plain"},
    {"User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G973F)", "Accept": "*/*"},
]

# Function to encode messages as hexadecimal
def encode_message(msg):
    return ''.join(format(ord(c), '02x') for c in msg)

# Function to generate random hex strings
def random_hex(length=8):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

# Main function to handle traffic generation
def main():
    start_time = time.time()
    # Choose a random time between 5 and 40 seconds to send covert messages
    covert_time = random.randint(5, 40)
    covert_messages_sent = False
    repeat_interval = 5  # Send a message every 5 seconds

    while True:
        current_time = time.time()
        elapsed_time = current_time - start_time

        if not covert_messages_sent and elapsed_time >= covert_time:
            # Send three packets with covert messages
            for _ in range(3):
                # Choose a covert message and encode it
                message = random.choice(covert_messages)
                encoded_msg = encode_message(message)

                num_params = random.randint(1,3)
                encoded_param = random.randint(0,num_params-1)

                # Prepare parameters with the encoded message
                params = {param: encoded_msg if i == encoded_param else random_hex(random.randint(16,40))
                          for i, param in enumerate(random.sample(query_params, num_params))}
                # Choose an endpoint and headers
                endpoint = random.choice(endpoints)
                headers = random.choice(header_options)
                url = f"{server_url}{endpoint}"
                try:
                    response = requests.get(url, params=params, headers=headers)
                    print(f"Sent covert message: {response.url} | Status: {response.status_code}")
                except Exception as e:
                    print("Error sending covert message:", e)
                # Wait a short time between sending the three packets
                time.sleep(repeat_interval)
            # Set the flag to True after sending covert messages
            covert_messages_sent = True
        else:
            # Send normal traffic
            # Choose an endpoint and mimic covert parameter structure
            endpoint = random.choice(endpoints)
            params = {param: random_hex(random.randint(16,40)) for param in random.sample(query_params, random.randint(1, 3))}
            headers = random.choice(header_options)
            url = f"{server_url}{endpoint}"
            try:
                response = requests.get(url, params=params, headers=headers)
                print(f"Generated normal traffic request: {response.url} | Status: {response.status_code}")
            except Exception as e:
                print("Error generating traffic:", e)
            # Wait for the repeat interval before sending the next message
            time.sleep(repeat_interval)

# Run the main function
if __name__ == "__main__":
    main()

