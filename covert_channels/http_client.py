#client

import requests
import random
import time

# Server URL and endpoint options to blend with normal traffic
server_url = "http://10.30.0.2:5000/"
endpoints = ["login", "products", "services", "faq", "support", "news", "user", "account"]

# Shared query parameter names
query_params = ["data", "info", "code", "msg", "auth", "ref", "temp", "check"]

# Expanded list of covert messages
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

# Headers to make covert traffic resemble normal traffic
header_options = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept": "text/html"},
    {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3)", "Accept": "application/json"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Accept": "application/xml"},
    {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)", "Accept": "text/plain"},
    {"User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G973F)", "Accept": "*/*"},
]

# Encode a message as hexadecimal
def encode_message(msg):
    return ''.join(format(ord(c), '02x') for c in msg)

# Generate random hex strings
def random_hex(length):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

# Function to send covert messages with varying endpoints and parameters
def send_covert_message(repeat_interval=5):
    while True:
        # Choose a covert message, endpoint, and headers
        message = random.choice(covert_messages)
        encoded_msg = encode_message(message)
        endpoint = random.choice(endpoints)
        headers = random.choice(header_options)

        num_params = random.randint(1,3)
        encoded_param = random.randint(0,num_params-1)

        # Prepare parameters, with the covert message embedded
        params = {param: encoded_msg if i == encoded_param else random_hex(random.randint(16,40))
                  for i, param in enumerate(random.sample(query_params, num_params))}

        # Construct and send the request
        url = f"{server_url}{endpoint}"

        try:
            response = requests.get(url, params=params, headers=headers)
            print(f"Sent covert message: {response.url} | Status: {response.status_code}")
        except Exception as e:
            print("Error sending covert message:", e)
        
        # Wait before sending the next covert message
        time.sleep(repeat_interval)

# Run indefinitely
send_covert_message()
