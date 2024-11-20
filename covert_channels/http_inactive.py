# normal http traffic client

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

# Headers to make both traffic types look alike
header_options = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept": "text/html"},
    {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3)", "Accept": "application/json"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Accept": "application/xml"},
    {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)", "Accept": "text/plain"},
    {"User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G973F)", "Accept": "*/*"},
]

# Function to generate random-looking data to mimic encoded data
def random_hex(length=8):
    return ''.join(random.choice('0123456789abcdef') for _ in range(length))

# Function for generating traffic similar to the covert channel
def generate_similar_normal_traffic(repeat_interval=5):
    while True:
        # Select an endpoint and mimic covert parameter structure
        endpoint = random.choice(endpoints)
        params = {param: random_hex(random.randint(16,40)) for param in random.sample(query_params, random.randint(1, 3))}
        headers = random.choice(header_options)

        # Construct and send request to mimic covert traffic closely
        url = f"{server_url}{endpoint}"
        try:
            response = requests.get(url, params=params, headers=headers)
            print(f"Generated normal traffic request: {response.url} | Status: {response.status_code}")
        except Exception as e:
            print("Error generating traffic:", e)
        
        # Wait before sending the next request
        time.sleep(repeat_interval)

# Run indefinitely to simulate constant traffic
generate_similar_normal_traffic()
