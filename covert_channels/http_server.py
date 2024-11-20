#server

from flask import Flask, request
import binascii

app = Flask(__name__)

# Decode hex to string function
def decode_message(hex_msg):
    try:
        # Convert hex to bytes and then decode to string
        return binascii.unhexlify(hex_msg).decode('utf-8')
    except (binascii.Error, UnicodeDecodeError):
        return None

# Route to handle incoming covert messages
@app.route('/<path:endpoint>', methods=['GET'])
def receive_covert_message(endpoint):
    # Extract and decode covert message from query parameters
    covert_message = None
    for key, value in request.args.items():
        decoded_msg = decode_message(value)
        if decoded_msg:
            covert_message = decoded_msg
            break  # Only decode the first parameter with a valid covert message

    # Log and show the covert message if one was found
    if covert_message:
        print(f"Received covert message: '{covert_message}'")
    else:
        print("Received normal traffic or invalid message.")

    return "Request received.", 200

# Start the server
if __name__ == '__main__':
    app.run(port=5000)


