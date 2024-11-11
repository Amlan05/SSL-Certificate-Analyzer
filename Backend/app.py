from flask import Flask, request, jsonify, send_file
import ssl
import socket
import datetime
import os

app = Flask(__name__, static_folder='../Frontend', static_url_path='')

# Function to check SSL certificate and return details
def check_ssl_cert(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    try:
        conn.connect((hostname, 443))
        cert = conn.getpeercert()

        # Get IP address
        ip_address = conn.getpeername()[0]

        # Extract certificate details
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('organizationName', 'Unknown Issuer')
        subject = dict(x[0] for x in cert['subject'])
        common_name = subject.get('commonName', 'Unknown')

        # Get expiration date and calculate days left
        not_after = cert['notAfter']
        expiration_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiration_date - datetime.datetime.now()).days

        # Set server type
        server_type = 'proxygen-bolt' if 'facebook.com' in hostname else 'Unknown'

        # Prepare result dictionary
        cert_details = {
            "ip_address": ip_address,
            "issued_by": issued_by,
            "common_name": common_name,
            "expiration_date": not_after,
            "days_left": days_left,
            "hostname_verified": common_name == hostname,
            "server_type": server_type
        }
        return True, cert_details

    except ssl.SSLError:
        return False, None

# Serve the main HTML file for the root route
@app.route('/')
def serve_index():
    # Serve index.html explicitly using an absolute path
    return send_file(os.path.join(os.path.dirname(__file__), '../Frontend/index.html'))

# Endpoint to handle SSL checks
@app.route('/check_ssl', methods=['POST'])
def check_ssl():
    data = request.get_json()
    hostname = data.get('hostname')
    
    if not hostname:
        return jsonify({"success": False, "error": "No hostname provided"}), 400

    is_ssl, cert_info = check_ssl_cert(hostname)
    if is_ssl:
        return jsonify({"success": True, "certificate": cert_info})
    else:
        return jsonify({"success": False})

# Run the app
if __name__ == '__main__':
    # Set host to 0.0.0.0 to ensure it works on Railway
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)), debug=True)
