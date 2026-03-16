from flask import Flask, request, jsonify, render_template
import re

app = Flask(__name__)

# ------------------------------
# Parse log line
# ------------------------------
def parse_log_line(line):
    pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+)'
    match = re.match(pattern, line)
    if match:
        return {
            "ip": match.group(1),
            "timestamp": match.group(2),
            "request": match.group(3),
            "status": match.group(4),
            "size": match.group(5)
        }
    return None


# ------------------------------
# Homepage
# ------------------------------
@app.route('/')
def home():
    return render_template("upload.html")


# ------------------------------
# Upload API
# ------------------------------
@app.route('/upload', methods=['POST'])
def upload():

    file = request.files.get('file')

    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    lines = file.read().decode('utf-8').splitlines()

    parsed_logs = []
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            parsed_logs.append(parsed)

    # ------------------------------
    # Threat Detection
    # ------------------------------
    suspicious = []

    for log in parsed_logs:
        status = log.get("status")
        request_text = log.get("request", "")
        ip = log.get("ip")

        # --- Status-based attacks ---
        if status == "401":
            suspicious.append({
                "ip": ip,
                "type": "Failed Login Attempt",
                "request": request_text
            })

        if status == "403":
            suspicious.append({
                "ip": ip,
                "type": "Unauthorized Access",
                "request": request_text
            })

        if "/admin" in request_text.lower():
            suspicious.append({
                "ip": ip,
                "type": "Admin Page Access Attempt",
                "request": request_text
            })

        # --- SQL Injection ---
        if re.search(r"(union select|or 1=1|'--)", request_text.lower()):
            suspicious.append({
                "ip": ip,
                "type": "SQL Injection Attempt",
                "request": request_text
            })

        # --- XSS ---
        if re.search(r"(<script>|javascript:)", request_text.lower()):
            suspicious.append({
                "ip": ip,
                "type": "XSS Attempt",
                "request": request_text
            })

        # --- Directory Traversal ---
        if "../" in request_text:
            suspicious.append({
                "ip": ip,
                "type": "Directory Traversal Attempt",
                "request": request_text
            })

    # ------------------------------
    # Top Attackers
    # ------------------------------
    ip_counts = {}

    for item in suspicious:
        ip = item["ip"]
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top_attackers = [
        {"ip": ip, "attack_count": count}
        for ip, count in ip_counts.items()
    ]

    # ------------------------------
    # Final Response
    # ------------------------------
    return jsonify({
        "message": "File uploaded & analyzed successfully",
        "total_entries": len(parsed_logs),
        "suspicious_count": len(suspicious),
        "top_attackers": top_attackers,
        "suspicious_activity": suspicious,
        "sample_data": parsed_logs[:5]
    })


# ------------------------------
# Run server
# ------------------------------
if __name__ == '__main__':
    app.run(debug=True)