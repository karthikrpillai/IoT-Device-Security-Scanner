from flask import Flask, jsonify, request, send_from_directory

from scanner import get_my_network, scan_network

app = Flask(__name__, static_folder="static")



@app.route("/")
def home():
    return send_from_directory("static", "index.html")



@app.route("/network")
def network():
    return jsonify({"network": get_my_network()})



@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    network_text = data.get("network", "")

    try:
        result = scan_network(network_text)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(result)


if __name__ == "__main__":
    print("Open http://localhost:5000 in your browser")
    app.run(host="127.0.0.1", port=5000)
