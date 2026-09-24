import socketserver
import threading

HOST = "127.0.0.1"


class TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"IPCamera login: ")


class MqttHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        if data:
            self.request.sendall(b"\x20\x02\x00\x00")  # MQTT connection accepted


class HttpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(1024)
        page = b"<html><title>Camera Login</title><body>Login page</body></html>"
        self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" + page)


class RtspHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(1024)
        self.request.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


services = [
    (2323, "Telnet", TelnetHandler),
    (1883, "MQTT", MqttHandler),
    (8080, "HTTP", HttpHandler),
    (554, "RTSP", RtspHandler),
]

print("Fake IoT device running on", HOST)
for port, name, handler in services:
    try:
        server = Server((HOST, port), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"  {name} on port {port}")
    except OSError:
        print(f"  Could not start {name} on port {port} (port already in use)")

print("Press CTRL+C to stop")
try:
    threading.Event().wait()
except KeyboardInterrupt:
    print("Stopped")
