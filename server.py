from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

PORT = int(os.environ.get("PORT", 8080))

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.path.dirname(__file__), **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "":
            self.path = "/log-dashboard.html"
        return super().do_GET()

    def log_message(self, format, *args):
        print(f"[LogLens] {self.address_string()} - {format % args}")

if __name__ == "__main__":
    print(f"🔍 LogLens Dashboard running on http://0.0.0.0:{PORT}")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
