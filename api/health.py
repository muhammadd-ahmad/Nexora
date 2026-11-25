import json, os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        key_ready = bool(os.getenv("SCAN_API_KEY"))
        scope_ready = bool(os.getenv("ALLOWED_TARGETS", "").strip())
        body = json.dumps({
            "status": "ok",
            "scan_ready": key_ready and scope_ready,
            "api_key_configured": key_ready,
            "authorized_scope_configured": scope_ready,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return
