# @even rygh
"""
Simple HTTP server for the frontend.
Serves the React frontend on port 8080.
"""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

class CORSRequestHandler(SimpleHTTPRequestHandler):
    # Ensure browsers interpret text assets as UTF-8.
    extensions_map = SimpleHTTPRequestHandler.extensions_map.copy()
    extensions_map.update(
        {
            ".html": "text/html; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".svg": "image/svg+xml; charset=utf-8",
            ".txt": "text/plain; charset=utf-8",
            ".md": "text/markdown; charset=utf-8",
        }
    )

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

if __name__ == '__main__':
    os.chdir('frontend')
    port = 8080
    server = HTTPServer(('localhost', port), CORSRequestHandler)
    print(f'Frontend server running at http://localhost:{port}')
    print(f'Serving files from: {os.getcwd()}')
    print(f'\nOpen in browser: http://localhost:{port}/index.html')
    print('\nPress Ctrl+C to stop\n')
    server.serve_forever()
