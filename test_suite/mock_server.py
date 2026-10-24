"""Serve deliberate attack pages at http://127.0.0.1:5000."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class MockHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path(__file__).parent / "mock_pages"), **kwargs)


if __name__ == "__main__":
    print("SafeParse mock pages: http://127.0.0.1:5000")
    ThreadingHTTPServer(("127.0.0.1", 5000), MockHandler).serve_forever()
