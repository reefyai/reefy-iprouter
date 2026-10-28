"""Authenticated Reefy app UI. Network mutations also require a same-page token."""
import hmac
import json
import os
from pathlib import Path
import secrets
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from engine import Router

ROOT = Path(__file__).parent


def serve(router, address, port):
    token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status, body, content_type='application/json'):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'self'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == '/':
                return self.reply(200, (ROOT / 'static/index.html').read_text().replace('__TOKEN__', token), 'text/html; charset=utf-8')
            if self.path in ('/icon.png', '/favicon.png'):
                return self.reply(200, (ROOT / 'reefy' / self.path[1:]).read_bytes(), 'image/png')
            if self.path in ('/app.js', '/style.css'):
                content_type = 'text/javascript' if self.path.endswith('.js') else 'text/css'
                return self.reply(200, (ROOT / 'static' / self.path[1:]).read_bytes(), content_type)
            if self.path == '/status':
                try:
                    return self.reply(200, router.status())
                except Exception:
                    return self.reply(503, dict(error='Network status is unavailable.'))
            return self.reply(404, dict(error='Not found.'))

        def do_POST(self):
            if not hmac.compare_digest(self.headers.get('X-Router-Token', ''), token):
                return self.reply(403, dict(error='Refresh this page before changing settings.'))
            if self.headers.get('Sec-Fetch-Site') not in (None, 'same-origin'):
                return self.reply(403, dict(error='Open Router through Reefy to change settings.'))
            if self.headers.get('Content-Type') != 'application/json':
                return self.reply(415, dict(error='JSON is required.'))
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 4096:
                    return self.reply(413, dict(error='Settings are too large.'))
                value = json.loads(self.rfile.read(size))
                if self.path == '/apply':
                    return self.reply(200, router.apply(value))
                if self.path == '/stop':
                    if value != {}:
                        raise ValueError('Stop takes no settings.')
                    return self.reply(200, router.stop())
                return self.reply(404, dict(error='Not found.'))
            except (ValueError, json.JSONDecodeError) as error:
                return self.reply(400, dict(error=str(error)))
            except Exception as error:
                router.error = str(error) if isinstance(error, RuntimeError) else 'Could not apply settings. The downstream interface remains isolated.'
                return self.reply(503, dict(error=router.error))

    return ThreadingHTTPServer((address, port), Handler)


def main():
    router = Router(os.environ.get('ROUTER_DATA', '/data'))
    # Smoke checks run as an unprivileged user on an isolated bridge. They must
    # serve HTTP without ever configuring the build host's network.
    def restore():
        while True:
            with router.lock:
                if router.config and not router.stopped:
                    if (router.config['dhcp'] and router.dhcp is not None
                            and router.dhcp.poll() is not None):
                        router.active = False
                    if router.active:
                        try:
                            router.refresh_protection()
                        except Exception as error:
                            router.error = str(error)
                    if not router.active:
                        try:
                            router.apply(router.config)
                        except Exception as error:
                            router.error = str(error)
            time.sleep(5)
    threading.Thread(target=restore, daemon=True).start()
    def shutdown(_signum, _frame):
        try:
            router.stop(persist=False)
        finally:
            raise SystemExit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    allocated = os.environ.get('APP_PORT_8080')
    server = serve(router, '127.0.0.1' if allocated else '0.0.0.0', int(allocated or 8080))
    server.serve_forever()


if __name__ == '__main__':
    main()
