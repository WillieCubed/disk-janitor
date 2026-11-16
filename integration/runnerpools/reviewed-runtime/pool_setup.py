"""One temporary loopback approval flow in the owner's chosen Chrome profile."""
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
import urllib.parse

from pool_auth import app_manifest
from pool_config import Failure, require, validate


def choose_chrome_profile(available, requested):
    require(isinstance(available, dict) and isinstance(requested, str) and bool(requested.strip()),
            'Choose a named existing Chrome profile.')
    normalized = re.sub(r'[^a-z0-9]', '', requested.lower())
    exact, candidates = [], []
    for directory, metadata in available.items():
        if not isinstance(directory, str) or not re.fullmatch(r'[A-Za-z0-9 _-]{1,80}', directory) or not isinstance(metadata, dict):
            continue
        name = metadata.get('name')
        if not isinstance(name, str):
            continue
        if requested.casefold() in (directory.casefold(), name.casefold()):
            exact.append(directory)
        candidate = re.sub(r'[^a-z0-9]', '', name.lower())
        if normalized and candidate and (normalized in candidate or candidate in normalized):
            candidates.append(directory)
    matches = exact or candidates
    require(len(matches) == 1, 'Chrome profile is missing or ambiguous; rerun with --chrome-profile and its exact visible name.')
    return matches[0]


def open_chrome(url, requested):
    """Open the URL in the named Chrome profile; False when macOS hides the profile list.

    macOS privacy controls can stop a terminal reading Chrome's profile list. The
    caller then shows the URL so the owner opens it in the intended profile.
    """
    if os.environ.get('SSH_CONNECTION'):
        return False  # The caller prints the URL for the forwarded local browser.
    path = Path.home() / 'Library/Application Support/Google/Chrome/Local State'
    try:
        available = json.loads(path.read_text())['profile']['info_cache']
    except (OSError, ValueError, KeyError, TypeError):
        return False
    directory = choose_chrome_profile(available, requested)
    # New invocation forwards this explicit profile to Chrome's own process.
    # No credentials or approval values are present in the URL/arguments.
    result = subprocess.run(['/usr/bin/open', '-na', 'Google Chrome', '--args', '--profile-directory=' + directory, url],
                            capture_output=True, timeout=30)
    require(result.returncode == 0, 'Chrome could not open the selected profile; native approval has not started.')
    return True


class ManifestFlow:
    """The conversion code is consumed in memory and never written to HTTP logs."""
    def __init__(self, profile, *, manifest_factory=None):
        self.profile = validate(profile)
        self.manifest_factory = manifest_factory or app_manifest
        self.nonce = secrets.token_urlsafe(32)
        self.event = threading.Event()
        self.code = None
        self.server = None
        self.thread = None
        self.lock = threading.Lock()
        self.closed = False

    def _response(self, target, host):
        try:
            if len(target) > 4096 or not target.startswith('/') or target.startswith('//'):
                return 400, 'Malformed setup request.'
            parsed = urllib.parse.urlsplit(target)
            if parsed.scheme or parsed.netloc or parsed.fragment or host != '127.0.0.1:'+str(self.server.server_port):
                return 400, 'Malformed setup request.'
            if parsed.path == '/start/' + self.nonce and not parsed.query:
                with self.lock:
                    if self.closed or self.event.is_set():
                        return 409, 'This setup approval has already been consumed.'
                manifest = json.dumps(self.manifest_factory(self.profile, self.callback_url))
                action = 'https://github.com/organizations/' + self.profile['owner']['login'] + '/settings/apps/new'
                if self.profile['owner']['type']=='User':action='https://github.com/settings/apps/new'
                return 200, ('<!doctype html><meta charset="utf-8"><title>Runner Pool Setup</title>'
                    '<h1>Set up runner pools for ' + html.escape(self.profile['id']) + '</h1>'
                    '<p>Continue to GitHub to create the account-specific runner application.</p>'
                    '<form method="post" action="' + html.escape(action, quote=True) + '">'
                    '<input type="hidden" name="manifest" value="' + html.escape(manifest, quote=True) + '">'
                    '<button type="submit">Continue to GitHub</button></form>')
            if parsed.path == '/callback/' + self.nonce:
                values = urllib.parse.parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True, max_num_fields=4)
                codes = values.get('code', [])
                if set(values) != {'code'} or len(codes) != 1 or not re.fullmatch(r'[A-Za-z0-9_-]{1,200}', codes[0]):
                    return 400, 'Malformed application approval.'
                with self.lock:
                    if self.closed or self.event.is_set():
                        return 409, 'This setup approval has already been consumed.'
                    self.code = codes[0]
                    self.event.set()
                return 200, ('<!doctype html><title>Runner Pool Setup</title>'
                    '<h1>Application created</h1><p>Return to the setup Terminal. It will open GitHub installation approval next.</p>')
        except ValueError:
            return 400, 'Malformed setup request.'
        return 404, 'Unknown setup request.'

    def __enter__(self):
        require(self.server is None and not self.closed, 'Create a fresh setup approval flow when resuming.')
        flow = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                status, content = flow._response(self.path, self.headers.get('Host'))
                encoded = content.encode()
                self.send_response(status)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(encoded)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Security-Policy', "default-src 'none'; form-action https://github.com; frame-ancestors 'none'; base-uri 'none'")
                self.end_headers()
                try:
                    self.wfile.write(encoded)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        requested_port=os.environ.get('RUNNER_POOLS_APPROVAL_PORT')
        require(requested_port is None or (re.fullmatch(r'[1-9][0-9]{3,4}',requested_port)
                and 1024<=int(requested_port)<=65535),
                'RUNNER_POOLS_APPROVAL_PORT must be an unused local port from 1024 to 65535.')
        self.server = ThreadingHTTPServer(('127.0.0.1', int(requested_port) if requested_port else 0), Handler)
        self.base_url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.start_url = self.base_url + '/start/' + self.nonce
        self.callback_url = self.base_url + '/callback/' + self.nonce
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def wait(self, timeout=900):
        require(self.event.wait(timeout), 'GitHub application approval timed out. Rerun the same setup; installed state is preserved.')
        with self.lock:
            require(not self.closed and self.code is not None, 'Application approval ended before completion. Resume the same setup.')
            return self.code

    def __exit__(self, *args):
        with self.lock:
            self.closed = True
            self.code = None
            self.event.set()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)
