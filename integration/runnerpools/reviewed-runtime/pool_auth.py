"""Operator GitHub CLI and isolated, in-memory GitHub App authentication."""

import base64
from datetime import datetime
import json
import hashlib
import http.client
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from pool_config import Failure, require, validate

PERMISSIONS = {"organization_self_hosted_runners": "write", "contents": "read"}
API_VERSION = "2026-03-10"
LIMIT = 2 * 1024 * 1024


def permissions(profile=None):
    value = PERMISSIONS.copy()
    if profile and profile["owner"]["type"] == "User":
        value = {"administration": "write", "contents": "read"}
    if profile and profile.get("fleet"):
        value["actions"] = "read"
    return value


def _unique(pairs):
    value = {}
    for key, item in pairs:
        require(
            key not in value, "GitHub returned ambiguous JSON; response suppressed."
        )
        value[key] = item
    return value


def _decode(raw, *, array=False):
    try:
        require(
            len(raw) <= LIMIT,
            "GitHub response exceeds the supported size; response suppressed.",
        )
        value = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError()),
        )
    except (ValueError, UnicodeError, TypeError):
        raise Failure("GitHub returned invalid JSON; response suppressed.") from None
    require(
        isinstance(value, list) and all(isinstance(item, dict) for item in value)
        if array
        else isinstance(value, dict),
        "GitHub returned an unexpected JSON shape; response suppressed.",
    )
    return value


def _path(path):
    require(
        isinstance(path, str)
        and re.fullmatch(r"[A-Za-z0-9_./?=&-]+", path) is not None
        and not path.startswith("/")
        and path.count("?") <= 1,
        "Use a relative native GitHub API resource path.",
    )
    resource, _, query = path.partition("?")
    require(
        all(part and part not in (".", "..") for part in resource.split("/")),
        "GitHub API path contains an unsupported segment.",
    )
    if query:
        try:
            pairs = urllib.parse.parse_qsl(query, strict_parsing=True)
        except ValueError:
            raise Failure("GitHub API query is malformed.") from None
        require(
            len(pairs) == len({key for key, _ in pairs}),
            "GitHub query keys must be unique.",
        )
        for key, value in pairs:
            require(
                key in ("page", "per_page", "ref", "status", "affiliation")
                and bool(value),
                "Unsupported GitHub API query.",
            )
            if key == "affiliation":
                require(
                    resource == "user/repos" and value == "owner",
                    "Only owned repository inventory may be listed.",
                )
            if key == "status":
                require(
                    value in ("queued", "in_progress"),
                    "Only queued/running demand may be inspected.",
                )
            if key in ("page", "per_page"):
                require(
                    value.isdigit()
                    and int(value) > 0
                    and (key != "per_page" or int(value) <= 100),
                    "GitHub pagination must use positive bounded values.",
                )
    return resource


def _input(method, path, payload):
    require(
        method in ("GET", "POST", "PATCH", "PUT", "DELETE"),
        "Unsupported GitHub API method.",
    )
    _path(path)
    require(
        payload is None or isinstance(payload, dict),
        "GitHub API payload must be an object.",
    )
    try:
        return (
            None if payload is None else json.dumps(payload, allow_nan=False).encode()
        )
    except (ValueError, TypeError, OverflowError):
        raise Failure("GitHub API payload cannot be encoded.") from None


def _gh_environment():
    env = dict(os.environ)
    for key in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_DEBUG",
    ):
        env.pop(key, None)
    env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
    env["GH_PROMPT_DISABLED"] = "1"
    return env


def _headers(token=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "isolated-runner-pools",
    }
    if token is not None:
        require(
            isinstance(token, str)
            and re.fullmatch(r"[A-Za-z0-9_.-]+", token) is not None,
            "GitHub authentication material is malformed; value suppressed.",
        )
        headers["Authorization"] = "Bearer " + token
    return headers


API_ROOT = "https://api.github.com/"
REDIRECTS = 2
RETRY_AFTER_LIMIT = 30


def _rate_limited(status, headers):
    return status == 429 or (
        status == 403
        and (headers.get("Retry-After") or headers.get("x-ratelimit-remaining") == "0")
    )


def _retry_after(status, headers):
    """Seconds to wait before one retry of a short rate limit, or None."""
    value = headers.get("Retry-After", "")
    if (
        _rate_limited(status, headers)
        and value.isdigit()
        and int(value) <= RETRY_AFTER_LIMIT
    ):
        return int(value)
    return None


class OperatorReader:
    """Read-only GitHub API over the operator's gh login, held only in this process's memory.

    The token is read once from gh's own store, never written, logged, placed in a
    command line or returned; each worker thread reuses one HTTPS connection.
    """

    def __init__(self, token):
        require(isinstance(token, str), "GitHub authentication material is malformed.")
        self._headers = _headers(token)
        self._local, self._lock, self._open = threading.local(), threading.Lock(), []
        self._context = ssl.create_default_context()
        self.rate_limited = False

    def __repr__(self):
        return "OperatorReader(token suppressed)"

    def _connection(self):
        connection = getattr(self._local, "connection", None)
        if connection is None:
            # No proxy or redirect handling: requests reach api.github.com directly or fail.
            connection = http.client.HTTPSConnection(
                "api.github.com", timeout=60, context=self._context
            )
            self._local.connection = connection
            with self._lock:
                self._open.append(connection)
        return connection

    def _reset(self):
        connection = getattr(self._local, "connection", None)
        self._local.connection = None
        if connection is not None:
            with self._lock:
                self._open = [c for c in self._open if c is not connection]
            connection.close()

    def __call__(self, method, path, payload=None, *, array=False):
        _read_only(method, payload)
        _input(method, path, payload)
        # GitHub answers a renamed or transferred repository with a redirect to its
        # canonical API path; follow it only within api.github.com, as gh does.
        for _ in range(REDIRECTS + 1):
            status, headers, raw = self._get(path)
            location = headers.get("Location", "")
            if status not in (301, 302, 307, 308):
                break
            require(
                location.startswith(API_ROOT),
                "GitHub redirected outside its API; credentials were not forwarded.",
            )
            path = location[len(API_ROOT) :]
            _input(method, path, payload)
        else:
            raise Failure("GitHub redirected too many times; response suppressed.")
        if status != 200:
            if _rate_limited(status, headers):
                self.rate_limited = True
                raise Failure(
                    "GitHub rate limit reached; retry later. Response suppressed."
                )
            raise Failure(
                f"GitHub API operation failed (HTTP {status}); response suppressed."
            )
        return _decode(raw, array=array)

    def _get(self, path):
        for attempt in range(2):
            try:
                connection = self._connection()
                connection.request("GET", "/" + path, headers=self._headers)
                response = connection.getresponse()
                raw = response.read(LIMIT + 1)
                if len(raw) > LIMIT or response.will_close:
                    self._reset()
                wait = _retry_after(response.status, response.headers)
                if wait is not None and not attempt:
                    # GitHub asks clients to pause before retrying a secondary limit.
                    time.sleep(wait)
                    continue
                return response.status, response.headers, raw
            except (OSError, http.client.HTTPException):
                # A server-closed keep-alive connection is ordinary; reconnect once.
                self._reset()
                if attempt:
                    raise Failure(
                        "GitHub HTTPS operation unavailable; credentials and response suppressed."
                    ) from None
        return response.status, response.headers, raw

    def close(self):
        with self._lock:
            connections, self._open = self._open, []
        for connection in connections:
            connection.close()


def _read_only(method, payload):
    require(method == "GET" and payload is None, "The operator reader is read-only.")


def _read_only_gh_api(method, path, payload=None, *, array=False):
    _read_only(method, payload)
    return gh_api(method, path, payload, array=array)


def operator_reader():
    """A fast read-only API using the existing gh login; read-only gh calls when no token is available."""
    try:
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            env=_gh_environment(),
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        token = result.stdout.strip() if result.returncode == 0 else ""
        return OperatorReader(token) if token else _read_only_gh_api
    except (OSError, subprocess.SubprocessError, Failure):
        return _read_only_gh_api


def gh_api(method, path, payload=None, *, array=False):
    """Use the operator's native gh login; never a durable daemon credential."""
    data = _input(method, path, payload)
    argv = [
        "gh",
        "api",
        "--hostname",
        "github.com",
        "--method",
        method,
        "--header",
        "X-GitHub-Api-Version: " + API_VERSION,
    ]
    if data is not None:
        argv.extend(["--input", "-"])
    argv.append(path)
    env = _gh_environment()
    try:
        result = subprocess.run(
            argv,
            input=None if data is None else data.decode(),
            env=env,
            text=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        raise Failure(
            "Native GitHub authentication or API command unavailable; inspect gh login locally."
        ) from None
    if result.returncode != 0:
        code = re.search(r"\(HTTP ([0-9]{3})\)", (result.stderr or "")[-8192:])
        if code:
            raise Failure(
                "Native GitHub API operation failed (HTTP "
                + code[1]
                + "); response suppressed."
            )
        raise Failure(
            "Native GitHub API operation failed; output suppressed. Inspect gh login and requested permissions locally."
        )
    if method != "GET" and not array and not result.stdout.strip():
        return {}
    return _decode(result.stdout, array=array)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure("GitHub redirected the request; credentials were not forwarded.")


def _request(method, path, payload=None, token=None, *, array=False):
    data = _input(method, path, payload)
    headers = dict(_headers(token), **{"Content-Type": "application/json"})
    request = urllib.request.Request(
        "https://api.github.com/" + path, data=data, headers=headers, method=method
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=60) as response:
            require(
                response.geturl() == request.full_url,
                "GitHub response came from an unexpected URL.",
            )
            if response.status == 204:
                return {}
            return _decode(response.read(LIMIT + 1), array=array)
    except urllib.error.HTTPError as error:
        error.close()
        raise Failure(
            f"GitHub API operation failed (HTTP {error.code}); response suppressed."
        ) from None
    except (OSError, ValueError, urllib.error.URLError):
        raise Failure(
            "GitHub HTTPS operation unavailable; credentials and response suppressed."
        ) from None


def protected_key(state, *, metadata=None):
    """Inspect metadata only. OpenSSL alone reads the protected PEM contents."""
    state = Path(state)
    require(
        state.is_absolute() and ".." not in state.parts,
        "App state must be an absolute protected directory.",
    )
    key = state / "app.pem"
    inspect = metadata or (lambda path: path.lstat())
    try:
        for directory in (*reversed(state.parents), state):
            info = inspect(directory)
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == 0
                and not info.st_mode & 0o022,
                "App state ancestors must be root-owned directories without links or shared write access.",
            )
        info = inspect(key)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) in (0o400, 0o600),
            "App PEM must be a single root-owned private regular file with mode 0400 or 0600.",
        )
    except OSError:
        raise Failure(
            "Protected App PEM metadata unavailable; install it through the native administrator handoff."
        ) from None
    return key


def _identity(actual, expected):
    require(
        isinstance(actual, dict)
        and type(actual.get("id")) is int
        and all(actual.get(key) == expected[key] for key in ("login", "id", "type")),
        "GitHub App organization identity differs from the configured immutable owner.",
    )


LEVELS = {"read": 1, "write": 2, "admin": 3}


def _permissions(value, profile=None, *, exact=False):
    """Require each permission at its level or higher; a minted token must match exactly.

    A shared controller App and its installations hold the union of what every
    pool needs, so an organization pool sees broader grants (such as actions
    write) than its own minimum (actions read).
    """
    require(
        isinstance(value, dict),
        "GitHub App permissions are unavailable; response suppressed.",
    )
    required = permissions(profile)
    if exact:
        missing = [key for key, level in required.items() if value.get(key) != level]
    else:
        missing = [
            key
            for key, level in required.items()
            if LEVELS.get(value.get(key), 0) < LEVELS[level]
        ]
    require(
        not missing,
        "GitHub App needs "
        + ", ".join(key.replace("_", " ") + " " + required[key] for key in missing)
        + " permission"
        + ("s" if len(missing) > 1 else "")
        + ".",
    )


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _sign_jwt(client_id, state):
    require(
        isinstance(client_id, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", client_id),
        "GitHub App client ID is invalid.",
    )
    key = protected_key(state)
    now = int(time.time())
    header = _b64(
        json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    claims = _b64(
        json.dumps(
            {"iss": client_id, "iat": now - 60, "exp": now + 540}, separators=(",", ":")
        ).encode()
    )
    signing = (header + "." + claims).encode()
    try:
        result = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(key)],
            input=signing,
            capture_output=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        raise Failure(
            "GitHub App JWT signing unavailable; signing output suppressed."
        ) from None
    require(
        result.returncode == 0
        and isinstance(result.stdout, bytes)
        and bool(result.stdout),
        "GitHub App JWT signing failed; signing output suppressed.",
    )
    return signing.decode() + "." + _b64(result.stdout)


SHARED_STATE = Path("/private/var/db/runner-pools-controller")
SHARED_PUBLIC = Path("/Library/Application Support/RunnerPools/controller-app.json")


def controller_state(profile, state):
    return SHARED_STATE if "controller_app" in profile else Path(state)


def app_identity(app, profile, client_id):
    reference = profile.get("controller_app")
    if reference:
        require(
            reference["client_id"] == client_id
            and app.get("slug") == reference["slug"],
            "Shared controller App identity differs from the pinned registration.",
        )
    _identity(app.get("owner"), reference["owner"] if reference else profile["owner"])


def validate_installation_selection(profile, selection):
    """Accept the owner's App grant without broadening runtime repository tokens."""
    organization = profile["owner"]["type"] == "Organization"
    require(
        selection == "selected" or (organization and selection == "all"),
        "Choose All repositories or Only select repositories for this organization App."
        if organization
        else "Choose Only select repositories for this personal App.",
    )


def discover_installation(profile, state, client_id):
    """Discover a human-installed private App without any provisional installation ID."""
    p = validate(profile)
    if "github_app" in p:
        require(
            p["github_app"]["client_id"] == client_id,
            "Discovery client differs from the configured GitHub App.",
        )
    jwt = _sign_jwt(client_id, controller_state(p, state))
    app = _request("GET", "app", token=jwt)
    require(
        isinstance(app, dict)
        and type(app.get("id")) is int
        and app["id"] > 0
        and app.get("client_id") == client_id,
        "Signing key belongs to a different GitHub App.",
    )
    app_identity(app, p, client_id)
    _permissions(app.get("permissions"), p)
    found, seen = [], set()
    for page in range(1, 101):
        rows = _request(
            "GET", f"app/installations?per_page=100&page={page}", token=jwt, array=True
        )
        require(
            isinstance(rows, list)
            and len(rows) <= 100
            and all(isinstance(row, dict) for row in rows),
            "GitHub App installation list is malformed; response suppressed.",
        )
        for row in rows:
            require(
                type(row.get("id")) is int
                and row["id"] > 0
                and row["id"] not in seen
                and row.get("app_id") == app["id"]
                and isinstance(row.get("account"), dict),
                "GitHub App installation identity is duplicated or inconsistent.",
            )
            seen.add(row["id"])
            if row["account"].get("id") != p["owner"]["id"]:
                require(
                    "controller_app" in p,
                    "GitHub App organization identity differs from the configured immutable owner.",
                )
                continue
            _identity(row.get("account"), p["owner"])
            require(
                row.get("suspended_at") is None,
                "The selected GitHub App installation is suspended.",
            )
            _permissions(row.get("permissions"), p)
            validate_installation_selection(p, row.get("repository_selection"))
            found.append(row["id"])
            require(
                len(found) <= 1,
                "Multiple installations match the organization; preserve credentials and inspect.",
            )
        if len(rows) < 100:
            return (
                {"client_id": client_id, "installation_id": found[0]} if found else None
            )
    raise Failure("GitHub App installation pagination exceeds the supported bound.")


class GitHubApp:
    def __init__(self, profile, state):
        self.profile = validate(profile)
        require(
            "github_app" in self.profile,
            "Configure public GitHub App identifiers before starting the pool controller.",
        )
        self.state = controller_state(self.profile, state)
        protected_key(self.state)
        self._token = None
        self._expires = 0
        self._token_lock = threading.Lock()

    def _jwt(self):
        return _sign_jwt(self.profile["github_app"]["client_id"], self.state)

    def _refresh(self):
        # Clear an old token before any verification/request can fail.
        self._token, self._expires = None, 0
        jwt = self._jwt()
        app = _request("GET", "app", token=jwt)
        require(
            type(app.get("id")) is int
            and app["id"] > 0
            and app.get("client_id") == self.profile["github_app"]["client_id"],
            "Signing key belongs to a different GitHub App.",
        )
        app_identity(app, self.profile, self.profile["github_app"]["client_id"])
        _permissions(app.get("permissions"), self.profile)
        installation_id = self.profile["github_app"]["installation_id"]
        installation = _request(
            "GET", f"app/installations/{installation_id}", token=jwt
        )
        require(
            installation.get("id") == installation_id
            and installation.get("app_id") == app["id"]
            and installation.get("suspended_at") is None,
            "GitHub App installation identity or suspension state differs.",
        )
        _identity(installation.get("account"), self.profile["owner"])
        _permissions(installation.get("permissions"), self.profile)
        validate_installation_selection(
            self.profile, installation.get("repository_selection")
        )
        ids = sorted({consumer["id"] for consumer in self.profile["consumers"]})
        require(
            len(ids) <= 500,
            "Installation authentication supports at most 500 configured repositories.",
        )
        minted = _request(
            "POST",
            f"app/installations/{installation_id}/access_tokens",
            payload={"repository_ids": ids, "permissions": permissions(self.profile)},
            token=jwt,
        )
        _permissions(minted.get("permissions"), self.profile, exact=True)
        token = minted.get("token")
        require(
            isinstance(token, str)
            and re.fullmatch(r"[A-Za-z0-9_.-]+", token) is not None,
            "GitHub returned malformed installation authentication; value suppressed.",
        )
        try:
            expiry = datetime.fromisoformat(minted["expires_at"].replace("Z", "+00:00"))
            require(
                expiry.tzinfo is not None,
                "GitHub installation expiry needs a timezone.",
            )
            expires = expiry.timestamp()
        except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
            raise Failure(
                "GitHub installation authentication expiry is invalid; value suppressed."
            ) from None
        now = time.time()
        require(
            now + 120 < expires <= now + 3660,
            "GitHub installation authentication must expire within one hour.",
        )
        self._token, self._expires = token, expires - 60

    def _allowed(self, method, path, payload):
        resource = _path(path)
        owner = re.escape(self.profile["owner"]["login"])
        root = f"orgs/{owner}/actions/"
        allowed = (
            method == "GET" and resource == "orgs/" + self.profile["owner"]["login"]
        )
        if self.profile["owner"]["type"] == "User":
            allowed = (
                method == "GET"
                and resource == "users/" + self.profile["owner"]["login"]
            )
        if re.fullmatch(root + r"runner-groups(?:/[1-9][0-9]*)?", resource):
            allowed = method in ("GET", "POST", "PATCH")
        if re.fullmatch(
            root + r"runner-groups/[1-9][0-9]*/(?:repositories|runners)", resource
        ):
            allowed = method in ("GET", "PUT")
        match = re.fullmatch(
            root + r"runner-groups/[1-9][0-9]*/repositories/([1-9][0-9]*)", resource
        )
        if match:
            allowed = method in ("PUT", "DELETE") and int(match.group(1)) in {
                c["id"] for c in self.profile["consumers"]
            }
        if re.fullmatch(root + r"runners(?:/[1-9][0-9]*)?", resource):
            allowed = method in ("GET", "DELETE") and (
                method != "DELETE" or resource.rsplit("/", 1)[1].isdigit()
            )
        if (
            resource
            == f"orgs/{self.profile['owner']['login']}/actions/runners/generate-jitconfig"
        ):
            allowed = method == "POST"
        if self.profile["owner"]["type"] == "User":
            # Personal credentials must never reach organization runner APIs.
            allowed = (
                method == "GET"
                and resource == "users/" + self.profile["owner"]["login"]
            )
            for consumer in self.profile["consumers"]:
                root = "repos/" + re.escape(consumer["repo"]) + "/actions/runners"
                if re.fullmatch(root, resource):
                    allowed = method == "GET"
                if re.fullmatch(root + "/[1-9][0-9]*", resource):
                    allowed = method in ("GET", "DELETE")
                if (
                    resource
                    == "repos/"
                    + consumer["repo"]
                    + "/actions/runners/generate-jitconfig"
                ):
                    allowed = method == "POST"
        for consumer in self.profile["consumers"]:
            if resource in (
                "repos/" + consumer["repo"],
                "repos/" + consumer["repo"] + "/contents/" + consumer["workflow"],
            ):
                allowed = method == "GET"
        if self.profile.get("fleet") and method == "GET":
            for consumer in self.profile["consumers"]:
                base = "repos/" + re.escape(consumer["repo"]) + "/actions/runs"
                if re.fullmatch(
                    base + r"(?:/[1-9][0-9]*/attempts/[1-9][0-9]*/jobs)?", resource
                ):
                    allowed = True
        require(
            allowed,
            "GitHub App resource is outside the configured organization/consumers or supported runner operations.",
        )
        if payload:
            ids = {c["id"] for c in self.profile["consumers"]}
            for field in ("repository_ids", "selected_repository_ids"):
                if field in payload:
                    require(
                        isinstance(payload[field], list)
                        and all(type(i) is int and i in ids for i in payload[field]),
                        "Runner group payload selects an unconfigured repository.",
                    )
            if "selected_workflows" in payload:
                refs = {
                    c["repo"] + "/" + c["workflow"] + "@refs/heads/main"
                    for c in self.profile["consumers"]
                }
                require(
                    isinstance(payload["selected_workflows"], list)
                    and all(
                        isinstance(ref, str) and ref in refs
                        for ref in payload["selected_workflows"]
                    ),
                    "Runner group payload selects an unconfigured workflow.",
                )

    def api(self, method, path, payload=None):
        _input(method, path, payload)
        self._allowed(method, path, payload)
        with self._token_lock:
            if self._token is None or time.time() >= self._expires:
                self._refresh()
            token = self._token
        try:
            return _request(method, path, payload=payload, token=token)
        except Failure:
            # Refresh identity on the next caller-controlled attempt, but never
            # replay a write whose remote completion could be ambiguous.
            with self._token_lock:
                if self._token == token:
                    self._token, self._expires = None, 0
            raise


def app_manifest(profile, redirect_url):
    p = validate(profile)
    require(
        isinstance(redirect_url, str)
        and len(redirect_url) <= 2048
        and all(ord(char) > 32 and ord(char) != 127 for char in redirect_url),
        "App redirect must be a literal URL without control characters.",
    )
    try:
        url = urllib.parse.urlsplit(redirect_url)
        port = url.port
    except ValueError:
        raise Failure("App redirect URL is malformed.") from None
    require(
        not url.username
        and not url.password
        and not url.fragment
        and (
            url.scheme == "https"
            and bool(url.hostname)
            or url.scheme == "http"
            and url.hostname == "127.0.0.1"
            and port is not None
        ),
        "App redirect must use HTTPS or an explicit loopback callback port.",
    )
    home = "https://github.com/" + p["owner"]["login"]
    # GitHub limits globally unique App names to 34 characters. Bind the
    # readable namespace to the immutable organization identity without truncation
    # collisions or an organization-length-dependent setup failure.
    identity = str(p["owner"]["id"]) + "/" + p["id"]
    if p.get("fleet"):
        identity += "/" + p["fleet"]["host_id"]
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:12]
    name = p["id"][:12] + "-runners-" + suffix
    return {
        "name": name,
        "url": home,
        "redirect_url": redirect_url,
        "public": False,
        "hook_attributes": {"url": home, "active": False},
        "default_permissions": permissions(p),
        "default_events": [],
    }


def exchange_manifest(code, profile):
    p = validate(profile)
    require(
        isinstance(code, str)
        and re.fullmatch(r"[A-Za-z0-9_-]{1,200}", code) is not None,
        "GitHub App manifest conversion code is invalid; value suppressed.",
    )
    value = _request("POST", "app-manifests/" + code + "/conversions")
    _identity(value.get("owner"), p["owner"])
    _permissions(value.get("permissions"), p)
    require(
        type(value.get("id")) is int
        and value["id"] > 0
        and isinstance(value.get("client_id"), str)
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value["client_id"])
        and isinstance(value.get("pem"), str)
        and value["pem"].startswith(
            ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")
        ),
        "GitHub App conversion returned incomplete identity/key material; response suppressed.",
    )
    if "github_app" in p:
        require(
            value["client_id"] == p["github_app"]["client_id"],
            "Converted GitHub App differs from the configured client identity.",
        )
    return {
        "app_id": value["id"],
        "client_id": value["client_id"],
        "pem": value["pem"],
        "slug": value.get("slug"),
    }
