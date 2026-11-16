"""Trusted root provisioning for disposable arm64 CI guests. No provider credentials."""

import base64
import re
import shlex

from pool_config import Failure, TOOLCHAINS

NODE = "24.22.0"
PYTHON = "3.14.8"
NODE_SHA = {
    "linux": "fef00bb4d36e1c50104a9775a10359beee98f162b4104dd12472c75065c6a143",
    "macos": "6a9724d9b50a5f22b4816cded441b5a8d9ddae546191a5e5b7efa5a5e2ee26d5",
}
PYTHON_SHA = {
    "linux": "c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73",
    "macos": "507fc086c5c006ff875d344a75b4e67b8fb3c401f1bc4908c6250adb673d4907",
}

# Android (macOS). Temurin 17 matches the JDK that Studio workflows request.
# Every archive is pinned by SHA-256 from its publisher: Adoptium's release API
# and the checksum table on https://developer.android.com/studio.
JDK_RELEASE = "17.0.21+9"
JDK_ARCHIVE = "OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.21_9.tar.gz"
JDK_URL = (
    "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/"
    + JDK_ARCHIVE
)
JDK_SHA = "78b08c7f5a0598242d5719c022e19479cb4a3aa45c37c19726a757a469ed1c15"
ANDROID_TOOLS_ARCHIVE = "commandlinetools-mac_arm64-15859902_latest.zip"
ANDROID_TOOLS_SHA = "835b62a26162b229b441d1f6d4680383815a270809eb33522c0d480fa5002c4e"
# sdkmanager verifies each package against the SHA-1 in Google's HTTPS repository manifest.
ANDROID_PACKAGES = ("platform-tools", "platforms;android-37.0", "build-tools;37.0.0")
ANDROID_BUILD_TOOLS = "37.0.0"
JDK_HOME = "/opt/runner-pool/jdk/Contents/Home"

# Docker (Linux). Official Docker apt packages for Ubuntu 24.04 arm64; the repository
# key is pinned by the SHA-256 of https://download.docker.com/linux/ubuntu/gpg.
DOCKER_KEY_SHA = "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570"
DOCKER_PACKAGES = (
    "docker-ce=5:29.9.2-1~ubuntu.24.04~noble",
    "docker-ce-cli=5:29.9.2-1~ubuntu.24.04~noble",
    "docker-ce-rootless-extras=5:29.9.2-1~ubuntu.24.04~noble",
    "docker-buildx-plugin=0.38.1-1~ubuntu.24.04~noble",
    "containerd.io=2.4.2-3~ubuntu.24.04~noble",
)
DOCKER_RUN = "/run/runner-pool-docker"
DOCKER_SERVICE = "runner-pool-docker.service"


def _file(path, text, mode="0755"):
    # All paths and modes below are fixed trusted constants; base64 avoids heredoc injection.
    encoded = base64.b64encode(text.encode()).decode()
    return f"printf '%s' '{encoded}' | /usr/bin/openssl base64 -d -A > {path}\nchmod {mode} {path}\nchown root {path}\n"


def _toolchains(platform, toolchains):
    selected = tuple(toolchains)
    if (
        platform not in ("linux", "macos")
        or len(set(selected)) != len(selected)
        or not set(selected) <= set(TOOLCHAINS[platform])
    ):
        raise Failure(
            "Guest toolchains must be unique reviewed names for this platform."
        )
    return selected


def _docker_unit():
    return f"""[Unit]
Description=Rootless Docker for the unprivileged CI build account
After=network-online.target binfmt-support.service
Wants=network-online.target

[Service]
Type=simple
User=ci-build
Environment=HOME=/home/ci-build
Environment=XDG_RUNTIME_DIR={DOCKER_RUN}
Environment=PATH=/usr/bin:/bin:/usr/sbin:/sbin
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=builtin
RuntimeDirectory=runner-pool-docker
RuntimeDirectoryMode=0700
Delegate=cpu cpuset io memory pids
ExecStart=/usr/bin/dockerd-rootless.sh --host=unix://{DOCKER_RUN}/docker.sock
Restart=on-failure
TimeoutStartSec=120
"""


_ROOTLESSKIT_PROFILE = """abi <abi/4.0>,
include <tunables/global>
/usr/bin/rootlesskit flags=(unconfined) {
  userns,
  include if exists <local/usr.bin.rootlesskit>
}
"""


def _toolchain_install(platform, toolchains):
    """Root-only installs of reviewed toolchains; credentials never enter the guest."""
    source = ""
    if "android" in toolchains:
        guest_home = "/Users/ci-build"
        sdk = guest_home + "/android-sdk"
        packages = " ".join('"' + name + '"' for name in ANDROID_PACKAGES)
        source += f"""# Android: Temurin JDK is root-owned; the SDK belongs to the build account so Gradle can add components.
curl --fail --location --proto '=https' --tlsv1.2 {JDK_URL} -o jdk.archive
printf '%s  %s\\n' {JDK_SHA} jdk.archive | shasum -a 256 -c -
mkdir -p /opt/runner-pool/jdk
tar -xzf jdk.archive --strip-components=1 --no-same-owner -C /opt/runner-pool/jdk
chown -R root /opt/runner-pool/jdk
chmod -R a+rX,go-w /opt/runner-pool/jdk
[ -x {JDK_HOME}/bin/java ]
curl --fail --location --proto '=https' --tlsv1.2 https://dl.google.com/android/repository/{ANDROID_TOOLS_ARCHIVE} -o android-tools.zip
printf '%s  %s\\n' {ANDROID_TOOLS_SHA} android-tools.zip | shasum -a 256 -c -
mkdir -p {sdk}/cmdline-tools
/usr/bin/unzip -q android-tools.zip -d android-tools
mv android-tools/cmdline-tools {sdk}/cmdline-tools/latest
chown -R ci-build {sdk}
chmod -R go-w {sdk}
# The build account installs, so downloaded packages are never parsed or written as root.
sudo -n -u ci-build /usr/bin/env -i HOME={guest_home} USER=ci-build LOGNAME=ci-build JAVA_HOME={JDK_HOME} \\
  ANDROID_HOME={sdk} PATH={JDK_HOME}/bin:/usr/bin:/bin:/usr/sbin:/sbin /bin/bash -s <<'ANDROID_SDK_INSTALL'
set -euo pipefail
{{ yes || true; }} | {sdk}/cmdline-tools/latest/bin/sdkmanager --sdk_root={sdk} --licenses >/dev/null
{sdk}/cmdline-tools/latest/bin/sdkmanager --sdk_root={sdk} {packages} </dev/null
ANDROID_SDK_INSTALL
"""
    if "browser" in toolchains:
        # Ubuntu 24.04 Chromium dependencies from Playwright's nativeDeps.ts.
        # NSS resolves reserved *.localhost names without product-specific aliases.
        source += """apt-get install -y libnss-myhostname fonts-liberation fonts-noto-color-emoji libfontconfig1 libfreetype6 libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64 libatspi2.0-0t64 libcairo2 libcups2t64 libdbus-1-3 libdrm2 libgbm1 libglib2.0-0t64 libnspr4 libnss3 libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 libxkbcommon0 libxrandr2
# Keep existing NSS services and make wildcard localhost resolution explicit.
sed -i '/^hosts:/ { /myhostname/! s/$/ myhostname/; }' /etc/nsswitch.conf
getent ahostsv4 runner-pool.localhost | grep -q '^127[.]0[.]0[.]1 '
"""
    if "docker" in toolchains:
        packages = " ".join(shlex.quote(name) for name in DOCKER_PACKAGES)
        source += f"""# Docker: rootless daemon owned by the build account, plus QEMU for linux/amd64 builds on ARM64.
. /etc/os-release
[ "$VERSION_CODENAME" = noble ]
install -d -m 0755 /etc/apt/keyrings
curl --fail --location --proto '=https' --tlsv1.2 https://download.docker.com/linux/ubuntu/gpg -o docker.asc
printf '%s  %s\\n' {DOCKER_KEY_SHA} docker.asc | shasum -a 256 -c -
install -m 0644 docker.asc /etc/apt/keyrings/docker.asc
printf '%s\\n' 'Types: deb' 'URIs: https://download.docker.com/linux/ubuntu' 'Suites: noble' 'Components: stable' 'Architectures: arm64' 'Signed-By: /etc/apt/keyrings/docker.asc' > /etc/apt/sources.list.d/docker.sources
apt-get update
apt-get install -y uidmap slirp4netns qemu-user-static binfmt-support
update-binfmts --enable qemu-x86_64
apt-get install -y {packages}
# No root daemon, socket or group may exist: jobs reach only the build account's own daemon.
systemctl disable --now docker.service docker.socket containerd.service
systemctl mask docker.service docker.socket containerd.service
getent group docker >/dev/null && groupdel docker || true
grep -q '^ci-build:' /etc/subuid || usermod --add-subuids 200000-265535 ci-build
grep -q '^ci-build:' /etc/subgid || usermod --add-subgids 200000-265535 ci-build
{_file("/etc/apparmor.d/usr.bin.rootlesskit", _ROOTLESSKIT_PROFILE, "0644")}if [ -d /sys/kernel/security/apparmor ]; then apparmor_parser -r /etc/apparmor.d/usr.bin.rootlesskit; fi
{_file("/etc/systemd/system/" + DOCKER_SERVICE, _docker_unit(), "0644")}systemctl daemon-reload
systemctl enable {DOCKER_SERVICE}
"""
    return source


def _toolchain_environment(platform, toolchains):
    """Job environment additions as a Python dict-literal fragment and a PATH prefix."""
    entries, path = "", ""
    if "android" in toolchains:
        sdk = "/Users/ci-build/android-sdk"
        entries += f"       'JAVA_HOME': {JDK_HOME!r}, 'ANDROID_HOME': {sdk!r}, 'ANDROID_SDK_ROOT': {sdk!r},\n"
        path = f"{JDK_HOME}/bin:{sdk}/cmdline-tools/latest/bin:{sdk}/platform-tools:"
    if "docker" in toolchains:
        entries += f"       'DOCKER_HOST': 'unix://{DOCKER_RUN}/docker.sock',\n"
    return entries, path


def _toolchain_wait(toolchains):
    """The rootless daemon starts as the build account before the job begins."""
    if "docker" not in toolchains:
        return ""
    return f"""subprocess.run(['/usr/bin/systemctl', 'start', {DOCKER_SERVICE!r}], check=True, timeout=120)
deadline = time.monotonic() + 90
while True:
    probe = socket.socket(socket.AF_UNIX)
    try:
        probe.connect('{DOCKER_RUN}/docker.sock')
        break
    except OSError:
        if time.monotonic() > deadline:
            raise SystemExit(75)
        time.sleep(1)
    finally:
        probe.close()
"""


def _toolchain_check(platform, toolchains):
    """Fail base preparation unless the build account can really run each toolchain."""
    source = ""
    if "android" in toolchains:
        sdk = "/Users/ci-build/android-sdk"
        run = f"sudo -n -u ci-build /usr/bin/env JAVA_HOME={JDK_HOME} ANDROID_HOME={sdk} PATH={JDK_HOME}/bin:/usr/bin:/bin"
        source += f"""{run} {JDK_HOME}/bin/java -version
{run} {sdk}/cmdline-tools/latest/bin/sdkmanager --sdk_root={sdk} --list_installed
{run} {sdk}/build-tools/{ANDROID_BUILD_TOOLS}/aapt2 version
[ "$(/usr/bin/stat -f %Su {sdk})" = ci-build ]
sudo -n -u ci-build /bin/test ! -w {JDK_HOME}/bin/java
"""
    if "docker" in toolchains:
        source += f"""grep -q '^ci-build:' /etc/subuid
grep -q '^ci-build:' /etc/subgid
[ "$(systemctl is-enabled {DOCKER_SERVICE})" = enabled ]
[ "$(systemctl is-enabled docker.service)" = masked ]
[ "$(systemctl is-enabled docker.socket)" = masked ]
sudo -n -u ci-build /usr/bin/docker --version
sudo -n -u ci-build /usr/bin/docker buildx version
[ -e /proc/sys/fs/binfmt_misc/qemu-x86_64 ]
"""
    return source


def _mac_build_group():
    return """# Dedicated build group removes the upstream staff default from sysadminctl.
if ! /usr/bin/dscl . -read /Groups/ci-build >/dev/null 2>&1; then
  /usr/bin/dscl . -create /Groups/ci-build
  /usr/bin/dscl . -create /Groups/ci-build PrimaryGroupID 503
  /usr/bin/dscl . -create /Groups/ci-build Password '*'
fi
[ "$(/usr/bin/dscl . -read /Groups/ci-build PrimaryGroupID | /usr/bin/awk '{print $2}')" = 503 ]
/usr/bin/dscl . -create /Users/ci-build PrimaryGroupID 503
/usr/sbin/dseditgroup -o edit -d ci-build -t user staff || true
chown -R ci-build:ci-build /Users/ci-build
"""


def script(
    platform, management_public_key, runner_version, runner_digest, toolchains=()
):
    if (
        platform not in ("linux", "macos")
        or not re.fullmatch(
            r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [A-Za-z0-9@._-]+)?", management_public_key
        )
        or not re.fullmatch(r"\d+\.\d+\.\d+", runner_version)
        or not re.fullmatch(r"[0-9a-f]{64}", runner_digest)
    ):
        raise Failure(
            "Guest preparation requires a supported platform, one Ed25519 public key and pinned runner release."
        )
    toolchains = _toolchains(platform, toolchains)
    guest_home = "/home/ci-build" if platform == "linux" else "/Users/ci-build"
    management_home = "/home/ci-manager" if platform == "linux" else "/Users/ci-manager"
    node_os = "linux" if platform == "linux" else "darwin"
    node_extension = "tar.xz" if platform == "linux" else "tar.gz"
    runner_os = "linux" if platform == "linux" else "osx"
    source = """#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
unset SSH_AUTH_SOCK GITHUB_TOKEN GH_TOKEN ACTIONS_RUNNER_INPUT_TOKEN
[ "$(id -u)" = 0 ]
[ "$(uname -m)" = arm64 ] || [ "$(uname -m)" = aarch64 ]
for path in /opt/runner-pool /usr/local/libexec; do
  [ ! -L "$path" ]
  mkdir -p "$path"
  chown root "$path"
  chmod 0755 "$path"
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
"""
    if platform == "linux":
        source += """export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git jq xz-utils build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev libncurses-dev uuid-dev tk-dev sudo openssh-server perl openssl
useradd --create-home --home-dir /home/ci-manager --shell /bin/bash ci-manager
useradd --create-home --home-dir /home/ci-build --shell /usr/sbin/nologin ci-build
passwd --lock ci-build
passwd --lock ci-manager
passwd --lock admin
usermod --shell /usr/sbin/nologin admin
# Remove inherited privileged group membership and keys from upstream job-inaccessible accounts.
gpasswd -d admin sudo || [ "$(id -nG admin)" != sudo ]
rm -f /home/admin/.ssh/authorized_keys /root/.ssh/authorized_keys
"""
    else:
        source += """# Upstream admin is only used for initial Tart guest-agent provisioning.
# A random unrecorded password removes its public upstream password.
/usr/sbin/sysadminctl -addUser ci-manager -fullName 'CI Management' -UID 502 -home /Users/ci-manager -shell /bin/bash -password "$(/usr/bin/openssl rand -hex 48)"
/usr/sbin/sysadminctl -addUser ci-build -fullName 'CI Build' -UID 503 -home /Users/ci-build -shell /usr/bin/false -password "$(/usr/bin/openssl rand -hex 48)"
/usr/sbin/sysadminctl -resetPasswordFor admin -newPassword "$(/usr/bin/openssl rand -hex 48)"
/usr/bin/dscl . -create /Users/ci-build AuthenticationAuthority ';DisabledUser;'
/usr/bin/dscl . -create /Users/ci-build UserShell /usr/bin/false
/usr/sbin/dseditgroup -o edit -d ci-build -t user admin || true
/usr/sbin/dseditgroup -o edit -d ci-manager -t user admin || true
/usr/bin/defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser || true
rm -f /etc/kcpassword /Users/admin/.ssh/authorized_keys /var/root/.ssh/authorized_keys
# Remote Login may use a macOS access-control group; enroll only management.
/usr/sbin/dseditgroup -o edit -a ci-manager -t user com.apple.access_ssh
# Keep agent-only bootstrap repair until management SSH is proven; finalization
# removes upstream sudo and disables the guest agent before sealing this base.
/usr/bin/dscl . -create /Users/admin UserShell /usr/bin/false
"""
    if platform == "macos":
        source += _mac_build_group()
    source += f"""mkdir -p {management_home}/.ssh {guest_home}
chmod 0700 {management_home} {management_home}/.ssh {guest_home}
printf '%s\\n' {shlex.quote(management_public_key)} > {management_home}/.ssh/authorized_keys
chmod 0600 {management_home}/.ssh/authorized_keys
chown -R ci-manager {management_home}
chown -R ci-build {guest_home}
printf '%s\\n' 'ci-manager ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/runner-pool-management
chmod 0440 /etc/sudoers.d/runner-pool-management
visudo -cf /etc/sudoers
mkdir -p /etc/ssh/sshd_config.d
printf '%s\\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin no' 'AllowUsers ci-manager' 'AllowAgentForwarding no' 'AllowTcpForwarding no' 'X11Forwarding no' > /etc/ssh/sshd_config.d/00-runner-pool.conf
# Install pinned official Node archive in a root-owned path.
curl --fail --location --proto '=https' --tlsv1.2 https://nodejs.org/dist/v{NODE}/node-v{NODE}-{node_os}-arm64.{node_extension} -o node.archive
printf '%s  %s\\n' {NODE_SHA[platform]} node.archive | shasum -a 256 -c -
mkdir -p /opt/runner-pool/node
tar -xf node.archive --strip-components=1 -C /opt/runner-pool/node
"""
    if platform == "linux":
        source += f"""curl --fail --location --proto '=https' --tlsv1.2 https://www.python.org/ftp/python/{PYTHON}/Python-{PYTHON}.tar.xz -o python.archive
printf '%s  %s\\n' {PYTHON_SHA[platform]} python.archive | shasum -a 256 -c -
tar -xf python.archive
cd Python-{PYTHON}
./configure --prefix=/opt/runner-pool/python --with-ensurepip=install
make -j 4
make install
cd "$work"
export PATH=/opt/runner-pool/node/bin:$PATH
npx --yes playwright@1.64.1 install-deps
"""
    else:
        source += f"""curl --fail --location --proto '=https' --tlsv1.2 https://www.python.org/ftp/python/{PYTHON}/python-{PYTHON}-macos11.pkg -o python.pkg
printf '%s  %s\\n' {PYTHON_SHA[platform]} python.pkg | shasum -a 256 -c -
/usr/sbin/installer -pkg python.pkg -target /
mkdir -p /opt/runner-pool/python/bin
ln -s /Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 /opt/runner-pool/python/bin/python3
"""
    source += _toolchain_install(platform, toolchains)
    source += f"""curl --fail --location --proto '=https' --tlsv1.2 https://github.com/actions/runner/releases/download/v{runner_version}/actions-runner-{runner_os}-arm64-{runner_version}.tar.gz -o runner.tar.gz
printf '%s  %s\\n' {runner_digest} runner.tar.gz | shasum -a 256 -c -
mkdir /opt/runner-pool/runner
tar -xzf runner.tar.gz -C /opt/runner-pool/runner
chmod -R a+rX,go-w /opt/runner-pool
chown -R root /opt/runner-pool
"""
    if platform == "linux":
        source += "/opt/runner-pool/runner/bin/installdependencies.sh\nsystemctl disable --now ssh.socket\nsystemctl enable --now ssh.service\n"
    return source + _helpers(platform, toolchains)


def _helpers(platform, toolchains=()):
    guest_home = "/home/ci-build" if platform == "linux" else "/Users/ci-build"
    source = ""
    # The management host sends only JIT configuration to this root-owned helper.
    extra_env, path_prefix = _toolchain_environment(platform, toolchains)
    waiting = _toolchain_wait(toolchains)
    imports = "import os, pathlib, pwd, shutil, subprocess, sys" + (
        ", socket, time" if waiting else ""
    )
    job = f"""#!/opt/runner-pool/python/bin/python3
{imports}
if os.geteuid() != 0:
    raise SystemExit(77)
user = pwd.getpwnam('ci-build')
jit = sys.stdin.readline(1048577).strip()
if not jit or len(jit) > 1048576 or not all(c.isalnum() or c in '+/=_-' for c in jit):
    raise SystemExit(65)
home = pathlib.Path({guest_home!r})
runner = home / 'actions-runner'
if runner.exists():
    raise SystemExit(73)
tool_cache = home / 'tool-cache'
tool_cache.mkdir(mode=0o700)
os.chown(tool_cache, user.pw_uid, user.pw_gid)
shutil.copytree('/opt/runner-pool/runner', runner)
for path in [runner, *runner.rglob('*')]:
    if not path.is_symlink():
        os.chown(path, user.pw_uid, user.pw_gid)
{waiting}# Never retain management authorization or inherited provider environment in a job.
env = {{'HOME': str(home), 'USER': 'ci-build', 'LOGNAME': 'ci-build',
{extra_env}       'PATH': '{path_prefix}/opt/runner-pool/python/bin:/opt/runner-pool/node/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
       'CI': 'true', 'RUNNER_TOOL_CACHE': str(tool_cache), 'AGENT_TOOLSDIRECTORY': str(tool_cache)}}
os.initgroups('ci-build', user.pw_gid)
os.setgid(user.pw_gid)
os.setuid(user.pw_uid)
os.chdir(runner)
os.execve(str(runner / 'run.sh'), [str(runner / 'run.sh'), '--jitconfig', jit], env)
"""
    source += _file("/usr/local/libexec/runner-pool-job", job)
    generation = r"""#!/opt/runner-pool/python/bin/python3
import json, os, re, stat, sys
if os.geteuid() != 0:
    raise SystemExit(77)
value = json.loads(sys.stdin.read(4097))
if (not isinstance(value, dict) or set(value) != {'profile', 'platform', 'generation'} or
    not re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', value.get('profile', '')) or
    len(value['profile']) > 20 or value.get('platform') not in ('linux', 'macos') or
    not re.fullmatch(r'[0-9a-f]{32}', value.get('generation', ''))):
    raise SystemExit(65)
fd = os.open('/etc/runner-pool-generation.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
with os.fdopen(fd, 'w') as stream:
    json.dump(value, stream, sort_keys=True)
    stream.flush()
    os.fsync(stream.fileno())
"""
    source += _file("/usr/local/libexec/runner-pool-generation", generation)
    # This check runs before every generation is exposed to provider scheduling.
    # Reviewed deploy and inspection jobs parse provider JSON with jq.
    tools = "command -v jq >/dev/null\n" if platform == "linux" else ""
    check = f"""#!/bin/bash
set -euo pipefail
[ "$(id -u)" = 0 ]
[ "$(id -un ci-build)" = ci-build ]
for group in $(id -Gn ci-build); do
  case "$group" in admin|staff|sudo|wheel|root|docker|lxd|_developer) exit 1;; esac
done
if sudo -n -u ci-build sudo -n true 2>/dev/null; then exit 1; fi
[ ! -e {guest_home}/.ssh ]
[ ! -e {guest_home}/.aws ]
[ ! -e {guest_home}/.config/gcloud ]
[ ! -e {guest_home}/actions-runner ]
[ ! -S /tmp/ssh-agent.socket ]
! mount | /usr/bin/grep -E 'virtiofs|My Shared Files|com.apple.virtio-fs'
[ "$(sudo -n -u ci-build /opt/runner-pool/node/bin/node --version)" = v{NODE} ]
[ "$(sudo -n -u ci-build /opt/runner-pool/python/bin/python3 --version)" = 'Python {PYTHON}' ]
{tools}{_toolchain_check(platform, toolchains)}sudo -n -u ci-build /bin/test ! -w /opt/runner-pool/runner
sudo -n -u ci-build /bin/test ! -w /usr/local/libexec/runner-pool-job
/usr/sbin/sshd -T | /usr/bin/grep -x "passwordauthentication no" >/dev/null
/usr/sbin/sshd -T | /usr/bin/grep -x "allowagentforwarding no" >/dev/null
printf '%s\\n' POOL_READY
"""
    source += _file("/usr/local/libexec/runner-pool-check", check)
    source += "/usr/local/libexec/runner-pool-check\n"
    return source


def finalize(platform, toolchains=()):
    """Idempotent final hardening over management SSH; no guest-agent dependency after this."""
    if platform not in ("linux", "macos"):
        raise Failure("Unknown guest hardening platform.")
    toolchains = _toolchains(platform, toolchains)
    management_home = "/home/ci-manager" if platform == "linux" else "/Users/ci-manager"
    source = """#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
[ "$(id -u)" = 0 ]
"""
    if platform == "linux":
        source += """systemctl disable --now tart-guest-agent.service
if [ -f /etc/systemd/system/tart-guest-agent.service ] && [ ! -L /etc/systemd/system/tart-guest-agent.service ]; then
  mv /etc/systemd/system/tart-guest-agent.service /opt/runner-pool/tart-guest-agent.service.disabled
fi
systemctl mask tart-guest-agent.service
systemctl daemon-reload
! systemctl is-active --quiet tart-guest-agent.service
! pgrep -f '^(/[^ ]*/)?tart-guest-agent([ ]|$)'
"""
    else:
        source += _mac_build_group()
        source += """# Management SSH has already been verified. Retain only its privileged policy.
find /etc/sudoers.d -type f ! -name runner-pool-management -delete
/usr/bin/sed -i '' '/NOPASSWD/d' /etc/sudoers
visudo -cf /etc/sudoers
for label in org.cirruslabs.tart-guest-agent org.cirruslabs.tart-guest-daemon; do
  /bin/launchctl disable system/$label
  /bin/launchctl disable gui/501/$label || true
  /bin/launchctl bootout system/$label || true
  /bin/launchctl bootout gui/501/$label || true
done
for path in /Library/LaunchAgents/tart-guest-agent.plist /Library/LaunchDaemons/tart-guest-daemon.plist /Library/LaunchAgents/org.cirruslabs.tart-guest-agent.plist /Library/LaunchDaemons/org.cirruslabs.tart-guest-daemon.plist; do
  rm -f "$path"
done
/usr/bin/pkill -f '^(/[^ ]*/)?tart-guest-agent([ ]|$)' || true
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  /usr/bin/pgrep -f '^(/[^ ]*/)?tart-guest-agent([ ]|$)' >/dev/null || break
  sleep 1
done
! /usr/bin/pgrep -f '^(/[^ ]*/)?tart-guest-agent([ ]|$)'
for path in /Library/LaunchAgents /Library/LaunchDaemons /opt/homebrew/bin /Users/admin/Library/LaunchAgents; do
  if [ -e "$path" ]; then sudo -n -u ci-build /bin/test ! -w "$path"; fi
done
"""
    source += "chmod -R a+rX,go-w /opt/runner-pool\n"
    source += _helpers(platform, toolchains)
    source += f"""sudo -n -u ci-build /bin/test ! -x {management_home}
sudo -n -u ci-build /bin/test ! -w /opt/runner-pool
sudo -n -u ci-build /bin/test ! -w /usr/local/libexec/runner-pool-job
/usr/local/libexec/runner-pool-check
"""
    return source
