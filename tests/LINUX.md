# Linux verification

The native Linux entry point is `bash tests/linux.sh`. It requires Python 3,
Bash, Git, procps (`ps`), lsof, zsh and ShellCheck. The script checks shell syntax,
installation/uninstallation in disposable homes, and the full Python suite.
macOS Seatbelt, launchd and sysctl-specific tests remain explicitly platform
limited. A container run does not validate macOS sandbox inheritance or an
installed Linux systemd service.

`Dockerfile.linux` builds an Ubuntu 24.04 test environment. Submit the build and
run through the installed job CLI. Supply a source-only snapshot containing
`bin/`, `tests/`, `formal/` (without recorded results),
`integration/runnerpools/reviewed-runtime/` (disposable broker test fixtures),
`completions/`, `man/`, `install.sh`, `README.md` and `config.example.env`;
do not mount the user home, repository secrets or Docker
socket inside the test container. Only the snapshot is mounted read-only:

```sh
disk-janitor submit -- docker build --tag disk-janitor-verification:ubuntu24.04 \
  --file tests/Dockerfile.linux tests
disk-janitor submit -- docker run --rm --network none --user 1000:1000 \
  --mount type=bind,source=/absolute/source-snapshot,target=/source,readonly \
  disk-janitor-verification:ubuntu24.04 bash -c \
  'mkdir -p /tmp/verification && cp -R /source/. /tmp/verification/ && cd /tmp/verification && bash tests/linux.sh'
```

Observe both submitted jobs to terminal settlement with `wait`, `status` and
`logs`. Run as the image's ordinary UID 1000 account so broker ownership checks
execute under the intended user policy. Tests create executable scripts and inspect owned processes, so their
temporary filesystem must allow execution. The disposable container layer
provides it without a writable host source mount. Installing the CLI during
tests targets only disposable homes inside the container.

CI runs installation and Python tests on Ubuntu and macOS, plus the bounded TLC
matrix on Ubuntu with Java 21. The checked-in TLC jar is digest-verified; Java is
a verification dependency only. See `formal/README.md` for exact model bounds and
assumptions. CI configuration is reproducible coverage, not a claim that a hosted
CI run occurred during local development.
