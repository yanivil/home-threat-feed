"""The scripts' secrets: an environment variable when it is set, else an item in the macOS login Keychain."""

import os
import subprocess

SERVICE = "spark-ioc-feed"


def item(account, env_var=None, environ=None, run=None):
    """The secret `account`: `env_var` from `environ` (default os.environ) when set and not blank,
    else the Keychain item (service SERVICE, account `account`) read with `run` (default
    subprocess.run); "" when neither has one."""
    environ = os.environ if environ is None else environ
    run = subprocess.run if run is None else run
    value = environ.get(env_var, "").strip() if env_var else ""
    if value:
        return value
    try:
        proc = run(["security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"],
                   capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""
