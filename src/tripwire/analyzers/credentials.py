"""Reads of secrets: keys, cloud credentials, browser data, wallets, tokens.

A path in a string is a *capability*, not proof. ``botocore`` mentions
``~/.aws/credentials`` for good reasons. The weight is moderate on its own;
the scorer raises it when the same package also has an exfiltration channel.
"""

from __future__ import annotations

import re

from ..models import Evidence, Package
from .base import DOC_NAMES, ev, fold, has_any, line_of

NAME = "credentials"

# Path separators as they appear in code: "a/b", "a\b" or path.join("a", "b").
SEP = r"""[/\\'",\s]+"""

SECRET_PATHS: list[tuple[str, re.Pattern[str], float, str]] = [
    # ".ssh" must be followed by a path separator or a closing quote. Whitespace or ")"
    # after it used to count, which matched property access like "before.ssh === x".
    ("ssh_keys", re.compile(r"""\.ssh(?:[/\\]|['"](?:\s*[,)/]|$))|\bid_(?:rsa|dsa|ecdsa|ed25519)\b""",
                            re.I | re.M), 0.5, "SSH keys"),
    ("cloud_credentials", re.compile(r"""\.aws[/\\'"\s,)]+(?:credentials|config)|\.azure[/\\]|gcloud[/\\]"""
                                     r"""(?:credentials|application_default_credentials)|\.kube[/\\]config""", re.I),
     0.45, "cloud credentials (AWS / Azure / GCP / Kubernetes)"),
    ("registry_tokens", re.compile(r"""\.npmrc\b|\.pypirc\b|\.git-credentials\b|\.docker[/\\]config\.json|"""
                                   r"""\.netrc\b""", re.I), 0.45, "package-registry or git tokens"),
    # A browser name alone is common (puppeteer downloads Chromium), so the
    # profile folder must follow it. "Login Data" / "Local State" are matched
    # case-sensitively as quoted file names, not as English words.
    ("browser_data", re.compile(
        r"""(?i:Google{s}Chrome|BraveSoftware{s}Brave-Browser|Microsoft{s}Edge|Opera Software|Chromium)"""
        r"""{s}(?i:User Data|Default{s}(?:Login Data|Cookies|Web Data))|(?i:\.mozilla{s}firefox)|"""
        r"""['"/\\](?:Login Data|Local State)['"]|(?i:cookies\.sqlite|key4\.db|logins\.json)""".format(s=SEP)),
     0.6, "browser profiles (saved passwords / cookies)"),
    ("crypto_wallets", re.compile(r"""\bwallet\.dat\b|Electrum[/\\]+wallets|\bExodus[/\\]|Ethereum[/\\]+keystore|"""
                                  r"""nkbihfbeogaeaoehlefnkodbefgpgknn|atomic[/\\]+Local Storage|"""
                                  r"""\bPhantom\b[^\n]{0,40}(?:wallet|extension)""", re.I), 0.6, "crypto wallets"),
    ("chat_tokens", re.compile(r"""(?:discord|discordcanary|discordptb)[/\\]+Local Storage[/\\]+leveldb|"""
                               r"""Telegram Desktop[/\\]+tdata""", re.I), 0.65, "Discord / Telegram session tokens"),
    ("shell_history", re.compile(r"""\.bash_history|\.zsh_history|ConsoleHost_history\.txt""", re.I), 0.4,
     "shell history"),
]

ENV_HARVEST: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"JSON\.stringify\(\s*process\.env\s*\)"), 0.55, "serialises every environment variable"),
    (re.compile(r"json\.dumps\(\s*(?:dict\()?\s*os\.environ\b"), 0.55, "serialises every environment variable"),
    (re.compile(r"(?:str|repr)\(\s*os\.environ\s*\)|urlencode\(\s*(?:dict\()?\s*os\.environ"), 0.5,
     "turns every environment variable into a string"),
    (re.compile(r"for\s+[\w, ]+\s+in\s+os\.environ(?:\.items\(\))?\s*:"), 0.25, "walks every environment variable"),
    (re.compile(r"Object\.(?:entries|keys|values)\(\s*process\.env\s*\)"), 0.25, "walks every environment variable"),
    (re.compile(r"dict\(\s*os\.environ\s*\)"), 0.15, "copies the whole environment"),
]
# Lower-case literals each SECRET_PATHS pattern needs; lets most files skip the regex.
PATH_KEYS = {
    "ssh_keys": (".ssh", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"),
    "cloud_credentials": (".aws", ".azure", "gcloud", ".kube"),
    "registry_tokens": (".npmrc", ".pypirc", ".git-credentials", ".docker", ".netrc"),
    "browser_data": ("chrome", "brave", "edge", "opera", "chromium", "mozilla", "login data", "local state",
                     "cookies.sqlite", "key4.db", "logins.json"),
    "crypto_wallets": ("wallet.dat", "electrum", "exodus", "ethereum", "nkbihfbeogaeaoehlefnkodbefgpgknn", "atomic",
                       "phantom"),
    "chat_tokens": ("discord", "telegram desktop"),
    "shell_history": ("bash_history", "zsh_history", "consolehost_history"),
}
ENV_KEYS = ("environ", "process.env")

# Names that are only interesting when a package collects them in bulk.
SECRET_ENV_NAMES = re.compile(
    r"""(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|NPM_TOKEN|GH_TOKEN|CI_JOB_TOKEN|"""
    r"""AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|SLACK_TOKEN|OPENAI_API_KEY|STRIPE_SECRET_KEY)""")
SKIP_SUFFIXES = (".md", ".rst", ".txt", ".html", ".css")


class CredentialsAnalyzer:
    name = NAME

    def analyze(self, pkg: Package) -> list[Evidence]:
        out: list[Evidence] = []
        seen: set[tuple[str, str]] = set()
        for f in pkg.files:
            if f.suffix in SKIP_SUFFIXES or f.basename.upper().startswith(DOC_NAMES):
                continue
            install = f.path in pkg.install_files
            bump = 0.1 if install else 0.0
            low = fold(f.text)
            for rule, rx, w, label in SECRET_PATHS:
                m = rx.search(f.text) if has_any(low, PATH_KEYS[rule]) else None
                if m and (rule, f.path) not in seen:
                    seen.add((rule, f.path))
                    out.append(ev(NAME, rule, w + bump, f"{f.path} reads or references {label}.", f,
                                  line_of(f.text, m.start())))
            for rx, w, label in ENV_HARVEST if has_any(low, ENV_KEYS) else ():
                m = rx.search(f.text)
                if m:
                    out.append(ev(NAME, "env_harvest", w + bump, f"{f.path} {label}.", f, line_of(f.text, m.start())))
                    break
            names = set(SECRET_ENV_NAMES.findall(f.text))
            if len(names) >= 3:
                m = SECRET_ENV_NAMES.search(f.text)
                out.append(ev(NAME, "secret_env_names", 0.35 + bump,
                              f"{f.path} reads {len(names)} different secret-token variables "
                              f"({', '.join(sorted(names)[:4])}).", f, line_of(f.text, m.start()) if m else None))
        return out
