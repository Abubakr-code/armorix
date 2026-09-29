import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from armorix import server


@pytest.fixture(scope="module")
def api():
    httpd = server.make_server(0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base, token = f"http://127.0.0.1:{httpd.server_address[1]}", server.Handler.token

    def call(method, path, body=None, auth=True):
        req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-Armorix-Token": token} if auth else {})
        with urllib.request.urlopen(req, timeout=10) as resp:
            ctype = resp.headers.get("Content-Type", "")
            data = resp.read()
            return json.loads(data) if "json" in ctype else data.decode()

    yield call
    httpd.shutdown()


def wait(call, job_id, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        view = call("GET", f"/jobs/{job_id}")
        if view["status"] != "running":
            return view
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def test_requires_token(api):
    with pytest.raises(urllib.error.HTTPError) as err:
        api("GET", "/status", auth=False)
    assert err.value.code == 403


def test_status(api):
    status = api("GET", "/status")
    assert status["version"] and "ready" in status["ai"]


@pytest.mark.parametrize("text, kind", [
    ("examples/vuln-shop papkasini tekshir", "scan"),
    ("'examples/vuln-shop' ni chuqur tekshir", "deep"),
    ("исправь ошибки в 'examples/vuln-shop'", "fix"),
])
def test_parse_task(text, kind):
    intent = server.parse_task(text, None)
    assert intent["kind"] == kind and intent["path"].endswith("examples/vuln-shop")


def test_task_runs_scan_job(api):
    reply = api("POST", "/task", {"text": "tekshir", "path": "examples/vuln-shop", "lang": "uz"})
    assert reply["kind"] == "scan" and "tekshiraman" in reply["reply"]
    view = wait(api, reply["job"])
    assert view["status"] == "done"
    result = view["result"]
    assert result["counts"]["critical"] >= 7
    first = result["findings"][0]
    assert first["severity_label"] == "KRITIK" and first["title"] and first["fix"]
    html = api("GET", f"/report/{reply['job']}.html")
    assert "Xavfsizlik hisoboti" in html


def test_task_without_path_asks_for_folder(api):
    reply = api("POST", "/task", {"text": "tekshir", "lang": "uz"})
    assert reply["job"] is None and "papka" in reply["reply"].lower()


def test_unknown_folder(api):
    reply = api("POST", "/task", {"text": "check /no/such/dir", "lang": "en"})
    assert reply["job"] is None and "not found" in reply["reply"]
