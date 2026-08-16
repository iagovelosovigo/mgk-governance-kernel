"""Loopback-only web UI and JSON API for the Functional Governance Runtime."""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .decision import DecisionState
from .sandbox import ACTUATORS, validate_request
from .workspace import RuntimeBundle

_EMPTY_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>
body {{ font-family: ui-monospace, Menlo, monospace; margin: 2rem; background: #0f1115; color: #e6e6e6; }}
a {{ color: #7cc4ff; }} code {{ background: #1a1d24; padding: 0.1rem 0.3rem; }}
table {{ border-collapse: collapse; width: 100%; }} td, th {{ border: 1px solid #2a2f3a; padding: 0.4rem; text-align: left; }}
pre {{ background: #1a1d24; padding: 0.8rem; overflow: auto; }}
input, select, textarea {{ background: #1a1d24; color: #e6e6e6; border: 1px solid #2a2f3a; padding: 0.3rem; }}
.badge {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px; font-weight: bold; }}
.allowed {{ background: #173d23; }} .denied {{ background: #3d1717; }}
.human {{ background: #3d3217; }} .indet {{ background: #2a2a2a; }}
</style></head><body><h1>{heading}</h1>{body}</body></html>"""


def _page(title: str, body: str) -> str:
    return _EMPTY_PAGE.format(title=title, heading=title, body=body)


def _badge(state: str) -> str:
    style = {
        "ALLOW": "allowed",
        "DENY": "denied",
        "REQUIRE_HUMAN": "human",
        "INDETERMINATE": "indet",
    }.get(state, "indet")
    return f'<span class="badge {style}">{html.escape(state)}</span>'


class RuntimeHandler(BaseHTTPRequestHandler):
    bundle: RuntimeBundle
    server_version = "MGK-Runtime/0.2.0"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    # ------------------------------------------------------------------ helpers
    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: str, title: str = "MGK Governance Runtime", status: int = 200) -> None:
        encoded = _page(title, body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}

    def _origin_allowed(self) -> bool:
        """Block cross-origin state-changing requests (CSRF defence).

        A malicious web page loaded in the same user's browser could otherwise
        submit proposals to the loopback runtime. Requests carrying an Origin or
        Referer that does not match this server are rejected.
        """
        origin = self.headers.get("Origin")
        referer = self.headers.get("Referer")
        allowed = {f"http://{self.server.server_address[0]}:{self.server.server_address[1]}"}
        if origin is not None:
            return origin in allowed
        if referer is not None:
            return any(referer.startswith(candidate) for candidate in allowed)
        return True

    # ------------------------------------------------------------------ routes
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in {"/", "/api/status"}:
            self._status()
        elif path == "/propose":
            self._propose_form()
        elif path == "/human-gate":
            self._human_gate()
        elif path == "/flight-recorder":
            self._flight_recorder()
        elif path == "/evidence":
            self._evidence()
        elif path == "/api/evidence":
            self._evidence_json()
        elif path == "/api/health":
            self._json({"status": "ok", "version": "0.2.0"})
        elif path.startswith("/decision/"):
            self._decision(path)
        else:
            self._html("<p>Not found. Try <a href='/'>/</a>.</p>", title="404", status=404)

    def do_POST(self) -> None:
        if not self._origin_allowed():
            self._json({"state": "DENY", "error": "cross-origin request rejected"}, 403)
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/propose":
            self._api_propose()
        elif path.startswith("/api/human-gate/"):
            self._api_human(path)
        else:
            self._json({"error": "not found"}, 404)

    # ------------------------------------------------------------------ pages
    def _status(self) -> None:
        bundle = self.bundle
        status = bundle.status()
        decisions = bundle.ledger.decisions()
        counts: dict[str, int] = {}
        for row in decisions:
            counts[row["state"]] = counts.get(row["state"], 0) + 1
        rows = "".join(
            f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>" for k, v in status.items()
        )
        actuator_rows = "".join(
            f"<tr><td><code>{html.escape(a.action)}</code></td><td>{html.escape(a.namespace)}</td>"
            f"<td>{html.escape(a.description)}</td></tr>"
            for a in sorted(ACTUATORS, key=lambda x: x.action)
        )
        state_rows = "".join(
            f"<tr><td>{_badge(state)}</td><td>{counts.get(state, 0)}</td></tr>"
            for state in ("ALLOW", "DENY", "REQUIRE_HUMAN", "INDETERMINATE")
        )
        body = f"""
<p><a href="/propose">Submit a proposal</a> · <a href="/human-gate">Human gate</a> ·
<a href="/flight-recorder">Flight recorder</a> · <a href="/evidence">Evidence</a></p>
<h2>System status</h2>
<table>{rows}</table>
<h2>Decision states</h2>
<table><tr><th>State</th><th>Count</th></tr>{state_rows}</table>
<h2>Governed actuators (closed registry)</h2>
<table><tr><th>Action</th><th>Namespace</th><th>Description</th></tr>{actuator_rows}</table>
"""
        self._html(body)

    def _propose_form(self) -> None:
        options = "".join(
            f'<option value="{html.escape(a.action)}">{html.escape(a.action)}</option>'
            for a in sorted(ACTUATORS, key=lambda x: x.action)
        )
        body = f"""
<p><a href="/">Status</a> · <a href="/human-gate">Human gate</a></p>
<h2>Submit a proposal</h2>
<p><strong>Proposal is not authority.</strong> This form records data only. No side effect
happens unless the kernel issues a scoped capability and the executor runs it.</p>
<form action="/api/propose" method="post" id="propose">
<table>
<tr><td>request_id</td><td><input name="request_id" value="req-1" /></td></tr>
<tr><td>principal</td><td><input name="principal" value="planner" /></td></tr>
<tr><td>audience</td><td><input name="audience" value="executor" /></td></tr>
<tr><td>action</td><td><select name="action">{options}</select></td></tr>
<tr><td>resource</td><td><input name="resource" value="files/note.txt" /></td></tr>
<tr><td>parameters</td><td><textarea name="parameters" rows="6" cols="60">{{"content_b64": "SGVsbG8sIE1HSyEK"}}</textarea></td></tr>
</table>
<button type="submit">Submit proposal</button>
</form>
<pre id="result"></pre>
<script>
const form = document.getElementById("propose");
form.addEventListener("submit", async (event) => {{
  event.preventDefault();
  const data = Object.fromEntries(new FormData(form));
  try {{ data.parameters = JSON.parse(data.parameters); }} catch (e) {{ data.parameters = {{}}; }}
  const response = await fetch("/api/propose", {{ method: "POST", headers: {{"Content-Type": "application/json"}}, body: JSON.stringify(data) }});
  const result = await response.json();
  document.getElementById("result").textContent = JSON.stringify(result, null, 2);
}});
</script>
"""
        self._html(body)

    def _human_gate(self) -> None:
        pending = self.bundle.pipeline.pending()
        if not pending:
            body = "<p>No proposals currently require human review.</p>"
        else:
            rows = []
            for row in pending:
                proposal = self.bundle.ledger.proposal(row["request_id"])
                rows.append(
                    f"<tr><td>{html.escape(row['request_id'])}</td>"
                    f"<td><code>{html.escape(proposal['action'])}</code></td>"
                    f"<td><code>{html.escape(proposal['resource'])}</code></td>"
                    f"<td>{html.escape(', '.join(row['reason_codes']))}</td>"
                    f"<td><button onclick='decide(\"{html.escape(row['request_id'])}\",\"APPROVE\")'>APPROVE</button> "
                    f"<button onclick='decide(\"{html.escape(row['request_id'])}\",\"DENY\")'>DENY</button></td></tr>"
                )
            body = f"""
<h2>Pending human decisions</h2>
<table><tr><th>Request</th><th>Action</th><th>Resource</th><th>Reason</th><th>Decision</th></tr>
{''.join(rows)}</table>
<pre id="result"></pre>
<script>
async function decide(requestId, decision) {{
  const operator = prompt("Operator identity:");
  if (!operator) return;
  const response = await fetch("/api/human-gate/" + requestId, {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{ decision, operator }}),
  }});
  const result = await response.json();
  document.getElementById("result").textContent = JSON.stringify(result, null, 2);
  location.reload();
}}
</script>
"""
        self._html(body)

    def _decision(self, path: str) -> None:
        request_id = path.removeprefix("/decision/")
        proposal = self.bundle.ledger.proposal(request_id)
        rows = [row for row in self.bundle.ledger.decisions() if row["request_id"] == request_id]
        if proposal is None and not rows:
            self._html("<p>Decision not found.</p>", title="404", status=404)
            return
        parts = [f"<h2>Proposal {html.escape(request_id)}</h2>"]
        if proposal:
            parts.append(
                "<table><tr><td>request_id</td><td><code>%s</code></td></tr>"
                "<tr><td>principal</td><td>%s</td></tr><tr><td>audience</td><td>%s</td></tr>"
                "<tr><td>action</td><td><code>%s</code></td></tr><tr><td>resource</td><td><code>%s</code></td></tr>"
                "<tr><td>request_digest</td><td><code>%s</code></td></tr></table>"
                % (
                    html.escape(proposal["request_id"]),
                    html.escape(proposal["principal"]),
                    html.escape(proposal["audience"]),
                    html.escape(proposal["action"]),
                    html.escape(proposal["resource"]),
                    html.escape(proposal["request_digest"]),
                )
            )
        for row in rows:
            parts.append(
                f"<h3>Decision {_badge(row['state'])}</h3>"
                f"<pre>{html.escape(json.dumps(row, indent=2, sort_keys=True))}</pre>"
            )
        self._html("".join(parts), title=f"Decision {request_id}")

    def _flight_recorder(self) -> None:
        count, head = self.bundle.flight.verify_integrity()
        events = []
        with self.bundle.flight.path.open("rb") as stream:
            for line in stream:
                events.append(json.loads(line))
        events.reverse()
        rows = "".join(
            f"<tr><td>{event['seq']}</td><td>{html.escape(event['event_type'])}</td>"
            f"<td><code>{html.escape(json.dumps(event['data'], sort_keys=True))}</code></td></tr>"
            for event in events[:200]
        )
        body = f"""
<h2>Flight recorder</h2>
<p>Records: {count} · head <code>{head[:16]}…</code> (integrity verified)</p>
<table><tr><th>Seq</th><th>Event</th><th>Data</th></tr>{rows}</table>
"""
        self._html(body)

    def _evidence(self) -> None:
        bundle = self.bundle
        try:
            audit_count, audit_head = bundle.audit.verify_integrity()
            failure_count, failure_head = bundle.failures.verify_integrity()
            flight_count, flight_head = bundle.flight.verify_integrity()
        except BaseException as exc:
            self._html(
                f"<h2>Evidence</h2><p><strong>Integrity verification failed.</strong></p>"
                f"<pre>{html.escape(type(exc).__name__)}: {html.escape(str(exc))}</pre>",
                title="Evidence — integrity failure",
                status=500,
            )
            return
        status = bundle.status()
        body = f"""
<h2>Evidence</h2>
<h3>Integrity</h3>
<table>
<tr><td>Audit ledger</td><td>{audit_count} records · head <code>{audit_head[:16]}…</code></td></tr>
<tr><td>Failure ledger</td><td>{failure_count} records · head <code>{failure_head[:16]}…</code></td></tr>
<tr><td>Flight recorder</td><td>{flight_count} records · head <code>{flight_head[:16]}…</code></td></tr>
<tr><td>Authorization epoch</td><td>{status['epoch']}</td></tr>
<tr><td>Consumed nonces (single-use capabilities)</td><td>{status['nonce_count']}</td></tr>
<tr><td>Authority</td><td><code>{status['identity']['authority']}</code></td></tr>
</table>
<h3>Sandbox workspace</h3>
<ul>
<li><a href="/evidence">files/</a> — {self._count_files()}</li>
</ul>
"""
        self._html(body)

    def _count_files(self) -> str:
        import os

        files = self.bundle.workspace.files_root
        records = self.bundle.workspace.records_root
        file_count = len([p for p in files.iterdir() if p.is_file()]) if files.exists() else 0
        record_count = len([p for p in records.iterdir() if p.is_file()]) if records.exists() else 0
        return f"{file_count} file(s), {record_count} record(s)"

    def _evidence_json(self) -> None:
        bundle = self.bundle
        try:
            audit_count, audit_head = bundle.audit.verify_integrity()
            failure_count, failure_head = bundle.failures.verify_integrity()
            flight_count, flight_head = bundle.flight.verify_integrity()
        except BaseException as exc:
            self._json(
                {
                    "state": DecisionState.INDETERMINATE.value,
                    "error": "integrity verification failed",
                    "detail": type(exc).__name__,
                },
                500,
            )
            return
        self._json(
            {
                "audit": {"count": audit_count, "head": audit_head},
                "failures": {"count": failure_count, "head": failure_head},
                "flight": {"count": flight_count, "head": flight_head},
                "status": bundle.status(),
            }
        )

    # ------------------------------------------------------------------ api
    def _api_propose(self) -> None:
        request = self._read_body()
        try:
            validate_request(request)
        except ValueError as exc:
            self._json({"state": "DENY", "error": str(exc)}, 400)
            return
        try:
            decision = self.bundle.pipeline.propose(request)
        except BaseException:
            self._json({"state": DecisionState.INDETERMINATE.value, "error": "internal failure"}, 500)
            return
        payload = decision.to_dict()
        self._json(payload)

    def _api_human(self, path: str) -> None:
        rest = path.removeprefix("/api/human-gate/")
        if "/" in rest:
            self._json({"error": "not found"}, 404)
            return
        request_id = rest
        body = self._read_body()
        decision_value = body.get("decision")
        operator = body.get("operator", "operator")
        if decision_value not in {"APPROVE", "DENY"}:
            self._json({"error": "decision must be APPROVE or DENY"}, 400)
            return
        try:
            if decision_value == "APPROVE":
                decision = self.bundle.pipeline.human_approve(request_id, operator)
            else:
                decision = self.bundle.pipeline.human_deny(request_id, operator)
        except BaseException:
            self._json(
                {"state": DecisionState.INDETERMINATE.value, "error": "internal failure"},
                500,
            )
            return
        self._json(decision.to_dict())


def make_server(bundle: RuntimeBundle, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    handler = type(
        "BoundRuntimeHandler",
        (RuntimeHandler,),
        {"bundle": bundle},
    )
    return ThreadingHTTPServer((host, port), handler)