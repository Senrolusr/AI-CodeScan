import json
import sys

sys.path.append("backend")

from services.audit_engine import _endpoint_matches_packet, _parse_raw_http_request, _parse_structured_response


def main():
    with open("backend/data/audit.db", "rb"):
        pass

    import sqlite3

    conn = sqlite3.connect("backend/data/audit.db")
    cur = conn.cursor()
    row = cur.execute("select llm_response from audit_stages where task_id=1 and stage_num=2").fetchone()
    payload = json.loads(row[0])
    parsed = _parse_structured_response(payload.get("content", ""))
    vuln = (parsed.get("vulnerabilities") or [None])[0]
    if not vuln:
        print("no_vuln")
        return

    endpoint = vuln.get("endpoint")
    poc_raw = vuln.get("poc_raw")
    packet = _parse_raw_http_request(poc_raw)
    print("endpoint=", repr(endpoint))
    print("packet=", packet)
    print("match=", _endpoint_matches_packet(endpoint, packet))


if __name__ == "__main__":
    main()
