#!/usr/bin/env bash
# End-to-end smoke test against a running agent (dev configuration).
# Exercises: pairing → demo device → full deep scan → findings → quarantine →
# restore → JSON report. Uses only synthetic test content (EICAR test string).
set -euo pipefail
BASE="${USBSHIELD_AGENT_URL:-http://127.0.0.1:8765}/api"
H=(-H 'X-USBShield-Client: usb-shield-web' -H 'Content-Type: application/json')

# Extract values from JSON on stdin without quoting pitfalls.
jx() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

echo "1) health"
curl -fsS "$BASE/health" > /dev/null && echo "   ok"

echo "2) pairing (loopback only)"
TOKEN=$(curl -fsS -X POST "$BASE/pair" "${H[@]}" | jx 'd["access_token"]')
AUTH=(-H "Authorization: Bearer $TOKEN" "${H[@]}")
echo "   token received (${#TOKEN} chars)"

echo "3) creating synthetic demo device"
DEV=$(curl -fsS -X POST "$BASE/devices/demo" "${AUTH[@]}" | jx 'd["device"]["id"]')
echo "   device id: $DEV"

echo "4) starting full deep scan"
SID=$(curl -fsS -X POST "$BASE/scans" "${AUTH[@]}" \
      -d "{\"device_id\": \"$DEV\", \"mode\": \"full\", \"custom_paths\": []}" \
      | jx 'd["id"]')
echo "   scan id: $SID"

echo "5) waiting for completion"
while :; do
  REC=$(curl -fsS "$BASE/scans/$SID" "${AUTH[@]}")
  STATUS=$(echo "$REC" | jx 'd["status"]')
  [ "$STATUS" != "queued" ] && [ "$STATUS" != "scanning" ] && break
  sleep 0.5
done
echo "$REC" | python3 -c "
import json, sys
r = json.load(sys.stdin)
c = r['counters']
print(f'   status={r[\"status\"]} outcome={r[\"outcome\"]}')
print(f'   files_scanned={c[\"files_scanned\"]} dirs={c[\"dirs_scanned\"]} '
      f'threats={c[\"threats_found\"]} partial={c[\"files_partial\"]} unable={c[\"files_unable\"]}')"

echo "6) findings"
FINDINGS=$(curl -fsS "$BASE/scans/$SID/findings" "${AUTH[@]}")
echo "$FINDINGS" | python3 -c "
import json, sys
for f in json.load(sys.stdin)['findings']:
    det = f['detection_name'] or f['reason'] or ''
    print(f'   [{f[\"classification\"]:12s}|{f[\"severity\"]:7s}] {f[\"path\"]}  ({det})')"

FID=$(echo "$FINDINGS" | jx 'next(f["id"] for f in d["findings"] if f["classification"] == "malicious" and not f["container"])')

echo "7) quarantine one detection"
QID=$(curl -fsS -X POST "$BASE/quarantine" "${AUTH[@]}" -d "{\"finding_id\": \"$FID\"}" \
      | jx 'd["id"]')
echo "   quarantined: $QID"

echo "8) restore it (confirmed)"
curl -fsS -X POST "$BASE/quarantine/$QID/restore" "${AUTH[@]}" \
     -d '{"confirm": true, "destination": "original"}' > /dev/null
echo "   restored"

echo "9) JSON report"
curl -fsS "$BASE/scans/$SID/report?format=json" "${AUTH[@]}" \
     | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'   outcome: {d[\"scan\"][\"outcome\"]} | findings: {len(d[\"findings\"])}')"

echo
echo "E2E demo complete - the pipeline detected, quarantined, restored and reported."
