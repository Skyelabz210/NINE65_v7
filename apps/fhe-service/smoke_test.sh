#!/usr/bin/env bash
# Smoke test: create session, encrypt, add, decrypt.
# Requires: jq, curl, and the fhe-service running on localhost:8080.
set -euo pipefail

BASE="http://127.0.0.1:8080"

echo "=== FHE Service Smoke Test ==="

# Health check
echo -n "Health check... "
curl -sf "$BASE/healthz" | jq -r .status
echo ""

# Create session
echo -n "Creating session (secure_128)... "
SID=$(curl -sf -X POST "$BASE/v1/sessions" \
  -H 'Content-Type: application/json' \
  -d '{"config":"secure_128"}' | jq -r .session_id)
echo "$SID"

# Encrypt two values
echo -n "Encrypting [42, 17]... "
ENC=$(curl -sf -X POST "$BASE/v1/sessions/$SID/encrypt" \
  -H 'Content-Type: application/json' \
  -d '{"values":[42,17]}')
CT_A=$(echo "$ENC" | jq -r .ciphertexts[0])
CT_B=$(echo "$ENC" | jq -r .ciphertexts[1])
echo "ok (2 ciphertexts)"

# Add
echo -n "Evaluating add(ct_a, ct_b)... "
CT_SUM=$(curl -sf -X POST "$BASE/v1/sessions/$SID/evaluate" \
  -H 'Content-Type: application/json' \
  -d "{\"operations\":[{\"op\":\"add\",\"inputs\":[\"$CT_A\",\"$CT_B\"]}]}" \
  | jq -r .results[0])
echo "ok"

# Decrypt
echo -n "Decrypting sum... "
RESULT=$(curl -sf -X POST "$BASE/v1/sessions/$SID/decrypt" \
  -H 'Content-Type: application/json' \
  -d "{\"ciphertexts\":[\"$CT_SUM\"]}" | jq -r .values[0])
echo "$RESULT"

# Validate
if [ "$RESULT" = "59" ]; then
  echo ""
  echo "PASS: 42 + 17 = 59"
else
  echo ""
  echo "FAIL: expected 59, got $RESULT"
  exit 1
fi

# Cleanup
curl -sf -X DELETE "$BASE/v1/sessions/$SID" > /dev/null
echo "Session cleaned up."
