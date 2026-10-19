#!/bin/bash
# End-to-end on nokemo2's TPM. Runs in ~/p3sig-ks-e2e; cleans up its key and server.
set -u
D=$(cd "$(dirname "$0")" && pwd); cd "$(mktemp -d)"; cp "$D/keyserver-client.php" client.php; cp "$(command -v p3sig || echo "$D/../p3sig")" p3sig
export P3SIG_TPM_DIR=$PWD/tpm
POINT=$(./p3sig keyserver init --label ks-e2e 2>/dev/null) || { echo "init failed"; exit 1; }
echo "chip point: ${POINT:0:24}..."
echo '{"STRIPE_SECRET_KEY":"sk_test_e2e","SMTP_PASSWORD":"pw"}' > values.json
./p3sig keyserver seal --pub "$POINT" --in values.json --out cache.enc && rm values.json
read SK PK < <(php -r '$k=sodium_crypto_sign_keypair(); echo base64_encode(sodium_crypto_sign_secretkey($k))," ",base64_encode(sodium_crypto_sign_publickey($k));')
mk() { printf '{"label":"ks-e2e","apps":{"pilot":{"key":"%s","ips":["%s"]}}}' "$PK" "$1" > ks.json; }
serve() { ./p3sig keyserver serve --config ks.json --listen 127.0.0.1:18787 2>>server.log & SRV=$!; sleep 1; }
mk 127.0.0.1; serve
echo -n "allowed address:  "; php client.php http://127.0.0.1:18787/v1/unwrap pilot "$SK" cache.enc
echo -n "replay-free again: "; php client.php http://127.0.0.1:18787/v1/unwrap pilot "$SK" cache.enc
kill $SRV; wait $SRV 2>/dev/null
mk 203.0.113.9; serve
echo -n "other address:    "; php client.php http://127.0.0.1:18787/v1/unwrap pilot "$SK" cache.enc
kill $SRV; wait $SRV 2>/dev/null
echo "--- server log"; sed 's/^[0-9\/: ]*//' server.log
rm -rf tpm ks.json cache.enc server.log
