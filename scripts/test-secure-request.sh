HOST=secure.acme.com
PORT=8090
ENDPOINT="$HOST:$PORT"

curl --tlsv1.2 -v -s  \
    --resolve "$ENDPOINT:127.0.0.1" \
    --cacert config/cacert.pem \
    --capath $PWD/CA/certsdb/ \
    --key config/client.key \
    --cert config/client.pem \
    -w "\n" \
    "https://$ENDPOINT"
