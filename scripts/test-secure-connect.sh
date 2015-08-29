openssl s_client -connect secure.acme.com:8090 -tls1_2 -CAfile config/cacert.pem -key config/client.key -cert config/client.pem -state
