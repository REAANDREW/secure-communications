# Script created using https://www.phildev.net/ssl/creating_ca.html

rm -rf CA
mkdir CA
echo "01" > CA/serial.txt
echo "01" > CA/crlnumber.txt
touch CA/index.txt

cp scripts/openssl.cnf CA/

# Generate the CA for Certificates
echo "openssl req -new -newkey rsa:2048 -nodes -keyout cakey.pem -out careq.pem -config ./openssl.cnf -subj '/C=US/ST=Denial/L=Springfield/O=Dis/CN=selfsigned_ca'" >> CA/generate_certs.sh
echo "openssl ca -batch -create_serial -out cacert.pem -days 365 -keyfile cakey.pem -selfsign -extensions ca_ext -config ./openssl.cnf -infiles careq.pem" >> CA/generate_certs.sh

#echo "openssl req -new -x509 -nodes -keyout cakey.pem -out cacert.pem -config ./openssl.cnf -extensions ca_ext -subj '/C=US/ST=Denial/L=Springfield/O=Dis/CN=secure.acme.com'" >> CA/generate_certs.sh

# Generate the CA signed Server certifcate
echo "openssl genrsa -out server.key 2048" >> CA/generate_certs.sh
echo "openssl req -new -key server.key -nodes -out server.csr -subj '/C=US/ST=Denial/L=Springfield/O=Dis/CN=secure.acme.com'" >> CA/generate_certs.sh
echo "openssl x509 -req -days 365 -extfile ./openssl.cnf -extensions ssl_server_ext -in server.csr -CA cacert.pem -CAkey cakey.pem -set_serial 01 -out server.pem" >> CA/generate_certs.sh

# Generate the CA signed Client certifcate
echo "openssl genrsa -out client.key 2048" >> CA/generate_certs.sh
echo "openssl req -new -key client.key -nodes -out client.csr -subj '/C=US/ST=Denial/L=Springfield/O=Dis/CN=secure.acme.com'" >> CA/generate_certs.sh
echo "openssl x509 -req -days 365 -extfile ./openssl.cnf -extensions ssl_client_ext -in client.csr -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out client.pem" >> CA/generate_certs.sh

echo "*** Test the connection with a server with the following command"
echo 'openssl s_client -connect secure.acme.com:8090 -tls1_2 -CAfile "$PWD/cacert.pem" -key client.key -cert client.pem -state > ssl_connection.log'

echo "*** Make a sample request using curl with the following command"
echo curl --tlsv1 --resolve secure.acme.com:8000:127.0.0.1 -vv -k --cacert cacert.pem --key client.key --cert client.pem -w "\n" https://secure.acme.com:8090
