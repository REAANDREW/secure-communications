# Script created using https://www.phildev.net/ssl/creating_ca.html

rm -rf CA
mkdir CA
#This is where signed certs will be stored
mkdir CA/certsdb
#This is where copies of the original CSRs will be stored
mkdir CA/certreqs
#This is where your CRL will be stored
mkdir CA/crl
#This is where the private key for the CA will live
mkdir CA/private

#Protect your private directory
chmod 700 CA/private

#Create the flat-file DB for your certificates. This is where a list of all signed certs will go. Openssl will use this to keep track of what's happened.
touch CA/index.txt

echo "basicConstraints        = CA:FALSE" >> CA/client.ext
echo "nsCertType              = client" >> CA/client.ext
echo "keyUsage                = digitalSignature, keyEncipherment" >> CA/client.ext
echo "subjectKeyIdentifier    = hash" >> CA/client.ext
echo "authorityKeyIdentifier  = keyid,issuer" >> CA/client.ext
echo "extendedKeyUsage        = clientAuth" >> CA/client.ext
echo "nsComment               = "OpenSSL Certificate for SSL Client"" >> CA/client.ext

#Your system openssl.cnf may be in some place other than /etc/openssl.cnf. If it's not there, try /usr/lib/ssl/openssl.cnf or /usr/share/ssl/openssl.cnf. If all else fails, run locate openssl.cnf.
cp scripts/openssl_a.cnf CA/

# Generate the CA for Client Certificates
echo "openssl req -new -newkey rsa:2048 -nodes -keyout private/cakey.pem -out careq.pem -config ./openssl_a.cnf -subj '/C=US/ST=Denial/L=Springfield/O=Dis/CN=selfsigned_ca'" >> CA/generate_certs.sh
echo "openssl ca -batch -create_serial -out cacert.pem -days 365 -keyfile private/cakey.pem -selfsign -extensions v3_ca_has_san -config ./openssl_a.cnf -infiles careq.pem" >> CA/generate_certs.sh

# Generate the CA signed Server certifcate
echo "openssl genrsa -out server.key 2048" >> CA/generate_certs.sh
echo "openssl req -new -key server.key -nodes -config ./openssl_a.cnf -extensions ssl_server_a -out server.csr -subj '/C=US/ST=Denial/L=Springfield/O=Dis/CN=secure.acme.com'" >> CA/generate_certs.sh
echo "openssl x509 -req -days 365 -in server.csr -CA cacert.pem -CAkey private/cakey.pem -set_serial 01 -out server.pem" >> CA/generate_certs.sh

# Generate the CA signed Client certifcate
echo "openssl genrsa -out client.key 2048" >> CA/generate_certs.sh
echo "openssl req -new -key client.key -nodes -config ./openssl_a.cnf -out client.csr -subj '/C=US/ST=Denial/L=Springfield/O=Dis/CN=secure.acme.com'" >> CA/generate_certs.sh
echo "openssl x509 -req -days 365 -extfile client.ext -in client.csr -CA cacert.pem -CAkey private/cakey.pem -CAcreateserial -out client.pem" >> CA/generate_certs.sh

echo "*** Test the connection with a server with the following command"
echo 'openssl s_client -connect secure.acme.com:8090 -tls1_2 -CAfile "$PWD/cacert.pem" -key client.key -cert client.pem -state > ssl_connection.log'

echo "*** Make a sample request using curl with the following command"
echo curl --tlsv1 --resolve secure.acme.com:8000:127.0.0.1 -vv -k --cacert cacert.pem --key client.key --cert client.pem -w "\n" https://secure.acme.com:8090
