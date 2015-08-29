rm -rf CA/ config/ logs/

sh scripts/make-ca.sh

(cd CA/ && sh generate_certs.sh)

mkdir config

mkdir logs

cp CA/*.pem config/
cp CA/*.key config/

go build

./secure-communications&
secure_pid=$!

sleep 5
# Run the scripts and output the logs

#Secure Connection
echo QUIT | sh scripts/test-secure-connect.sh > logs/secure-connection.log 2>&1

#Secure Request
sh scripts/test-secure-request.sh > logs/secure-request.log 2>&1

# Certificates

openssl x509 -in CA/cacert.pem -text > logs/cacert.txt
openssl x509 -in CA/server.pem -text > logs/server.txt
openssl x509 -in CA/client.pem -text > logs/client.txt

kill -9 $secure_pid
