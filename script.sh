# Create unencrypted private key and a CSR (certificate signing request)
openssl req -newkey rsa:2048 -nodes -keyout localhost.key -out localhost.csr

openssl rsa -in localhost.key -out localhost.key

# Create self-signed certificate (`localhost.crt`) with the private key and CSR
openssl x509 -signkey localhost.key -in localhost.csr -req -days 365 -out localhost.crt

# Create a self-signed root CA
openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt

echo "authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost" >> localhost.ext

openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in localhost.csr -out localhost.crt -days 365 -CAcreateserial -extfile localhost.ext
