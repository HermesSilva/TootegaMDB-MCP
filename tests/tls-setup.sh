#!/usr/bin/env bash
# Prepara o ambiente de teste de TLS: gera uma autoridade certificadora e
# certificados de servidor (RSA e ECDSA) com o openssl do sistema — usado aqui
# só como ferramenta de teste, para termos servidores TLS de verdade do outro lado —
# e sobe dois PostgreSQL com TLS ligado.
# Uso (WSL, na raiz do projeto):  bash tests/tls-setup.sh
set -euo pipefail
D=/tmp/tmdb-tls
rm -rf "$D"; mkdir -p "$D"; cd "$D"

# Autoridade e servidor RSA (SAN: localhost)
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 -subj "/CN=TMDB Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=tmdb-pg" 2>/dev/null
printf 'subjectAltName=DNS:localhost,DNS:*.tmdb.test\nbasicConstraints=CA:FALSE\n' > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 30 -extfile ext.cnf 2>/dev/null

# Autoridade e servidor ECDSA P-256, com uma intermediária P-384 no meio (testa a cadeia)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout ec-ca.key -out ec-ca.pem -days 30 \
  -subj "/CN=TMDB Test EC Root" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout ec-int.key -out ec-int.csr -subj "/CN=TMDB Test EC Intermediate" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE\n' > int.cnf
openssl x509 -req -in ec-int.csr -CA ec-ca.pem -CAkey ec-ca.key -CAcreateserial -out ec-int.pem -days 30 -extfile int.cnf 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ec-server.key -out ec-server.csr -subj "/CN=tmdb-pg-ec" 2>/dev/null
openssl x509 -req -in ec-server.csr -CA ec-int.pem -CAkey ec-int.key -CAcreateserial -out ec-server.pem -days 30 -extfile ext.cnf 2>/dev/null
cat ec-server.pem ec-int.pem > ec-chain.pem

# Certificado da autoridade que o MySQL do container gerou sozinho
docker exec tmdb-test-mysql-1 cat /var/lib/mysql/ca.pem > mysql-ca.pem 2>/dev/null || true

chmod 644 *.pem; chmod 600 *.key
docker rm -f tmdb-pg-tls tmdb-pg-ec >/dev/null 2>&1 || true
run_pg() { # nome porta certificado chave
  docker run -d --name "$1" -e POSTGRES_USER=tmdb -e POSTGRES_PASSWORD=Tmdb_Test_123 -e POSTGRES_DB=tmdb \
    -p "127.0.0.1:$2:5432" -v "$D/$3:/tls/server.crt:ro" -v "$D/$4:/tls/server.key.in:ro" postgres:17-alpine \
    sh -c 'cp /tls/server.key.in /tls.key && chown postgres /tls.key && chmod 600 /tls.key && \
           exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls.key' >/dev/null
}
run_pg tmdb-pg-tls 55433 server.pem server.key
run_pg tmdb-pg-ec 55434 ec-chain.pem ec-server.key
echo "certificados em $D; PostgreSQL com TLS em 55433 (RSA) e 55434 (ECDSA, com intermediária)"
