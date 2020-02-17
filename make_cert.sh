#!/usr/bin/env bash
if [ $# -ne 2 ]; then
    echo "help:"
    echo "$0 <certificate_file> <f.q.d.n1,f.q.d.n2,...>"
    exit 1
fi

cert=$1
fqdns=$(echo $2 | tr "," "\n")

san=""
CN=""
for f in $fqdns; do
  if [ -z $CN ]; then CN=$f; fi
  san=$san"DNS:"$f","
done

echo $san

openssl req -x509 -newkey rsa:4096 -keyout $cert.key -out $cert.crt \
              -days 365 -nodes -extensions v3_ca \
              -subj "/C=FR/ST=IDF/L=Paris/O=This/OU=Thast/CN=$CN/subjectAltName=$san"
cat $cert.crt > $cert.pem
cat $cert.key >> $cert.pem