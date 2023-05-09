#!/bin/bash
# Based on answer from Diego Woitasen: https://stackoverflow.com/questions/10175812/how-to-generate-a-self-signed-ssl-certificate-using-openssl#answer-10176685
# Just left most values at their placeholders because the cert isn't checked by the test client anyway.
openssl req -x509 -newkey rsa:4096 -keyout server_priv_key.pem -out server_cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.54.17"