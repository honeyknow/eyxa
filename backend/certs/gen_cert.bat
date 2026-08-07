@echo off
REM Generates a self-signed TLS certificate for local Eyxa backend development.
REM Valid for 365 days. Place key.pem and cert.pem in eyxa/backend/certs/.
REM HARDENING: Replace with a CA-signed certificate before Phase 9 validation.
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes ^
  -subj "/CN=localhost/O=Eyxa-Dev/C=IN" ^
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
echo [OK] cert.pem and key.pem generated
