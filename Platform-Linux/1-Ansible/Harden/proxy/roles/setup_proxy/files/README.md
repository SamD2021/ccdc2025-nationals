To create a self-signed certificate.

```bash
openssl req -newkey rsa:2048 -nodes -keyout haproxy.key -x509 -days 365 -out haproxy.crt -subj "/CN=your.domain.com"
cat haproxy.key haproxy.crt > haproxy.pem
```
