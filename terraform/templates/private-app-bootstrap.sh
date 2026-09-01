#!/bin/bash
set -euxo pipefail

useradd --system --home-dir /opt/soclab-app --shell /sbin/nologin soclab-app
install -d -o soclab-app -g soclab-app -m 0755 /opt/soclab-app
install -d -o root -g soclab-app -m 0750 /etc/soclab-app

cat > /opt/soclab-app/index.html <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Hybrid SOC Lab AWS Application</title>
</head>
<body>
  <h1>Hybrid SOC Lab AWS Application</h1>
  <p>This private HTTPS service is reachable only through the approved hybrid path.</p>
</body>
</html>
EOF

chown soclab-app:soclab-app /opt/soclab-app/index.html

openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout /etc/soclab-app/server.key \
  -out /etc/soclab-app/server.crt \
  -days 365 \
  -subj "/CN=10.50.20.10"

chown root:soclab-app /etc/soclab-app/server.key /etc/soclab-app/server.crt
chmod 0640 /etc/soclab-app/server.key /etc/soclab-app/server.crt

cat > /opt/soclab-app/server.py <<'PYTHON'
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
import ssl

os.chdir("/opt/soclab-app")

server = ThreadingHTTPServer(("0.0.0.0", 443), SimpleHTTPRequestHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    certfile="/etc/soclab-app/server.crt",
    keyfile="/etc/soclab-app/server.key",
)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PYTHON

chown soclab-app:soclab-app /opt/soclab-app/server.py
chmod 0750 /opt/soclab-app/server.py

cat > /etc/systemd/system/soclab-app.service <<'EOF'
[Unit]
Description=Hybrid SOC Lab private HTTPS application
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=soclab-app
Group=soclab-app
WorkingDirectory=/opt/soclab-app
ExecStart=/usr/bin/python3 /opt/soclab-app/server.py
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now soclab-app.service

touch /var/lib/soclab-app-bootstrap-complete
