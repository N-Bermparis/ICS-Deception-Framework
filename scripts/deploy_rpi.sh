#!/usr/bin/env bash
set -euo pipefail


HOST="$1" # IP of the Raspberry Pi
USER="pi"


echo "Copying fake_plc to ${HOST}..."
scp -r src/iot-nodes/raspberrypi ${USER}@${HOST}:/home/${USER}/ics_honeypot/
ssh ${USER}@${HOST} "bash -s" <<'EOF'
cd /home/pi/ics_honeypot/raspberrypi
python3 -m venv .venv || true
source .venv/bin/activate
pip install --upgrade pip
pip install -r /home/pi/ics_honeypot/../requirements.txt || true
nohup python3 fake_plc.py controller.local --interval 30 > fake_plc.log 2>&1 &
EOF


echo "Deployed and started fake PLC on ${HOST}"
