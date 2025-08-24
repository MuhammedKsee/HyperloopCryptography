#!/usr/bin/env bash
set -e
pip install -r requirements.txt
python certs/make_test_certs.py
python server.py &
sleep 1
python client.py
