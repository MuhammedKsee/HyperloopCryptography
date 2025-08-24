@echo off
pip install -r requirements.txt
python certs\make_test_certs.py
start /B python server.py
ping -n 2 127.0.0.1 >NUL
python client.py
