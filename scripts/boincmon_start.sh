#!/bin/bash

read -sp "Please enter master password: " password
echo
echo $password | nohup ./pi_boincmon.py 1>/dev/null 2>&1 &
sleep 2s
echo "Service started - now tailing logs. Press CTRL + C to exit."
tail -f ../logs/pi_boincmon_service.log

