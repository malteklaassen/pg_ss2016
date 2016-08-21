#!/bin/bash
sudo ./install.sh < test/install_input
sleep 2
csprg_start
sleep 2
python test/selenium_gen.py
sleep 2
sudo csprg_generate
sleep 2
CSP=`curl -i http://localhost:80/ 2> /dev/null | grep "^Content-Security-Policy: " | head -n 1`
sleep 2
sudo csprg_uninstall
sleep 2
echo ""
echo "The CSP-Header sent now is"
echo $CSP
