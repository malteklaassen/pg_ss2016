#!/bin/bash

## Prep
mkdir -p /usr/share/csprg
mkdir -p /etc/csprg
# Creating systemuser csprg if he doesn't already exists
id -u csprg &> /dev/null || useradd -r -s /usr/bin/nologin csprg
# Setting permissions on created directories
chown csprg:csprg /usr/share/csprg
chmod g+w /usr/share/csprg

## Proxy
echo "Enter the URL of the server you want to proxy (e.g. https://www2.example.com:80 ):"
read server
echo "Enter the address of the client that will run the tests (e.g. 192.168.56.101 ):"
read client
sed "s=\$SERVER=$server=g" skels/nginx.conf.skel | sed "s=\$CLIENT=$client=g" > /etc/nginx/nginx.conf
sed "s=\$POLICY=default-src 'none'=g" skels/csp.conf.skel > /etc/nginx/csp.conf
cp skels/csp.conf.skel /etc/nginx/csp.conf.skel
cp proxy/fastcgi.conf /etc/nginx/fastcgi.conf
cp proxy/fastcgi_params /etc/nginx/fastcgi_params

## Collector
cp collector/csprg_collector.php /usr/share/csprg/csprg_collector.php
cp collector/csprg_collector2.php /usr/share/csprg/csprg_collector2.php
cp collector/php-fcgi /usr/bin/php-fcgi

## Generator
echo "Enter the URL under which the client will find the server (e.g. http://192.168.56.1:8080 ):"
read self
sed "s=\$SELF=$self=g" skels/gen.conf.skel > /etc/csprg/gen.conf
cp generator/csprg_chrome /usr/bin/csprg_chrome

cp skels/csprg_apply /usr/bin/csprg_apply
