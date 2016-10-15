#!/bin/bash

## Prepare config and data folders
mkdir -p /etc/csprg
mkdir -p /usr/share/csprg
mkdir -p /usr/share/csprg/data
if [ ! -f /usr/share/csprg/csprg_collector.csp ]; then
	echo "default-src 'none'" > /usr/share/csprg/csprg_collector.csp
fi

# Get input from user
echo "Enter the URL of the server you want to proxy (e.g. https://www2.example.com:80 ):"
read server
echo "Enter the URL under which the client will find the server (e.g. http://192.168.56.1:8080 ):"
read self

## Configure the proxies
sed "s=\$SERVER=$server=g" proxygen/src/nginx.conf.skel > proxygen/src/nginx.conf
sed "s=\$SERVER=$server=g" proxyprod/src/nginx.conf.skel > proxyprod/src/nginx.conf

read policy < /usr/share/csprg/csprg_collector.csp
sed "s=\$POLICY=$policy=g" proxyprod/src/csp.conf.skel > proxyprod/src/csp.conf

## Copy the Containers
cp -r proxygen /usr/share/csprg
cp -r proxyprod /usr/share/csprg

## Collector
cp -r collector /usr/share/csprg
cp src/csprg_reset /usr/bin/csprg_reset
chmod -R og+w /usr/share/csprg/data

## Copy the docker-compose file and build
cp docker-compose.yml /usr/share/csprg/docker-compose.yml
docker-compose -f /usr/share/csprg/docker-compose.yml build
cp src/csprg_start /usr/bin/csprg_start
cp src/csprg_stop /usr/bin/csprg_stop

## Generator
sed "s=\$SELF=$self=g" generator/gen.conf.skel > /etc/csprg/gen.conf
cp generator/csprg_generate /usr/bin/csprg_generate
cp generator/csprg_chrome /usr/bin/csprg_chrome

## Uninstall
cp src/csprg_uninstall /usr/bin/csprg_uninstall
