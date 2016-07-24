
build: generator_build

generator_build: generator/csprg_chrome.hs
	$(MAKE) -C generator

install: proxy_install generator_install collector_install

proxy_install: proxy/nginx.conf proxy/fastcgi.conf proxy/fastcgi_params
	mkdir /usr/share/csprg
	cp proxy/nginx.conf /etc/nginx/nginx.conf
	cp proxy/fastcgi.conf /etc/nginx/fastcgi.conf
	cp proxy/fastcgi_params /etc/nginx/fastcgi_params

collector_install: collector/php-fcgi collector/csprg_collector.php collector/csprg_collector2.php
	cp collector/csprg_collector.php /usr/share/csprg_collector.php
	cp collector/csprg_collector2.php /usr/share/csprg_collector2.php
	# todo: install php-fcgi
        
generator_install: generator/gen.conf generator/csprg_chrome
	cp generator/gen.conf /usr/share/csprg/gen.conf
	cp genertor/csprg_chrome /usr/bin/csprg_chrome
