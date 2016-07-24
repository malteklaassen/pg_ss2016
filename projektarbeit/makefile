build: generator_build

generator_build: generator/csprg_chrome.hs
	$(MAKE) -C generator

install: prep_install proxy_install generator_install collector_install

prep_install:
	# Creating directories
	mkdir -p /usr/share/csprg
	mkdir -p /etc/csprg
	# Creating systemuser csprg if he doesnt already exists
	./install_util/csprg_user.sh
	# Setting permissions on created directories
	chown csprg:csprg /usr/share/csprg
	chmod g+w /usr/share/csprg # so that a user can write there himself if he has the right permissions

proxy_install: proxy/nginx.conf proxy/fastcgi.conf proxy/fastcgi_params
	# Setting proxy-configurations.
	cp proxy/nginx.conf /etc/nginx/nginx.conf
	cp proxy/fastcgi.conf /etc/nginx/fastcgi.conf
	cp proxy/fastcgi_params /etc/nginx/fastcgi_params

collector_install: collector/php-fcgi collector/csprg_collector.php collector/csprg_collector2.php
	cp collector/csprg_collector.php /usr/share/csprg/csprg_collector.php
	cp collector/csprg_collector2.php /usr/share/csprg/csprg_collector2.php
	cp collector/php-fcgi /usr/bin/php-fcgi
        
generator_install: generator/gen.conf generator/csprg_chrome
	cp generator/gen.conf /etc/csprg/gen.conf
	cp generator/csprg_chrome /usr/bin/csprg_chrome
