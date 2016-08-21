FROM php:fpm

COPY src /var/www/html
RUN touch /var/www/html/csprg_collector.txt
RUN touch /var/www/html/csprg_collector2.txt
RUN chown -R www-data:www-data /var/www/html
