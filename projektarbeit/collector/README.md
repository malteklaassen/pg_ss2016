# Collection
CSP Reporting is simple POSTing of a JSON object for every violation to a URL specified in the policy. What needs to be done in collection is therefor
 1. Taking in the violation reports
 2. Storing the reports / passing the reports to the generator

For this we use a php:fpm Docker container, listening on port 9000.

## Configurations
A full example configuration can be found in the [proxy-folders](../proxygen/).

When using nginx with fastcgi for the `csprg_collector.php` or `csprg_collector2.php` files we need to configure nginx to pass these requests to our locally running php-cgi instance. This looks something like this:

```
location ~ csprg_collector.php$ {
	fastcgi_pass	127.0.0.1:9000;
	fastcgi_param	SCRIPT_FILENAME	$document_root$fastcgi_script_name;
	include	fastcgi_params;
	include	fastcgi.conf;
}
```

Also, the policy of the generation-server must include something along the lines of `report-uri /csprg_collector.php`.

The other thing we need is for the according php-files to be placed in `$document_root` (which we have set in the example configuration to `/var/www/html/`) and the user `www-data` has to have write access to that folder or at least the according files.
