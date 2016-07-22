# Collection
CSP Reporting is simple POSTing of a JSON object for every violation to a URL specified in the policy. What needs to be done in collection is therefor
 1. Taking in the violation reports
 2. Storing the reports / passing the reports to the generator

For this we use cgi/fcgi through php-cgi in bindaddress-mode or php-fpm in combination with nginx (or any other webserver).
