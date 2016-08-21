# Tests
## Dependencies
Additionally to the dependencies needed for CSPRG we also need:
 1. Selenium WebDriver for Chrome/Python
 2. A possibiliy to headlessly start Chrome

## Running the test
From the `projektarbeit` folder simply run `test/install_test.sh` (if there is no other instance of CSPRG running).

This will set up CSPRG using `http://bonnbox.stw-bonn.de`, load a few pages via Selenium on `proxygen`, generate a policy, apply this policy to `proxyprod` and print the policy sent by `proxyprod` after application. Then it will uninstall CSPRG from the system again.

The last line of the output should look like this:
```
Content-Security-Policy: media-src 'self'; img-src 'self' https://pbs.twimg.com https://csi.gstatic.com https://maps.googleapis.com https://maps.gstatic.com; style-src 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' https://maps.googleapis.com; font-src https://fonts.gstatic.com; report-uri /csprg_collector2.php
```
