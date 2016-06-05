# Proxy
A simple python3 HTTP reverse-proxy for playing around with different CSPs.

Call with `python3 proxy.py example.com` where example.com is the site to be proxied. By default the proxy listens on Port 8080 and takes the CSP Header Value from the file `csp-string` in the CWD.

The `gm.html` and `gm.js` (when placed on the proxied server) together with the CSP Header Value `script-src 'self' maps.googleapis.com` can be used as an example. (There still is a ressource being blocked, I suspect it's the inline style, I haven't really looked into it yet.)
