#!/usr/bin/with-contenv bashio
chmod 777 /data/
mkdir -p /data/links
chmod -R 666 /data/links
chmod 777 /data/links
chmod 644 /data/options.json
is_ssl_active=$(cat /data/options.json |jq .activate_tls)
if [ $is_ssl_active = true ]; then
    if test -f "/ssl/privkey.pem"; then
        sed  -i 's/  listen 8888 default_server;/  include \/etc\/nginx\/snippets\/tls.conf;/g' /etc/nginx/http.d/default.conf
    fi;
fi;

# Start nginx
if ! pgrep nginx >/dev/null; then
    nginx
fi

# ---- PHP-FPM auto-detection (CRITICAL PART) ----
for php_fpm in \
    /usr/sbin/php-fpm83 \
    /usr/sbin/php-fpm82 \
    /usr/sbin/php-fpm8 \
    /usr/sbin/php-fpm \
    /usr/bin/php-fpm83 \
    /usr/bin/php-fpm82 \
    /usr/bin/php-fpm8 \
    /usr/bin/php-fpm
do
    if [ -x "$php_fpm" ]; then
        bashio::log.info "Using PHP-FPM binary: $php_fpm"
        exec "$php_fpm" -F
    fi
done