ARG BUILD_FROM
FROM $BUILD_FROM

ENV LANG C.UTF-8

# PHP_INI_DIR to be symmetrical with official php docker image
ENV PHP_INI_DIR /etc/php/8.3

# Persistent runtime dependencies

RUN apk add --no-cache nginx openrc

RUN apk add --no-cache \
        php83 \
        php83-bcmath \
        php83-dom \
        php83-ctype \
        php83-curl \
        php83-fileinfo \
        php83-fpm \
        php83-gd \
        php83-iconv \
        php83-intl \
        php83-json \
        php83-mbstring \
        php83-mysqlnd \
        php83-opcache \
        php83-openssl \
        php83-pdo \
        php83-pdo_mysql \
        php83-pdo_pgsql \
        php83-pdo_sqlite \
        php83-phar \
        php83-posix \
        php83-simplexml \
        php83-session \
        php83-soap \
        php83-tokenizer \
        php83-xml \
        php83-xmlreader \
        php83-xmlwriter \
        php83-zip \
        curl

EXPOSE 8888
EXPOSE 8899

COPY run.sh /
COPY tls.conf /etc/nginx/snippets/
COPY default.conf /etc/nginx/http.d/
COPY www.conf /etc/php83/php-fpm.d/
COPY app/admin/ /var/www/admin/
COPY app/user/ /var/www/user/
RUN chmod a+x /run.sh
RUN mkdir -p /run/nginx
RUN mkdir -p /share/limited-guest-access
RUN ln -sf /dev/stderr /var/log/nginx/error.log
CMD ["/run.sh"]
