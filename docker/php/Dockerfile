FROM php:7.4.0-fpm

RUN apt-get update && docker-php-ext-install pdo_mysql
ADD https://raw.githubusercontent.com/mlocati/docker-php-extension-installer/master/install-php-extensions /usr/local/bin/
RUN chmod uga+x /usr/local/bin/install-php-extensions && sync && install-php-extensions gd xdebug memcached mysqli