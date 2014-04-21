#!/usr/bin/env bash

set -ev

COMPOSER_PATH="~/.phpenv/versions/$TRAVIS_PHP_VERSION/bin/composer.phar"

sudo $COMPOSER_PATH self-update
$COMPOSER_PATH install --dev