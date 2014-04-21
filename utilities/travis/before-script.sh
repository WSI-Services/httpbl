#!/usr/bin/env bash

set -ev

COMPOSER_PATH=$(whereis composer)
COMPOSER_PATH="/${COMPOSER_PATH#*/}"

sudo $COMPOSER_PATH self-update
$COMPOSER_PATH install --dev