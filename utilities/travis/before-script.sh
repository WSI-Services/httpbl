#!/usr/bin/env bash

set -ev

composer self-update
composer install --dev