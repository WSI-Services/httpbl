#!/usr/bin/env bash

REPO_DIR="$(dirname "$(readlink -f "$0/..")")"

"$REPO_DIR/vendor/phpunit/phpunit/phpunit" -c "$REPO_DIR/phpunit.xml"