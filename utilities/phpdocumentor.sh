#!/usr/bin/env bash

REPO_DIR="$(dirname "$(readlink -f "$0/..")")"

"$REPO_DIR/vendor/phpdocumentor/phpdocumentor/bin/phpdoc.php" -c "$REPO_DIR/phpdoc.dist.xml"