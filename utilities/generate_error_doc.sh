#!/bin/sh
set -e

python3 utils/generate_error_doc.py
echo "Moving error_codes.md to docs/apidoc/error_codes.md"
mv error_codes.md ../docs/apidoc/error_codes.md
