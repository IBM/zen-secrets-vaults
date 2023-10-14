#!/bin/bash

cd "$(dirname "$0")"/.. || exit

echo "Generating JWT..."

TOKEN=$(python3 utilities/generate_jwt.py)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "Generated Token: $TOKEN"
else
    echo "Failed to generate token"
    echo "Error: $TOKEN"
fi