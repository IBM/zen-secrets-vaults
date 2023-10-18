#!/bin/bash
set -e

cd "$(dirname "$0")" || exit

if [ ! -d "env" ]; then
    python3 -m venv env
    source env/bin/activate
    
    # Checking if PyJWT is installed, if not installing it
    if ! pip show pyjwt > /dev/null 2>&1; then
        pip install pyjwt[crypto]
    fi
    
else
    source env/bin/activate
fi

echo "Generating JWT..."

TOKEN=$(python3 utils/generate_test_jwt.py)
EXIT_CODE=$?

deactivate

# Print the token or error message
if [ $EXIT_CODE -eq 0 ]; then
    echo "Generated Token: $TOKEN"
else
    echo "Failed to generate token"
    echo "Error: $TOKEN"
fi
