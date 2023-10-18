import jwt
import os
import time
from datetime import datetime, timedelta

def generate_jwt():
    try:
        PRIVATE_KEY_PATH = os.environ.get('PRIVATE_KEY_PATH')

        if PRIVATE_KEY_PATH is None:
            raise RuntimeError("PRIVATE_KEY_PATH environment variable is not set")
        
        with open(PRIVATE_KEY_PATH, 'r') as key_file:
            private_key = key_file.read()

        currentTime = datetime.utcnow()
        expiresAt = currentTime + timedelta(minutes=1440)

        epoch = datetime.utcfromtimestamp(0)
        iat = (currentTime - epoch).total_seconds()
        exp = (expiresAt - epoch).total_seconds()

        claimInfo = {
            "uid": "1000330999",
            "sub": "1000330999",
            "iat": int(iat),
            "exp": int(exp),
            "iss": "ZEN-SECRETS",
            "aud": "ZEN-VAULT-BRIDGE",
        }
        
        encoded_jwt = jwt.encode(claimInfo, private_key, algorithm='RS256')
        return encoded_jwt

    except Exception as e:
        return str(e)

if __name__ == "__main__":
    print(generate_jwt())
