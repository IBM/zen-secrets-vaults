from routes import app
from framework.utils import load_jwt_public_keys 

load_jwt_public_keys()

if __name__ == "__main__":
    app.run()