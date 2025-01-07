from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    CORS(app)
    
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )
    
    from app.routes import api
    app.register_blueprint(api, url_prefix='/api')
    
    return app