import os
import time
import traceback
import threading
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables FIRST
load_dotenv()

# Global MongoDB variables
mongo_client = None
db = None
RECONNECT_INTERVAL = 10  # seconds

def try_connect():
    """
    Try to establish a MongoDB connection once (short timeout).
    Returns True on success, False on failure.
    """
    global mongo_client, db
    try:
        uri = app.config.get('MONGO_URI')
        mongo_db_name = app.config.get('MONGO_DB_NAME')
        # Use a small serverSelectionTimeoutMS for quick failure so app can continue starting
        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        client.admin.command('ping')  # Quick check
        mongo_client = client
        db = mongo_client[mongo_db_name]
        app.config['DB'] = db
        print("✓ MongoDB connection established")
        return True
    except Exception as e:
        print(f"✗ MongoDB connection failed: {e}")
        traceback.print_exc()
        mongo_client = None
        db = None
        app.config['DB'] = None
        return False

def monitor_mongo():
    """
    Background thread that keeps trying to connect to MongoDB if disconnected,
    and pings periodically when connected to detect disconnects and re-establish them.
    This does not block app startup.
    """
    global mongo_client, db
    # Try an initial connect attempt
    try_connect()

    while True:
        try:
            if mongo_client is None:
                # Attempt to connect
                try_connect()
            else:
                # If we have a client, do a lightweight ping to ensure it's alive
                try:
                    mongo_client.admin.command('ping')
                except Exception as ping_exc:
                    print(f"✗ MongoDB ping failed (will retry): {ping_exc}")
                    traceback.print_exc()
                    # Mark as disconnected and attempt reconnection on next iterations
                    try:
                        mongo_client.close()
                    except Exception:
                        pass
                    mongo_client = None
                    db = None
                    app.config['DB'] = None
        except Exception:
            # Catch-all to prevent thread from dying
            traceback.print_exc()
            mongo_client = None
            db = None
            app.config['DB'] = None
        # Sleep before next check/attempt
        time.sleep(RECONNECT_INTERVAL)

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-this')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 24)))
app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/GarudaRush')
app.config['MONGO_DB_NAME'] = os.getenv('MONGODBNAME', 'GarudaRush')

# Enable CORS
CORS(app, 
     resources={r"/*": {"origins": os.getenv('FRONTEND_URL', 'http://localhost:3000'), 
                       "methods": ["GET", "POST", "PUT", "DELETE"],
                       "allow_headers": ["Content-Type", "Authorization"]}})

# Initialize JWT
jwt = JWTManager(app)

# Start MongoDB monitor thread (NON-BLOCKING)
monitor_thread = threading.Thread(target=monitor_mongo, daemon=True)
monitor_thread.start()

# Import and register routes AFTER app config
from routes.auth import auth_bp
from routes.traffic import traffic_bp
from routes.dashboard import dashboard_bp
from routes.alerts import alerts_bp

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(traffic_bp, url_prefix='/api/traffic')
app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
app.register_blueprint(alerts_bp, url_prefix='/api/alerts')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has expired", "message": "Please login again"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"error": "Invalid token", "message": "Token verification failed"}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({"error": "Authorization required", "message": "Request does not contain an access token"}), 401

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    db_status = "connected" if app.config.get('DB') is not None else "disconnected"
    return jsonify({
        "status": "healthy", 
        "service": "GarudaRush API", 
        "version": "1.0.0", 
        "database": db_status
    }), 200

# Root endpoint
@app.route('/')
def index():
    return jsonify({
        "message": "GarudaRush API", 
        "version": "1.0.0",
        "endpoints": {
            "auth": "/api/auth",
            "traffic": "/api/traffic", 
            "dashboard": "/api/dashboard",
            "alerts": "/api/alerts",
            "health": "/api/health"
        }
    }), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    print(f"""
    ╔═══════════════════════════════════════╗
    ║     🦅 GarudaRush Backend Started     ║
    ║                                       ║
    ║  Port: {port}                            ║
    ║  Debug: {debug}                         ║
    ║  MongoDB: {'Connected' if db else 'Disconnected'}              ║
    ╚═══════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=port, debug=debug)
