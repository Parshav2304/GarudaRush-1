# import os
# import time
# import traceback
# import threading
# from flask import Flask, jsonify
# from flask_cors import CORS
# from flask_jwt_extended import JWTManager
# from pymongo import MongoClient
# from datetime import timedelta
# from dotenv import load_dotenv

# # Load environment variables FIRST
# load_dotenv()

# # Global MongoDB variables
# mongo_client = None
# db = None
# RECONNECT_INTERVAL = 10  # seconds

# def try_connect():
#     """
#     Try to establish a MongoDB connection once (short timeout).
#     Returns True on success, False on failure.
#     """
#     global mongo_client, db
#     try:
#         uri = app.config.get('MONGO_URI')
#         mongo_db_name = app.config.get('MONGO_DB_NAME')
#         # Use a small serverSelectionTimeoutMS for quick failure so app can continue starting
#         client = MongoClient(uri, serverSelectionTimeoutMS=2000)
#         client.admin.command('ping')  # Quick check
#         mongo_client = client
#         db = mongo_client[mongo_db_name]
#         app.config['DB'] = db
#         print("✓ MongoDB connection established")
#         return True
#     except Exception as e:
#         print(f"✗ MongoDB connection failed: {e}")
#         traceback.print_exc()
#         mongo_client = None
#         db = None
#         app.config['DB'] = None
#         return False

# def monitor_mongo():
#     """
#     Background thread that keeps trying to connect to MongoDB if disconnected,
#     and pings periodically when connected to detect disconnects and re-establish them.
#     This does not block app startup.
#     """
#     global mongo_client, db
#     # Try an initial connect attempt
#     try_connect()

#     while True:
#         try:
#             if mongo_client is None:
#                 # Attempt to connect
#                 try_connect()
#             else:
#                 # If we have a client, do a lightweight ping to ensure it's alive
#                 try:
#                     mongo_client.admin.command('ping')
#                 except Exception as ping_exc:
#                     print(f"✗ MongoDB ping failed (will retry): {ping_exc}")
#                     traceback.print_exc()
#                     # Mark as disconnected and attempt reconnection on next iterations
#                     try:
#                         mongo_client.close()
#                     except Exception:
#                         pass
#                     mongo_client = None
#                     db = None
#                     app.config['DB'] = None
#         except Exception:
#             # Catch-all to prevent thread from dying
#             traceback.print_exc()
#             mongo_client = None
#             db = None
#             app.config['DB'] = None
#         # Sleep before next check/attempt
#         time.sleep(RECONNECT_INTERVAL)

# # Initialize Flask app
# app = Flask(__name__)

# # Configuration
# app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
# app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-this')
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 24)))
# app.config['MONGO_URI'] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/GarudaRush')
# app.config['MONGO_DB_NAME'] = os.getenv('MONGODBNAME', 'GarudaRush')

# # Enable CORS
# CORS(app, 
#      resources={r"/*": {"origins": os.getenv('FRONTEND_URL', 'http://localhost:3000'), 
#                        "methods": ["GET", "POST", "PUT", "DELETE"],
#                        "allow_headers": ["Content-Type", "Authorization"]}})

# # Initialize JWT
# jwt = JWTManager(app)

# # Start MongoDB monitor thread (NON-BLOCKING)
# monitor_thread = threading.Thread(target=monitor_mongo, daemon=True)
# monitor_thread.start()

# # Import and register routes AFTER app config
# from routes.auth import auth_bp
# from routes.traffic import traffic_bp
# from routes.dashboard import dashboard_bp
# from routes.alerts import alerts_bp

# app.register_blueprint(auth_bp, url_prefix='/api/auth')
# app.register_blueprint(traffic_bp, url_prefix='/api/traffic')
# app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
# app.register_blueprint(alerts_bp, url_prefix='/api/alerts')

# # Error handlers
# @app.errorhandler(404)
# def not_found_error(error):
#     return jsonify({"error": "Resource not found"}), 404

# @app.errorhandler(500)
# def internal_error(error):
#     return jsonify({"error": "Internal server error"}), 500

# # JWT error handlers
# @jwt.expired_token_loader
# def expired_token_callback(jwt_header, jwt_payload):
#     return jsonify({"error": "Token has expired", "message": "Please login again"}), 401

# @jwt.invalid_token_loader
# def invalid_token_callback(error):
#     return jsonify({"error": "Invalid token", "message": "Token verification failed"}), 401

# @jwt.unauthorized_loader
# def missing_token_callback(error):
#     return jsonify({"error": "Authorization required", "message": "Request does not contain an access token"}), 401

# # Health check endpoint
# @app.route('/api/health', methods=['GET'])
# def health_check():
#     db_status = "connected" if app.config.get('DB') is not None else "disconnected"
#     return jsonify({
#         "status": "healthy", 
#         "service": "GarudaRush API", 
#         "version": "1.0.0", 
#         "database": db_status
#     }), 200

# # Root endpoint
# @app.route('/')
# def index():
#     return jsonify({
#         "message": "GarudaRush API", 
#         "version": "1.0.0",
#         "endpoints": {
#             "auth": "/api/auth",
#             "traffic": "/api/traffic", 
#             "dashboard": "/api/dashboard",
#             "alerts": "/api/alerts",
#             "health": "/api/health"
#         }
#     }), 200

# if __name__ == '__main__':
#     port = int(os.getenv('PORT', 5000))
#     debug = os.getenv('FLASK_ENV', 'production') == 'development'
#     print(f"""
#     ╔═══════════════════════════════════════╗
#     ║     🦅 GarudaRush Backend Started     ║
#     ║                                       ║
#     ║  Port: {port}                            ║
#     ║  Debug: {debug}                         ║
#     ║  MongoDB: {'Connected' if db else 'Disconnected'}              ║
#     ╚═══════════════════════════════════════╝
#     """)
#     app.run(host='0.0.0.0', port=port, debug=debug)

"""
GarudaRush Backend Application - DEMO MODE (No MongoDB Required)
This version uses in-memory storage for demonstration purposes
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import uuid

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'demo-secret-key-12345')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'demo-jwt-secret-12345')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize JWT
jwt = JWTManager(app)

# IN-MEMORY DATABASE (for demo purposes)
USERS_DB = {}
TRAFFIC_DB = []
ALERTS_DB = []

print("🎯 Running in DEMO MODE - No MongoDB required!")
print("📦 Using in-memory storage (data will reset on restart)")

# ==================== AUTH ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        
        if not email or not password or not full_name:
            return jsonify({'error': 'All fields are required'}), 400
        
        if email in USERS_DB:
            return jsonify({'error': 'User already exists'}), 409
        
        # Create user
        user_id = str(uuid.uuid4())
        USERS_DB[email] = {
            'id': user_id,
            'email': email,
            'password': generate_password_hash(password),
            'full_name': full_name,
            'role': 'user',
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Create token
        access_token = create_access_token(identity=user_id)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': user_id,
                'email': email,
                'full_name': full_name,
                'role': 'user'
            },
            'access_token': access_token
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = USERS_DB.get(email)
        
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        access_token = create_access_token(identity=user['id'])
        
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role']
            },
            'access_token': access_token
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user"""
    try:
        user_id = get_jwt_identity()
        
        for user in USERS_DB.values():
            if user['id'] == user_id:
                return jsonify({
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'full_name': user['full_name'],
                        'role': user['role']
                    }
                }), 200
        
        return jsonify({'error': 'User not found'}), 404
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== TRAFFIC ROUTES ====================

@app.route('/api/traffic/submit', methods=['POST'])
@jwt_required()
def submit_traffic():
    """Submit traffic data"""
    try:
        data = request.get_json()
        
        traffic_entry = {
            'id': str(uuid.uuid4()),
            'agent_id': data.get('agent_id', 'demo-agent'),
            'packet_count': data.get('packet_count', 0),
            'byte_count': data.get('byte_count', 0),
            'packet_rate': data.get('packet_rate', 0),
            'protocol': data.get('protocol', 'TCP'),
            'is_suspicious': data.get('is_suspicious', False),
            'ml_confidence': data.get('ml_confidence', 0.0),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        TRAFFIC_DB.append(traffic_entry)
        
        # Keep only last 1000 entries
        if len(TRAFFIC_DB) > 1000:
            TRAFFIC_DB.pop(0)
        
        # Create alert if suspicious
        if traffic_entry['is_suspicious']:
            alert = {
                'id': str(uuid.uuid4()),
                'attack_type': 'DDoS Attack',
                'severity': 'high',
                'status': 'active',
                'confidence': traffic_entry['ml_confidence'],
                'packet_count': traffic_entry['packet_count'],
                'timestamp': datetime.utcnow().isoformat()
            }
            ALERTS_DB.append(alert)
        
        return jsonify({'message': 'Traffic data submitted', 'id': traffic_entry['id']}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/live', methods=['GET'])
@jwt_required()
def get_live_traffic():
    """Get live traffic data"""
    try:
        limit = int(request.args.get('limit', 20))
        
        recent_traffic = TRAFFIC_DB[-limit:] if TRAFFIC_DB else []
        
        normal = []
        suspicious = []
        
        for t in recent_traffic:
            timestamp = t.get('timestamp', '')
            time_str = timestamp.split('T')[1][:8] if 'T' in timestamp else '00:00:00'
            
            point = {
                'time': time_str,
                'value': t.get('packet_rate', 0)
            }
            
            if t.get('is_suspicious'):
                suspicious.append(point)
            else:
                normal.append(point)
        
        return jsonify({
            'normal': normal,
            'suspicious': suspicious,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic/stats', methods=['GET'])
@jwt_required()
def get_traffic_stats():
    """Get traffic statistics"""
    try:
        total_packets = sum(t.get('packet_count', 0) for t in TRAFFIC_DB)
        total_bytes = sum(t.get('byte_count', 0) for t in TRAFFIC_DB)
        
        return jsonify({
            'stats': {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'recent_attacks': len([a for a in ALERTS_DB if a.get('status') == 'active'])
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== DASHBOARD ROUTES ====================

@app.route('/api/dashboard/overview', methods=['GET'])
@jwt_required()
def get_dashboard_overview():
    """Get dashboard overview"""
    try:
        total_detections = len(ALERTS_DB)
        attack_rate = (total_detections / len(TRAFFIC_DB) * 100) if TRAFFIC_DB else 0
        
        return jsonify({
            'overview': {
                'total_records': len(TRAFFIC_DB) + len(ALERTS_DB),
                'traffic_records': len(TRAFFIC_DB),
                'alert_records': len(ALERTS_DB)
            },
            'detection_stats': {
                'total_detections': total_detections,
                'attack_rate': round(attack_rate, 2),
                'false_positive_rate': 2.5,
                'avg_detection_time': 3.2
            },
            'attack_distribution': {
                'SYN Flood': 35,
                'HTTP Flood': 25,
                'UDP Flood': 20,
                'DNS Amplification': 15,
                'Slowloris': 3,
                'Other': 2
            },
            'model_performance': {
                'accuracy': 98.5,
                'precision': 97.2,
                'recall': 96.8,
                'f1_score': 97.0
            },
            'system_info': {
                'active_agents': 1,
                'uptime_hours': 24,
                'last_updated': datetime.utcnow().isoformat()
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ALERTS ROUTES ====================

@app.route('/api/alerts/', methods=['GET'])
@jwt_required()
def get_alerts():
    """Get alerts"""
    try:
        limit = int(request.args.get('limit', 50))
        recent_alerts = ALERTS_DB[-limit:] if ALERTS_DB else []
        
        return jsonify({
            'alerts': recent_alerts,
            'pagination': {
                'total': len(ALERTS_DB),
                'page': 1,
                'limit': limit,
                'total_pages': 1
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/summary', methods=['GET'])
@jwt_required()
def get_alerts_summary():
    """Get alerts summary"""
    try:
        return jsonify({
            'summary': {
                'by_severity': {
                    'low': 5,
                    'medium': 10,
                    'high': 15,
                    'critical': 8
                },
                'by_status': {
                    'active': len([a for a in ALERTS_DB if a.get('status') == 'active']),
                    'acknowledged': 0,
                    'resolved': 0
                },
                'total': len(ALERTS_DB)
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization required'}), 401

# ==================== HEALTH & ROOT ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'GarudaRush API (Demo Mode)',
        'version': '1.0.0-demo',
        'database': 'in-memory',
        'users': len(USERS_DB),
        'traffic_records': len(TRAFFIC_DB),
        'alerts': len(ALERTS_DB)
    }), 200

@app.route('/')
def index():
    return jsonify({
        'message': 'GarudaRush API - Demo Mode',
        'version': '1.0.0-demo',
        'mode': 'In-Memory Storage (No MongoDB required)',
        'endpoints': {
            'auth': '/api/auth',
            'traffic': '/api/traffic',
            'dashboard': '/api/dashboard',
            'alerts': '/api/alerts',
            'health': '/api/health'
        }
    }), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    
    print(f"""
    ╔═══════════════════════════════════════╗
    ║   🦅 GarudaRush Backend - DEMO MODE   ║
    ║                                       ║
    ║  Port: {port}                            ║
    ║  Mode: In-Memory Storage              ║
    ║  MongoDB: Not Required ✅              ║
    ╚═══════════════════════════════════════╝
    
    ✅ No database setup needed!
    ✅ Perfect for demos and presentations
    ✅ Data resets on restart
    
    Ready to accept connections!
    """)
    
    app.run(host='0.0.0.0', port=port, debug=debug)
