"""
GarudaRush - Combined Streamlit App with Embedded API
This runs both the frontend UI and backend API in one Streamlit app
"""

import streamlit as st
import requests
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
from werkzeug.serving import make_server

# ===== FLASK API (Backend) =====

api = Flask(__name__)
api.config['SECRET_KEY'] = 'demo-secret-12345'
api.config['JWT_SECRET_KEY'] = 'demo-jwt-12345'
api.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
CORS(api, resources={r"/*": {"origins": "*"}})
jwt = JWTManager(api)

# In-memory storage
USERS = {}
TRAFFIC = []
ALERTS = []

@api.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email', '').lower()
        password = data.get('password', '')
        full_name = data.get('full_name', '')
        
        if not all([email, password, full_name]):
            return jsonify({'error': 'All fields required'}), 400
        
        if email in USERS:
            return jsonify({'error': 'User exists'}), 409
        
        user_id = str(uuid.uuid4())
        USERS[email] = {
            'id': user_id,
            'email': email,
            'password': generate_password_hash(password),
            'full_name': full_name,
            'role': 'user'
        }
        
        token = create_access_token(identity=user_id)
        
        return jsonify({
            'message': 'Registered successfully',
            'user': {'id': user_id, 'email': email, 'full_name': full_name, 'role': 'user'},
            'access_token': token
        }), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').lower()
        password = data.get('password', '')
        
        user = USERS.get(email)
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        token = create_access_token(identity=user['id'])
        
        return jsonify({
            'message': 'Login successful',
            'user': {'id': user['id'], 'email': user['email'], 'full_name': user['full_name'], 'role': user['role']},
            'access_token': token
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/dashboard/overview', methods=['GET'])
def get_overview():
    return jsonify({
        'overview': {
            'total_records': len(TRAFFIC) + len(ALERTS),
            'traffic_records': len(TRAFFIC),
            'alert_records': len(ALERTS)
        },
        'detection_stats': {
            'total_detections': len(ALERTS),
            'attack_rate': round((len(ALERTS) / len(TRAFFIC) * 100) if TRAFFIC else 0, 2),
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
        }
    }), 200

@api.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'users': len(USERS)}), 200

@api.route('/')
def root():
    return jsonify({'message': 'GarudaRush API', 'version': '1.0.0'}), 200

# Start Flask in background thread
class ServerThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)
        self.server = make_server('127.0.0.1', 5000, api, threaded=True)
        
    def run(self):
        self.server.serve_forever()
        
    def shutdown(self):
        self.server.shutdown()

# Start API server
if 'server' not in st.session_state:
    st.session_state.server = ServerThread()
    st.session_state.server.start()

# ===== STREAMLIT FRONTEND =====

st.set_page_config(page_title="GarudaRush", page_icon="🦅", layout="wide")

# Custom CSS
st.markdown("""
<style>
    .main {background-color: #0f1117;}
    .stButton>button {
        background-color: #00aaff;
        color: white;
        border-radius: 8px;
        padding: 10px 20px;
        border: none;
        font-weight: 600;
    }
    .stButton>button:hover {
        background-color: #0077c7;
    }
    h1 {color: #00aaff;}
    .metric-card {
        background: #151821;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #1e212d;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.token = None
    st.session_state.user = None

# Header
st.markdown("# 🦅 GarudaRush Dashboard")
st.markdown("### ML-Enhanced DDoS Detection System")

# Login/Register
if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Login to Your Account")
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login", key="login_btn"):
            try:
                response = requests.post(
                    'http://127.0.0.1:5000/api/auth/login',
                    json={'email': email, 'password': password}
                )
                if response.status_code == 200:
                    data = response.json()
                    st.session_state.logged_in = True
                    st.session_state.token = data['access_token']
                    st.session_state.user = data['user']
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error(response.json().get('error', 'Login failed'))
            except Exception as e:
                st.error(f"Error: {e}")
    
    with tab2:
        st.subheader("Create New Account")
        full_name = st.text_input("Full Name", key="reg_name")
        email_reg = st.text_input("Email", key="reg_email")
        password_reg = st.text_input("Password", type="password", key="reg_password")
        
        if st.button("Register", key="reg_btn"):
            try:
                response = requests.post(
                    'http://127.0.0.1:5000/api/auth/register',
                    json={'email': email_reg, 'password': password_reg, 'full_name': full_name}
                )
                if response.status_code == 201:
                    data = response.json()
                    st.session_state.logged_in = True
                    st.session_state.token = data['access_token']
                    st.session_state.user = data['user']
                    st.success("Registration successful!")
                    st.rerun()
                else:
                    st.error(response.json().get('error', 'Registration failed'))
            except Exception as e:
                st.error(f"Error: {e}")

else:
    # Dashboard (logged in)
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        st.markdown(f"**Welcome, {st.session_state.user['full_name']}!**")
    with col3:
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.token = None
            st.session_state.user = None
            st.rerun()
    
    # Fetch dashboard data
    try:
        response = requests.get('http://127.0.0.1:5000/api/dashboard/overview')
        if response.status_code == 200:
            data = response.json()
            
            # Metrics
            st.markdown("## 📊 System Overview")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Records", data['overview']['total_records'])
            with col2:
                st.metric("Traffic Records", data['overview']['traffic_records'])
            with col3:
                st.metric("Alert Records", data['overview']['alert_records'])
            with col4:
                st.metric("Detection Rate", f"{data['detection_stats']['attack_rate']}%")
            
            # Detection Stats
            st.markdown("## 🎯 Detection Statistics")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Detections", data['detection_stats']['total_detections'])
            with col2:
                st.metric("Attack Rate", f"{data['detection_stats']['attack_rate']}%")
            with col3:
                st.metric("False Positive", f"{data['detection_stats']['false_positive_rate']}%")
            with col4:
                st.metric("Avg Detection Time", f"{data['detection_stats']['avg_detection_time']}s")
            
            # Attack Distribution
            st.markdown("## 🔍 Attack Distribution")
            st.bar_chart(data['attack_distribution'])
            
            # Model Performance
            st.markdown("## 🏆 Model Performance")
            perf = data['model_performance']
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Accuracy", f"{perf['accuracy']}%")
            with col2:
                st.metric("Precision", f"{perf['precision']}%")
            with col3:
                st.metric("Recall", f"{perf['recall']}%")
            with col4:
                st.metric("F1 Score", f"{perf['f1_score']}%")
            
            st.success("✅ System running in demo mode - No MongoDB required!")
            
    except Exception as e:
        st.error(f"Error fetching dashboard data: {e}")
