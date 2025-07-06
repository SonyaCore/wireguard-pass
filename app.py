
# app_railway.py
#!/usr/bin/env python3
"""
WireGuard PaaS API Server - Railway Deployment Version
Modified for Railway cloud deployment with persistent storage considerations
"""

import os
import json
import uuid
import subprocess
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import sqlite3
import secrets
import base64
import tempfile

from flask import Flask, request, jsonify, send_file, Response
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Railway configuration - using /tmp for non-persistent storage
WG_CONFIG_DIR = Path('/tmp/wireguard')
WG_KEYS_DIR = Path('/tmp/wireguard-paas/keys')
DATABASE_PATH = os.environ.get('DATABASE_URL', '/tmp/wireguard-paas/wireguard.db')

# Railway specific settings
PORT = int(os.environ.get('PORT', 8080))
SERVER_ENDPOINT = os.environ.get('SERVER_ENDPOINT', 'wg-pass.railway.app:51820')
RAILWAY_STATIC_URL = os.environ.get('RAILWAY_STATIC_URL', '')

# Network configuration
VPN_NETWORK = ipaddress.IPv4Network('10.0.0.0/24')

# Ensure directories exist
WG_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
WG_KEYS_DIR.mkdir(parents=True, exist_ok=True)
Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

class RailwayWireGuardManager:
    """WireGuard manager optimized for Railway deployment"""
    
    def __init__(self):
        self.init_database()
        self.init_server_keys()
        self.mock_mode = self.check_mock_mode()
    
    def check_mock_mode(self) -> bool:
        """Check if we should run in mock mode (for Railway limitations)"""
        try:
            # Try to run wg command
            result = subprocess.run(['wg', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode != 0
        except:
            return True
    
    def init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # WireGuard peers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wg_peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                peer_name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_handshake TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Server configuration table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_config (
                id INTEGER PRIMARY KEY,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def init_server_keys(self):
        """Initialize server WireGuard keys"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM server_config')
        if cursor.fetchone()[0] == 0:
            # Generate server keys
            private_key = self.generate_private_key()
            public_key = self.generate_public_key(private_key)
            
            cursor.execute('''
                INSERT INTO server_config (private_key, public_key, ip_address, port)
                VALUES (?, ?, ?, ?)
            ''', (private_key, public_key, '10.0.0.1', 51820))
            
            conn.commit()
        
        conn.close()
    
    def generate_private_key(self) -> str:
        """Generate WireGuard private key"""
        if self.mock_mode:
            # Generate mock key for demo purposes
            return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        
        try:
            result = subprocess.run(['wg', 'genkey'], capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except:
            # Fallback to mock key
            return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
    
    def generate_public_key(self, private_key: str) -> str:
        """Generate WireGuard public key from private key"""
        if self.mock_mode:
            # Generate mock public key
            return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        
        try:
            result = subprocess.run(['wg', 'pubkey'], input=private_key, capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except:
            # Fallback to mock key
            return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
    
    def get_next_ip(self) -> str:
        """Get next available IP address"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT ip_address FROM wg_peers WHERE is_active = 1')
        used_ips = [row[0] for row in cursor.fetchall()]
        
        # Add server IP
        used_ips.append('10.0.0.1')
        
        for ip in VPN_NETWORK.hosts():
            if str(ip) not in used_ips:
                conn.close()
                return str(ip)
        
        conn.close()
        raise Exception("No available IP addresses")
    
    def create_peer(self, user_id: int, peer_name: str) -> Dict:
        """Create a new WireGuard peer"""
        private_key = self.generate_private_key()
        public_key = self.generate_public_key(private_key)
        ip_address = self.get_next_ip()
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO wg_peers (user_id, peer_name, public_key, private_key, ip_address)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, peer_name, public_key, private_key, ip_address))
        
        peer_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            'id': peer_id,
            'peer_name': peer_name,
            'public_key': public_key,
            'private_key': private_key,
            'ip_address': ip_address
        }
    
    def get_server_config(self) -> Dict:
        """Get server configuration"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT private_key, public_key, ip_address, port FROM server_config LIMIT 1')
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'private_key': row[0],
                'public_key': row[1],
                'ip_address': row[2],
                'port': row[3]
            }
        return {}
    
    def generate_client_config(self, peer_id: int) -> str:
        """Generate client configuration file"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT private_key, ip_address FROM wg_peers WHERE id = ? AND is_active = 1
        ''', (peer_id,))
        
        peer_data = cursor.fetchone()
        if not peer_data:
            conn.close()
            return ""
        
        private_key, ip_address = peer_data
        conn.close()
        
        server_config = self.get_server_config()
        
        # Use Railway URL if available
        endpoint = SERVER_ENDPOINT
        if RAILWAY_STATIC_URL:
            endpoint = f"{RAILWAY_STATIC_URL.replace('https://', '').replace('http://', '')}:51820"
        
        client_config = f"""[Interface]
PrivateKey = {private_key}
Address = {ip_address}/24
DNS = 8.8.8.8, 1.1.1.1

[Peer]
PublicKey = {server_config['public_key']}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
        
        return client_config
    
    def get_user_peers(self, user_id: int) -> List[Dict]:
        """Get all peers for a user"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, peer_name, public_key, ip_address, created_at, is_active
            FROM wg_peers WHERE user_id = ?
        ''', (user_id,))
        
        peers = []
        for row in cursor.fetchall():
            peers.append({
                'id': row[0],
                'peer_name': row[1],
                'public_key': row[2],
                'ip_address': row[3],
                'created_at': row[4],
                'is_active': bool(row[5])
            })
        
        conn.close()
        return peers
    
    def deactivate_peer(self, peer_id: int, user_id: int) -> bool:
        """Deactivate a peer"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE wg_peers SET is_active = 0 WHERE id = ? AND user_id = ?
        ''', (peer_id, user_id))
        
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        return affected > 0

# Initialize WireGuard manager
wg_manager = RailwayWireGuardManager()

def token_required(f):
    """Decorator to require JWT token"""
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user_id, *args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

# API Routes (same as before)
@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    try:
        password_hash = generate_password_hash(data['password'])
        cursor.execute('''
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
        ''', (data['username'], data['email'], password_hash))
        
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username or email already exists'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    """Login user and return JWT token"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing credentials'}), 400
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, password_hash FROM users WHERE username = ?
    ''', (data['username'],))
    
    user = cursor.fetchone()
    conn.close()
    
    if user and check_password_hash(user[1], data['password']):
        token = jwt.encode({
            'user_id': user[0],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({'token': token}), 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/peers', methods=['GET'])
@token_required
def get_peers(current_user_id):
    """Get all peers for current user"""
    peers = wg_manager.get_user_peers(current_user_id)
    return jsonify({'peers': peers}), 200

@app.route('/api/peers', methods=['POST'])
@token_required
def create_peer(current_user_id):
    """Create a new peer"""
    data = request.get_json()
    
    if not data or not data.get('peer_name'):
        return jsonify({'message': 'Peer name is required'}), 400
    
    try:
        peer = wg_manager.create_peer(current_user_id, data['peer_name'])
        return jsonify({'peer': peer}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/peers/<int:peer_id>/config', methods=['GET'])
@token_required
def get_peer_config(current_user_id, peer_id):
    """Get WireGuard configuration for a peer"""
    # Verify peer belongs to user
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id FROM wg_peers WHERE id = ? AND user_id = ? AND is_active = 1
    ''', (peer_id, current_user_id))
    
    if not cursor.fetchone():
        conn.close()
        return jsonify({'message': 'Peer not found'}), 404
    
    conn.close()
    
    config = wg_manager.generate_client_config(peer_id)
    if config:
        return jsonify({'config': config}), 200
    
    return jsonify({'message': 'Could not generate config'}), 500

@app.route('/api/peers/<int:peer_id>/config/download', methods=['GET'])
@token_required
def download_peer_config(current_user_id, peer_id):
    """Download WireGuard configuration file"""
    # Verify peer belongs to user
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT peer_name FROM wg_peers WHERE id = ? AND user_id = ? AND is_active = 1
    ''', (peer_id, current_user_id))
    
    peer_data = cursor.fetchone()
    if not peer_data:
        conn.close()
        return jsonify({'message': 'Peer not found'}), 404
    
    peer_name = peer_data[0]
    conn.close()
    
    config = wg_manager.generate_client_config(peer_id)
    if config:
        return Response(
            config,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename={peer_name}.conf'
            }
        )
    
    return jsonify({'message': 'Could not generate config'}), 500

@app.route('/api/peers/<int:peer_id>', methods=['DELETE'])
@token_required
def delete_peer(current_user_id, peer_id):
    """Deactivate a peer"""
    if wg_manager.deactivate_peer(peer_id, current_user_id):
        return jsonify({'message': 'Peer deactivated successfully'}), 200
    
    return jsonify({'message': 'Peer not found'}), 404

@app.route('/api/status', methods=['GET'])
def status():
    """Get service status"""
    return jsonify({
        'status': 'running',
        'version': '1.0.0',
        'server_endpoint': SERVER_ENDPOINT,
        'mock_mode': wg_manager.mock_mode,
        'railway_url': RAILWAY_STATIC_URL
    }), 200

@app.route('/', methods=['GET'])
def home():
    """Home page with API documentation"""
    return jsonify({
        'message': 'WireGuard PaaS API',
        'version': '1.0.0',
        'endpoints': {
            'register': 'POST /api/register',
            'login': 'POST /api/login',
            'peers': 'GET /api/peers',
            'create_peer': 'POST /api/peers',
            'get_config': 'GET /api/peers/{id}/config',
            'download_config': 'GET /api/peers/{id}/config/download',
            'delete_peer': 'DELETE /api/peers/{id}',
            'status': 'GET /api/status'
        }
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
