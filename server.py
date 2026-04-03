#!/usr/bin/env python3
"""
Simple Flask backend for Reminders app with user authentication
and cloud data sync using SQLite.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

# Serve frontend from Flask root so phone can open same host directly
@app.route('/')
def serve_frontend():
    return app.send_static_file('index.html')

# Configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

DB_FILE = os.path.join(os.path.dirname(__file__), 'reminders.db')

# ── DATABASE SETUP ──
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        dob TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Add missing columns on older schema
    columns = [row[1] for row in c.execute("PRAGMA table_info(users)")]
    if 'name' not in columns:
        c.execute('ALTER TABLE users ADD COLUMN name TEXT')
    if 'dob' not in columns:
        c.execute('ALTER TABLE users ADD COLUMN dob TEXT')
    
    # Lists table
    c.execute('''CREATE TABLE IF NOT EXISTS lists (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        color TEXT NOT NULL,
        icon TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    # Reminders table
    c.execute('''CREATE TABLE IF NOT EXISTS reminders (
        id TEXT PRIMARY KEY,
        list_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        completed BOOLEAN DEFAULT 0,
        flagged BOOLEAN DEFAULT 0,
        date TEXT,
        priority TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(list_id) REFERENCES lists(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()

init_db()

# ── AUTH ROUTES ──
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    try:
        name = data.get('name', '').strip()
        dob = data.get('dob', '').strip()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        hashed = generate_password_hash(password)
        c.execute('INSERT INTO users (email, password, name, dob) VALUES (?, ?, ?, ?)', (email, hashed, name, dob))
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        
        access_token = create_access_token(identity=str(user_id))
        return jsonify({'access_token': access_token, 'user_id': user_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        
        if not user or not check_password_hash(user[1], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_id = user[0]
        access_token = create_access_token(identity=str(user_id))
        return jsonify({'access_token': access_token, 'user_id': user_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = int(get_jwt_identity())
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT email, name, dob FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'email': user['email'], 'name': user['name'] or '', 'dob': user['dob'] or ''}), 200

@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    dob = data.get('dob', '').strip()
    password = data.get('password', '').strip()

    if password and len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        if password:
            hashed = generate_password_hash(password)
            c.execute('UPDATE users SET name = ?, dob = ?, password = ? WHERE id = ?', (name, dob, hashed, user_id))
        else:
            c.execute('UPDATE users SET name = ?, dob = ? WHERE id = ?', (name, dob, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Profile updated'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    # Frontend should delete token
    return jsonify({'message': 'Logged out'}), 200

# ── LISTS ROUTES ──
@app.route('/api/lists', methods=['GET'])
@jwt_required()
def get_lists():
    user_id = int(get_jwt_identity())
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM lists WHERE user_id = ?', (user_id,))
    lists = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(lists), 200

@app.route('/api/lists', methods=['POST'])
@jwt_required()
def create_list():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''INSERT INTO lists (id, user_id, name, color, icon) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (data['id'], user_id, data['name'], data['color'], data['icon']))
        conn.commit()
        conn.close()
        return jsonify({'message': 'List created'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/lists/<list_id>', methods=['DELETE'])
@jwt_required()
def delete_list(list_id):
    user_id = int(get_jwt_identity())
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('DELETE FROM lists WHERE id = ? AND user_id = ?', (list_id, user_id))
        c.execute('DELETE FROM reminders WHERE list_id = ? AND user_id = ?', (list_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'List deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── REMINDERS ROUTES ──
@app.route('/api/reminders', methods=['GET'])
@jwt_required()
def get_reminders():
    user_id = int(get_jwt_identity())
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM reminders WHERE user_id = ?', (user_id,))
    reminders = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(reminders), 200

@app.route('/api/reminders', methods=['POST'])
@jwt_required()
def create_reminder():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''INSERT INTO reminders 
                     (id, list_id, user_id, text, completed, flagged, date, priority)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (data['id'], data['list_id'], user_id, data['text'], 
                   data.get('completed', False), data.get('flagged', False),
                   data.get('date'), data.get('priority')))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Reminder created'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reminders/<reminder_id>', methods=['PUT'])
@jwt_required()
def update_reminder(reminder_id):
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''UPDATE reminders 
                     SET text = ?, completed = ?, flagged = ?, date = ?, priority = ?
                     WHERE id = ? AND user_id = ?''',
                  (data.get('text'), data.get('completed'), data.get('flagged'),
                   data.get('date'), data.get('priority'), reminder_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Reminder updated'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reminders/<reminder_id>', methods=['DELETE'])
@jwt_required()
def delete_reminder(reminder_id):
    user_id = int(get_jwt_identity())
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('DELETE FROM reminders WHERE id = ? AND user_id = ?', (reminder_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Reminder deleted'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reminders/sync/all', methods=['POST'])
@jwt_required()
def sync_all():
    """Sync all reminders at once"""
    user_id = int(get_jwt_identity())
    data = request.get_json()
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # Clear old reminders and lists for this user
        c.execute('DELETE FROM reminders WHERE user_id = ?', (user_id,))
        c.execute('DELETE FROM lists WHERE user_id = ?', (user_id,))
        
        # Insert new data
        for lst in data.get('lists', []):
            c.execute('''INSERT INTO lists (id, user_id, name, color, icon)
                         VALUES (?, ?, ?, ?, ?)''',
                      (lst['id'], user_id, lst['name'], lst['color'], lst['icon']))
            
            for rem in lst.get('reminders', []):
                c.execute('''INSERT INTO reminders 
                             (id, list_id, user_id, text, completed, flagged, date, priority)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                          (rem['id'], lst['id'], user_id, rem['text'],
                           rem.get('completed', False), rem.get('flagged', False),
                           rem.get('date'), rem.get('priority')))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'Synced'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── HEALTH CHECK ──
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
