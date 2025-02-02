from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3, hashlib
from datetime import timedelta

app = Flask(_name_)
CORS(app, supports_credentials=True)
app.config.update(JWT_SECRET_KEY="your_secret_key", JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1))
jwt = JWTManager(app)

# Hash function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Database connection
def get_db_connection():
    return sqlite3.connect("notes.db", check_same_thread=False)

# Initialize database
with get_db_connection() as conn:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT);
        CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content TEXT);
    """)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Invalid request"}), 400

    try:
        with get_db_connection() as conn:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                         (data["username"], hash_password(data["password"])))
        return jsonify({"message": "User registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "Invalid request"}), 400

    with get_db_connection() as conn:
        user = conn.execute("SELECT id FROM users WHERE username = ? AND password = ?", 
                            (data["username"], hash_password(data["password"]))).fetchone()
    
    if user:
        return jsonify({"token": create_access_token(identity=user[0])}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/add_note", methods=["POST"])
@jwt_required()
def add_note():
    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("content"):
        return jsonify({"error": "Invalid request"}), 400

    with get_db_connection() as conn:
        conn.execute("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)", 
                     (get_jwt_identity(), data["title"], data["content"]))
    return jsonify({"message": "Note added successfully"}), 201

@app.route("/view_notes", methods=["GET"])
@jwt_required()
def view_notes():
    with get_db_connection() as conn:
        notes = conn.execute("SELECT id, title, content FROM notes WHERE user_id = ?", 
                             (get_jwt_identity(),)).fetchall()
    
    return jsonify([{"id": n[0], "title": n[1], "content": n[2]} for n in notes]), 200

@app.route("/delete_note/<int:note_id>", methods=["DELETE"])
@jwt_required()
def delete_note(note_id):
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", 
                              (note_id, get_jwt_identity()))
        if cursor.rowcount == 0:
            return jsonify({"error": "Note not found"}), 404
        conn.commit()
    return jsonify({"message": "Note deleted successfully"}), 200

if _name_ == "_main_":
    app.run(debug=True)