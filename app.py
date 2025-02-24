from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_session import Session as FlaskSession
from authlib.integrations.flask_client import OAuth
from functools import wraps
from datetime import datetime, timedelta
import os
import csv
from io import StringIO
import json
import logging
from collections import defaultdict 
import re


# Configuration
class Config:
    SECRET_KEY = os.environ.get('VERY_UNHACKABLE_WELL_HASHED_SECRET_KEY', 'fallback_secret_key')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(os.path.abspath(os.path.dirname(__file__)), "instance", "users.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_TYPE = 'filesystem'

app = Flask(__name__, instance_relative_config=True)
app.config.from_object(Config)

# Add SQLALCHEMY_BINDS after app is created
app.config['SQLALCHEMY_BINDS'] = {
    'attendance': f'sqlite:///{os.path.join(app.instance_path, "attendance.db")}'
}

base_dir = os.path.abspath(os.path.dirname(__file__))

# Ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Initialize Flask extensions
db = SQLAlchemy(app)
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
Session = FlaskSession()
Session.init_app(app)

# Global error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# User session management
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    school_name = db.Column(db.String(150), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(150), nullable=True)
    is_active = db.Column(db.Boolean, default=True)

class Attendance(db.Model):
    __bind_key__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    event_id = db.Column(db.Integer, nullable=False)
    school_name = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    present = db.Column(db.Boolean, default=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(150), nullable=False)
    event_date = db.Column(db.String(50), nullable=False)
    event_location = db.Column(db.String(150), nullable=False)
    event_description = db.Column(db.Text, nullable=False)

class Signup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    school_name = db.Column(db.String(150), nullable=False)
    user = db.relationship('User', backref=db.backref('signups', lazy=True))
    event = db.relationship('Event', backref=db.backref('signups', lazy=True))

# File paths
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)  # Ensure data directory exists
EVENTS_FILE = os.path.join(DATA_DIR, 'events.json')
SIGNUPS_FILE = os.path.join(DATA_DIR, 'signups.json')
ATTENDANCE_FILE = os.path.join(DATA_DIR, 'attendance.json')

# Helper functions
def load_json(file_path, default=None):
    if not os.path.exists(file_path):
        return default
    with open(file_path, 'r') as f:
        content = f.read().strip()
        if not content:
            return default  # Return default for empty files
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return default  # Return default for malformed JSON

def save_json(file_path, data):
    with open(file_path, 'w') as f:
        json.dump(data, f)

# Add your other functions and routes here

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()  # This creates tables in the default database (users.db)
        db.create_all(bind_key='attendance')  # This creates tables in the attendance database
    app.run(debug=True)
