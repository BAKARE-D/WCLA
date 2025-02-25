from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_session import Session as FlaskSession
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
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

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    print(f'Loading user with ID: {user_id}')  # Debugging statement
    return User.query.get(user_id)

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

@app.before_request
def load_logged_in_user():
    user = get_current_user()  # Retrieve the current user
    print(f'Current user loaded: {user}')  # Debugging statement
    print(f'Session ID: {session.get("user_id")}')  # Debugging statement
    print(f'Current user is authenticated: {user.is_authenticated}')  # Debugging statement

# Models
class User(db.Model, UserMixin):
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

# In your models.py file, update the Signup model to include the extra fields.
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
    """Load JSON data from a file with proper error handling."""
    if not os.path.exists(file_path):
        return default if default is not None else {}
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return data if data is not None else default if default is not None else {}
    except json.JSONDecodeError:
        # If file is empty or malformed, return default
        return default if default is not None else {}
    except Exception as e:
        logging.error(f"Error loading JSON from {file_path}: {str(e)}")
        return default if default is not None else {}

def save_json(file_path, data):
    """Save JSON data to a file with proper error handling."""
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        logging.error(f"Error saving JSON to {file_path}: {str(e)}")
        return False

def load_signups():
    """Load all signups from the database."""
    return Signup.query.all()

def save_signups(signups):
    """Save signups to the database."""
    try:
        for signup in signups:
            db.session.add(signup)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error saving signups: {str(e)}")
        return False

def load_event(event_id):
    """Load an event from the database."""
    return Event.query.get(event_id)

def load_events():
    """Load all events from the database."""
    return Event.query.all()

def save_events(events):
    """Save events to the database."""
    try:
        for event in events:
            db.session.add(event)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error saving events: {str(e)}")
        return False

def load_signups_for_event(event_id):
    """Load signups for a specific event from the database."""
    return Signup.query.filter_by(event_id=event_id).all()

def get_current_user():
    user_id = session.get('user_id')  # Assuming you store user ID in the session
    if user_id:
        return User.query.get(user_id)  # Fetch the user from the database
    return None  # Return None if no user is logged in

#Error handling
@app.errorhandler(400)
def handle_400(e):
    return "Bad Request", 400

@app.errorhandler(401)
def handle_401(e):
    return "Unauthorized", 401

@app.errorhandler(403)
def handle_403(e):
    return "Forbidden", 403

# Custom decorator to check if a user is an admin
from flask import abort

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard'))  # Redirect to a safe page
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/admin_setup')
def admin_setup():
    if User.query.filter_by(username='admin').first():
        flash('Admin account already exists!', 'info')
        return redirect(url_for('login'))

    hashed_password = generate_password_hash('adminpassword')
    admin_user = User(username='admin', password=hashed_password,
                      school_name='Admin School', phone_number='0000000000',
                      email='admin@example.com', is_admin=True, name='Admin')

    db.session.add(admin_user)
    db.session.commit()

    flash('Admin account created successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        school_name = request.form.get('school_name')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        name = request.form.get('name')

        if not all([username, password, confirm_password, school_name, phone_number, email, name]):
            flash('All fields are required', 'error')
            return abort(400)

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email format', 'error')
            return abort(400)

        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return abort(400)

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html'), 200

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists', 'error')
            else:
                flash('Email already exists', 'error')
            return render_template('register.html'), 200

        try:
            hashed_password = generate_password_hash(password)
            new_user = User(
                username=username,
                password=hashed_password,
                school_name=school_name,
                phone_number=phone_number,
                email=email,
                name=name,
                is_active=True
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error during registration', 'error')
            return abort(400)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f'Trying to log in user: {username}')  # Debugging statement
        user = User.query.filter_by(username=username).first()
        if user:
            print(f'User found: {user.username}')  # Debugging statement
            if check_password_hash(user.password, password):  # Assuming you are hashing passwords
                session['user_id'] = user.id  # Set user ID in session
                print(f'Session set for user ID: {user.id}')  # Debugging statement
                print(f'User is authenticated: {user.is_authenticated}')  # Debugging statement
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))  # Redirect to dashboard
            else:
                print('Password is incorrect.')  # Debugging statement
        else:
            print('User not found.')  # Debugging statement
        flash('Invalid username or password.', 'error')
        return redirect(url_for('login'))  # Redirect back to login page
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        session.clear()
        flash('Please log in again.', 'error')
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user)

@app.route('/user/<int:user_id>')
@login_required
def view_user_profile(user_id):
    """View a user's profile."""
    user = User.query.get_or_404(user_id)
    return render_template('user_profile.html', user=user)

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    """Update the current user's profile."""
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    
    if not user:
        session.clear()
        flash('Please log in again.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        school_name = request.form.get('school_name')

        # Validate required fields
        if not all([name, email, phone_number, school_name]):
            flash('All fields are required.', 'error')
            return redirect(url_for('update_profile')), 400

        try:
            # Check if email is already taken by another user
            existing_user = User.query.filter(User.email == email, User.id != user_id).first()
            if existing_user:
                flash('Email is already in use.', 'error')
                return redirect(url_for('update_profile')), 400

            # Update user profile
            user.name = name
            user.email = email
            user.phone_number = phone_number
            user.school_name = school_name
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating profile: {str(e)}")
            flash('Error updating profile. Please try again.', 'error')
            return redirect(url_for('update_profile')), 400

    return render_template('update_profile.html', user=user)

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('You need to be an admin to access this page!', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        event_name = request.form.get('event_name', '').strip()
        event_date = request.form.get('event_date', '').strip()
        event_location = request.form.get('event_location', '').strip()
        event_description = request.form.get('event_description', '').strip()

        # Validate required fields
        if not all([event_name, event_date, event_location, event_description]):
            flash('All fields are required', 'error')
            return abort(400)

        # Validate field lengths
        if len(event_name) > 100:
            flash('Event name is too long', 'error')
            return abort(400)

        if len(event_location) > 200:
            flash('Event location is too long', 'error')
            return abort(400)

        # Validate date format and future date
        try:
            date_obj = datetime.strptime(event_date, '%Y-%m-%d')
            if date_obj.date() < datetime.now().date():
                flash('Event date must be in the future', 'error')
                return abort(400)
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD', 'error')
            return abort(400)

        # Check for duplicate event name
        if Event.query.filter_by(event_name=event_name).first():
            flash('Event with this name already exists', 'error')
            return abort(400)

        try:
            new_event = Event(
                event_name=event_name,
                event_date=event_date,
                event_location=event_location,
                event_description=event_description
            )
            db.session.add(new_event)
            db.session.commit()
            flash('Event created successfully!', 'success')
            return redirect(url_for('events'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating event', 'error')
            return abort(400)

    return render_template('create_event.html')

@app.route('/events')
def events():
    if 'user_id' not in session:
        flash('Please log in to view events.', 'error')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        session.clear()
        flash('Please log in again.', 'error')
        return redirect(url_for('login'))

    events = Event.query.all()
    return render_template('events.html', events=events, user=user)

@app.route('/event/<int:event_id>')
def view_event_details(event_id):
    if 'user_id' not in session:
        flash('Please log in to view event details.', 'error')
        return redirect(url_for('login'))

    event = Event.query.get_or_404(event_id)
    signups = Signup.query.filter_by(event_id=event_id).all()
    return render_template('event_details.html', event=event, signups=signups)

@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    """Delete an event (admin only)."""
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    if not user or not user.is_admin:
        flash('Admin privileges required.', 'error')
        return abort(403)

    event = Event.query.get_or_404(event_id)
    try:
        # Delete all signups for this event
        Signup.query.filter_by(event_id=event_id).delete()
        # Delete all attendance records for this event
        Attendance.query.filter_by(event_id=event_id).delete()
        # Delete the event
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully.', 'success')
        return redirect(url_for('events'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting event: {str(e)}")
        flash('Error deleting event. Please try again.', 'error')
        return redirect(url_for('events')), 400

@app.route('/view_signups/<int:event_id>')
@login_required
def view_signups(event_id):
    """View signups for an event."""
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    if not user:
        flash('Please log in again.', 'error')
        return redirect(url_for('login'))

    event = Event.query.get_or_404(event_id)
    signups = Signup.query.filter_by(event_id=event_id).all()
    return render_template('view_signups.html', event=event, signups=signups, user=user)

@app.route('/sign_up/<int:event_id>', methods=['GET', 'POST'])
@login_required
def sign_up(event_id):
    """Sign up for an event."""
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    if not user:
        flash('Please log in again.', 'error')
        return redirect(url_for('login'))

    event = Event.query.get_or_404(event_id)
    existing_signup = Signup.query.filter_by(user_id=user_id, event_id=event_id).first()
    if existing_signup:
        flash('You are already signed up for this event.', 'error')
        return redirect(url_for('events')), 400

    if request.method == 'POST':
        try:
            signup = Signup(
                user_id=user_id,
                event_id=event_id,
                first_name=request.form.get('first_name'),
                last_name=request.form.get('last_name'),
                school_name=user.school_name
            )
            db.session.add(signup)
            db.session.commit()
            flash('Successfully signed up for the event!', 'success')
            return redirect(url_for('events'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error signing up for event: {str(e)}")
            flash('Error signing up for event. Please try again.', 'error')
            return redirect(url_for('events')), 400

    return render_template('sign_up.html', event=event, user=user)

@app.route('/remove_signup/<int:event_id>', methods=['POST'])
@login_required
def remove_signup(event_id):
    """Remove signup from an event."""
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)
    if not user:
        flash('Please log in again.', 'error')
        return redirect(url_for('login'))

    signup = Signup.query.filter_by(user_id=user_id, event_id=event_id).first()
    if not signup:
        flash('You are not signed up for this event.', 'error')
        return redirect(url_for('events')), 404

    try:
        db.session.delete(signup)
        db.session.commit()
        flash('Successfully removed signup.', 'success')
        return redirect(url_for('events'))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error removing signup: {str(e)}")
        flash('Error removing signup. Please try again.', 'error')
        return redirect(url_for('events')), 400

@app.route('/review_attendance/<event_id>')
@login_required
def review_attendance(event_id):
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        session.clear()
        flash('Please log in again.', 'error')
        return redirect(url_for('login'))

    event = load_event(event_id)
    if not event:
        return "Event not found", 404

    attendances = Attendance.query.filter_by(event_id=int(event_id)).all()

    formatted_attendance = [
        f"{attendance.first_name} {attendance.last_name} ({attendance.school_name}) was {'present' if attendance.present else 'not present'}"
        for attendance in attendances
    ]

    return render_template('review_attendance.html', event=event, attendance=formatted_attendance, user=user)

@app.route('/events/<int:event_id>/mark-attendance', methods=['GET', 'POST'])
@login_required
def mark_attendance(event_id):
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('You need to be an admin to access this page!', 'error')
        return redirect(url_for('login'))

    event = load_event(event_id)
    if event is None:
        flash('Event not found.', 'error')
        return redirect(url_for('events'))

    signups = load_signups_for_event(event_id)

    if request.method == 'POST':
        for signup in signups:
            attendance = Attendance.query.filter_by(
                user_id=signup.user_id,
                event_id=event_id,
                first_name=signup.first_name,
                last_name=signup.last_name
            ).first()

            present = f"{signup.user_id}_{signup.first_name}_{signup.last_name}" in request.form.getlist('attendance')

            if not attendance:
                attendance = Attendance(
                    user_id=signup.user_id,
                    event_id=event_id,
                    school_name=signup.school_name,
                    first_name=signup.first_name,
                    last_name=signup.last_name,
                    present=present
                )
                db.session.add(attendance)
            else:
                attendance.present = present

        try:
            db.session.commit()
            flash('Attendance successfully marked.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error marking attendance. Please try again.', 'error')

        return redirect(url_for('review_events'))

    current_attendance = {
        f"{a.user_id}_{a.first_name}_{a.last_name}": a.present 
        for a in Attendance.query.filter_by(event_id=event_id).all()
    }

    return render_template('mark_attendance.html', event=event, signups=signups, event_id=event_id, current_attendance=current_attendance, user=user)

@app.route('/event_statistics', methods=['GET', 'POST'])
@login_required
def event_statistics():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('You need to be an admin to access this page!', 'error')
        return redirect(url_for('login'))

    events = load_events()
    
    # Get filter parameters
    start_date = request.form.get('start_date')
    end_date = request.form.get('end_date')
    specific_date = request.form.get('specific_date')

    event_stats = []
    total_attendees = 0
    schools_signed_up = set()
    school_emails = set()

    for event in events:
        event_date = datetime.strptime(event.event_date, '%Y-%m-%d').date()
        
        # Apply date filters
        if specific_date:
            if event_date != datetime.strptime(specific_date, '%Y-%m-%d').date():
                continue
        elif start_date and end_date:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
            if not (start <= event_date <= end):
                continue

        # Calculate attendance statistics
        attendances = Attendance.query.filter_by(event_id=event.id).all()
        total_attendees += len(attendances)
        present_attendees = sum(1 for a in attendances if a.present)
        
        presence_percentage = (present_attendees / len(attendances) * 100) if attendances else 0

        event_stats.append({
            'id': event.id,
            'name': event.event_name,
            'date': event.event_date,
            'total_attendees': len(attendances),
            'present_attendees': present_attendees,
            'presence_percentage': round(presence_percentage, 2)
        })

        # Collect unique schools and their emails
        for attendance in attendances:
            schools_signed_up.add(attendance.school_name)
            user = User.query.filter_by(id=attendance.user_id).first()
            if user:
                school_emails.add(user.email)

    # Sort events by date
    event_stats.sort(key=lambda x: x['date'], reverse=True)

    # Calculate summary statistics
    total_events = len(event_stats)
    total_schools_signed_up = len(schools_signed_up)
    total_schools_in_db = db.session.query(func.count(func.distinct(User.school_name))).scalar()

    return render_template('event_statistics.html', 
                           event_stats=event_stats,
                           start_date=start_date, 
                           end_date=end_date, 
                           specific_date=specific_date,
                           total_events=total_events,
                           total_schools_signed_up=total_schools_signed_up,
                           total_schools_in_db=total_schools_in_db,
                           total_attendees=total_attendees,
                           school_emails=list(school_emails), user=user)

@app.route('/export_statistics')
@login_required
def export_statistics():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('You need to be an admin to access this page!', 'error')
        return redirect(url_for('login'))

    events = load_events()
    
    # Check if there are no events
    if not events:
        flash('No events available for export.', 'error')
        return redirect(url_for('events'))  # Redirect to the events page

    # Create a StringIO object to write CSV data
    si = StringIO()
    csv_writer = csv.writer(si)

    # Write headers
    csv_writer.writerow(["Event Name", "Date", "Total Attendees", "Present Attendees", "Presence Percentage"])

    # Write data
    for event in events:
        attendances = Attendance.query.filter_by(event_id=event.id).all()
        total_attendees = len(attendances)
        present_attendees = sum(1 for a in attendances if a.present)
        presence_percentage = (present_attendees / total_attendees * 100) if total_attendees else 0

        csv_writer.writerow([
            event.event_name,
            event.event_date,
            total_attendees,
            present_attendees,
            f"{presence_percentage:.2f}%"
        ])

    # Create the HTTP response
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=event_statistics.csv"
    output.headers["Content-type"] = "text/csv"

    return output

@app.route('/schools')
@login_required
def schools():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('You need to be an admin to access this page!', 'error')
        return redirect(url_for('login'))

    # Get sorting parameter from query string
    sort_by = request.args.get('sort', 'school_name')  # Default sort by school name

    # Query to get unique school names, emails, and phone numbers
    school_data = db.session.query(
        User.school_name,
        User.email,
        User.phone_number
    ).distinct().all()

    # Calculate participation percentage and total events signed up for each school
    participation_data = {}
    for school_name, email, phone_number in school_data:
        signups = load_signups()  # Load signups from your JSON or database
        total_events = len(signups)  # Total events signed up for

        # Set to track unique attended events
        attended_events = set()
        for event_id, event_signups in signups.items():
            for signup in event_signups:
                if signup['school_name'] == school_name and signup['user_id'] in [u.id for u in User.query.filter_by(school_name=school_name).all()]:
                    attended_events.add(event_id)  # Add unique event ID to the set

        # Calculate participation percentage
        attended_count = len(attended_events)  # Count of unique events attended
        participation_percentage = (attended_count / total_events * 100) if total_events > 0 else 0

        participation_data[school_name] = {
            'email': email,
            'phone_number': phone_number,
            'participation_percentage': round(participation_percentage, 2),
            'total_events': total_events  # Add total events signed up for
        }

    # Sort the data based on the sort_by parameter
    if sort_by == 'school_name':
        sorted_data = sorted(participation_data.items(), key=lambda x: x[0])  # Sort by school name
    elif sort_by == 'total_events':
        sorted_data = sorted(participation_data.items(), key=lambda x: x[1]['total_events'], reverse=True)  # Sort by total events signed up
    elif sort_by == 'participation_percentage':
        sorted_data = sorted(participation_data.items(), key=lambda x: x[1]['participation_percentage'], reverse=True)  # Sort by participation percentage
    else:
        sorted_data = participation_data.items()  # Default case

    return render_template('schools.html', participation_data=sorted_data, user=user)

@app.route('/export_selected_schools', methods=['POST'])
@login_required
def export_selected_schools():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash('You need to be an admin to access this page!', 'error')
        return redirect(url_for('login'))
    selected_schools = request.form.getlist('selected_schools')

    # If no schools are selected, get all schools
    if not selected_schools:
        selected_schools = [school_name for school_name, _, _ in db.session.query(
            User.school_name,
            User.email,
            User.phone_number
        ).distinct().all()]

    # Prepare data for export
    participation_data = {}
    for school_name in selected_schools:
        user = User.query.filter_by(school_name=school_name).first()
        if user:
            # Calculate participation data
            signups = load_signups()  # Load signups from your JSON or database
            total_events = len(signups)  # Total events signed up for
            attended_events = set()
            for event_id, event_signups in signups.items():
                for signup in event_signups:
                    if signup['school_name'] == school_name and signup['user_id'] in [u.id for u in User.query.filter_by(school_name=school_name).all()]:
                        attended_events.add(event_id)  # Add unique event ID to the set

            attended_count = len(attended_events)  # Count of unique events attended
            participation_percentage = (attended_count / total_events * 100) if total_events > 0 else 0
            participation_percentage = min(participation_percentage, 100)

            participation_data[school_name] = {
                'email': user.email,
                'phone_number': user.phone_number,
                'participation_percentage': round(participation_percentage, 2),
                'total_events': total_events  # Add total events signed up for
            }

    # Create a CSV response
    output = StringIO() # type: ignore
    writer = csv.DictWriter(output, fieldnames=['School Name', 'Email', 'Phone Number', 'Participation Percentage', 'Total Events Signed Up'])
    writer.writeheader()
    for school_name, data in participation_data.items():
        writer.writerow({
            'School Name': school_name,
            'Email': data['email'],
            'Phone Number': data['phone_number'],
            'Participation Percentage': data['participation_percentage'],
            'Total Events Signed Up': data['total_events']
        })

    # Create the response
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=selected_schools.csv"
    response.headers["Content-type"] = "text/csv"

    return response

@app.route('/event_attendance_statistics')
@login_required
def event_attendance_statistics():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if not user:
        session.clear()
        flash('Please log in again.', 'error')
        return redirect(url_for('login'))

    # Get all events and their attendance statistics
    events = db.session.query(Event).all()
    attendance_stats = []

    for event in events:
        total_attendees = db.session.query(func.count(Attendance.id)).filter_by(event_id=event.id).scalar() or 0  # Default to 0 if None
        present_attendees = db.session.query(func.count(Attendance.id)).filter_by(event_id=event.id, present=True).scalar() or 0  # Default to 0 if None
        absent_attendees = total_attendees - present_attendees

        # Calculate presence percentage safely
        presence_percentage = (present_attendees / total_attendees * 100) if total_attendees > 0 else 0

        attendance_stats.append({
            'event_name': event.event_name,
            'total_attendees': total_attendees,
            'present_attendees': present_attendees,
            'absent_attendees': absent_attendees,
            'presence_percentage': round(presence_percentage, 2)  # Round the percentage
        })

    # Calculate average, max, and min attendance
    attendance_counts = (
        db.session.query(func.count(Attendance.id).label('attendance_count'))
        .group_by(Attendance.event_id)
    ).subquery()

    average_attendance = db.session.query(func.avg(attendance_counts.c.attendance_count)).scalar() or 0  # Default to 0 if None
    max_attendance = db.session.query(func.max(attendance_counts.c.attendance_count)).scalar() or 0  # Default to 0 if None
    min_attendance = db.session.query(func.min(attendance_counts.c.attendance_count)).scalar() or 0  # Default to 0 if None

    # Debugging output
    print(f"Average Attendance: {average_attendance}")
    print(f"Max Attendance: {max_attendance}")
    print(f"Min Attendance: {min_attendance}")

    return render_template('event_attendance_statistics.html', 
                           attendance_stats=attendance_stats,
                           average_attendance=average_attendance,
                           max_attendance=max_attendance,
                           min_attendance=min_attendance, user=user)

@app.route('/home')
def home():
    user = get_current_user()  # Retrieve the current user
    print(f'Current user: {user}')  # Debugging statement
    upcoming_events = Event.query.filter(Event.event_date >= datetime.now()).order_by(Event.event_date).limit(3).all()  # Fetch the next 3 upcoming events
    return render_template('home.html', user=user, events=upcoming_events)

@app.route('/')
def index():
    return redirect(url_for('home'))

@app.route('/admin_only_page')
@admin_required
def admin_only_page():
    # Admin-only functionality here
    return render_template('admin_page.html')

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()  # This creates tables in the default database (users.db)
        db.create_all(bind_key='attendance')  # This creates tables in the attendance database
    app.run(debug=True)