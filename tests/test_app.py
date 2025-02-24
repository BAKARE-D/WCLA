import unittest
from app import app, db, User, Attendance, Event, Signup
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import os
import json

class AppTestCase(unittest.TestCase):
    def setUp(self):
        # Set up the test client and a test database
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # In-memory database for testing
        self.app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        self.app.config['SESSION_TYPE'] = 'filesystem'  # Enable session support for testing
        self.client = self.app.test_client()

        # Create test data directory
        os.makedirs('data', exist_ok=True)

        with self.app.app_context():
            db.create_all()  # Create the database tables

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()  # Drop the database tables

    def create_test_user(self, is_admin=False):
        """Helper function to create a test user"""
        user = User(
            username='testuser',
            password=generate_password_hash('testpassword'),
            email='testuser@example.com',
            phone_number='1234567890',
            school_name='Test School',
            name='Test User',
            is_admin=is_admin
        )
        with self.app.app_context():
            db.session.add(user)
            db.session.commit()  # Commit the user to the database
        return user

    def create_test_event(self, name='Test Event', date=None):
        """Helper function to create a test event"""
        if date is None:
            date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
        event = Event(
            event_name=name,
            event_date=date,
            event_location='Test Location',
            event_description='Test Description'
        )
        with self.app.app_context():
            db.session.add(event)
            db.session.commit()
        return event

    def login_test_user(self):
        """Helper function to log in a test user"""
        return self.client.post('/login', data={
            'username': 'testuser',
            'password': 'testpassword'
        }, follow_redirects=True)

    # Test Cases
    def test_register_user(self):
        response = self.client.post('/register', data={
            'username': 'testuser',
            'password': 'testpassword',
            'email': 'testuser@example.com',
            'phone_number': '1234567890',
            'school_name': 'Test School'
        })
        self.assertEqual(response.status_code, 302)  # Check for redirect after successful registration
        with self.app.app_context():
            user = User.query.filter_by(username='testuser').first()
            self.assertIsNotNone(user)  # Ensure the user was created

    def test_login_user(self):
        self.create_test_user()
        response = self.login_test_user()
        self.assertEqual(response.status_code, 200)  # Should successfully reach dashboard

    def test_login_empty_credentials(self):
        response = self.client.post('/login', data={})
        self.assertEqual(response.status_code, 400)  # Should return bad request

    def test_login_user_invalid(self):
        response = self.client.post('/login', data={
            'username': 'nonexistent',
            'password': 'wrong'
        })
        self.assertEqual(response.status_code, 401)  # Should return unauthorized

    def test_logout(self):
        self.create_test_user()
        self.login_test_user()
        response = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)  # Should successfully reach login page

    def test_create_event(self):
        user = self.create_test_user(is_admin=True)
        self.login_test_user()
        future_date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
        response = self.client.post('/create_event', data={
            'event_name': 'Test Event',
            'event_date': future_date,
            'event_location': 'Test Location',
            'event_description': 'Test Description'
        })
        self.assertEqual(response.status_code, 302)  # Should redirect after successful creation
        with self.app.app_context():
            event = Event.query.filter_by(event_name='Test Event').first()
            self.assertIsNotNone(event)  # Ensure the event was created

    def test_view_events(self):
        self.create_test_user()
        self.create_test_event()
        self.login_test_user()
        response = self.client.get('/events')
        self.assertEqual(response.status_code, 200)  # Should successfully show events page

    def test_view_event_details(self):
        self.create_test_user()
        event = self.create_test_event()
        self.login_test_user()
        response = self.client.get(f'/event/{event.id}')
        self.assertEqual(response.status_code, 200)  # Should successfully show event details

    def test_load_json(self):
        with open('data/test.json', 'w') as f:
            json.dump({"key": "value"}, f)

        data = load_json('data/test.json')
        self.assertEqual(data, {"key": "value"})

    def test_load_json_file_not_found(self):
        data = load_json('data/non_existent.json', default={})
        self.assertEqual(data, {})

    def test_save_json(self):
        save_json('data/test_save.json', {"key": "value"})
        data = load_json('data/test_save.json')
        self.assertEqual(data, {"key": "value"})

    def test_load_signups(self):
        save_json('data/signups.json', {"1": [{"user_id": 1, "first_name": "Test", "last_name": "User"}]})
        signups = load_signups()
        self.assertEqual(signups, {"1": [{"user_id": 1, "first_name": "Test", "last_name": "User"}]})

    def test_save_signups(self):
        save_signups({"1": [{"user_id": 1, "first_name": "Test", "last_name": "User"}]})
        signups = load_signups()
        self.assertEqual(signups, {"1": [{"user_id": 1, "first_name": "Test", "last_name": "User"}]})

    def test_load_events(self):
        save_events({"1": {"event_name": "Test Event"}})
        events = load_events()
        self.assertEqual(events, {"1": {"event_name": "Test Event"}})

    def test_save_events(self):
        save_events({"1": {"event_name": "Test Event"}})
        events = load_events()
        self.assertEqual(events, {"1": {"event_name": "Test Event"}})

    def test_load_signups_for_event(self):
        save_signups({"1": [{"user_id": 1, "first_name": "Test", "last_name": "User"}]})
        signups = load_signups_for_event(1)
        self.assertEqual(signups, [{"user_id": 1, "first_name": "Test", "last_name": "User"}])

    def test_load_event(self):
        save_events({"1": {"event_name": "Test Event"}})
        event = load_event(1)
        self.assertEqual(event, {"event_name": "Test Event"})

    def test_invalid_route(self):
        response = self.client.get('/invalid_route')
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_create_event_without_login(self):
        response = self.client.post('/create_event', data={
            'event_name': 'Unauthorized Event',
            'event_date': '2023-12-01',
            'event_location': 'Test Location',
            'event_description': 'Test Description'
        })
        self.assertEqual(response.status_code, 302)  # Check for redirect (not logged in)

    def test_sign_up_for_event_without_login(self):
        response = self.client.post('/sign_up/1', data={
            'first_name': 'Test',
            'last_name': 'User',
            'school_name': 'Test School'
        })
        self.assertEqual(response.status_code, 302)  # Check for redirect (not logged in)

    def test_remove_signup_without_login(self):
        response = self.client.post('/remove_signup/1')
        self.assertEqual(response.status_code, 302)  # Check for redirect (not logged in)

    def test_view_signups_for_event_without_login(self):
        response = self.client.get('/view_signups/1')
        self.assertEqual(response.status_code, 302)  # Check for redirect (not logged in)

    def test_load_json_empty_file(self):
        with open('data/empty.json', 'w') as f:
            f.write('')
        data = load_json('data/empty.json', default={})
        self.assertEqual(data, {})

    def test_save_json_overwrite(self):
        save_json('data/test_save.json', {"key": "value"})
        save_json('data/test_save.json', {"key": "new_value"})
        data = load_json('data/test_save.json')
        self.assertEqual(data, {"key": "new_value"})

    def test_load_signups_empty(self):
        signups = load_signups()
        self.assertEqual(signups, {})

    def test_save_signups_empty(self):
        save_signups({})
        signups = load_signups()
        self.assertEqual(signups, {})

    def test_load_events_empty(self):
        events = load_events()
        self.assertEqual(events, {})

    def test_save_events_empty(self):
        save_events({})
        events = load_events()
        self.assertEqual(events, {})

    def test_load_signups_for_event_empty(self):
        signups = load_signups_for_event(999)  # Non-existent event
        self.assertEqual(signups, [])

    def test_invalid_event_id(self):
        response = self.client.get('/view_signups/999')  # Non-existent event
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_remove_signup_invalid_event(self):
        response = self.client.post('/remove_signup/999')  # Non-existent event
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_sign_up_for_event_invalid_event(self):
        response = self.client.post('/sign_up/999', data={
            'first_name': 'Test',
            'last_name': 'User',
            'school_name': 'Test School'
        })
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_create_event_invalid_date_format(self):
        with self.app.app_context():
            admin_user = User(username='admin', password=generate_password_hash('adminpassword'), school_name='Admin School',
                              phone_number='0000000000', email='admin@example.com', is_admin=True)
            db.session.add(admin_user)
            db.session.commit()

        with self.client as c:
            c.post('/login', data={
                'username': 'admin',
                'password': 'adminpassword'
            })

            response = c.post('/create_event', data={
                'event_name': 'Test Event',
                'event_date': 'invalid-date',
                'event_location': 'Test Location',
                'event_description': 'Test Description'
            })
            self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_create_event_past_date(self):
        with self.app.app_context():
            admin_user = User(username='admin', password=generate_password_hash('adminpassword'), school_name='Admin School',
                              phone_number='0000000000', email='admin@example.com', is_admin=True)
            db.session.add(admin_user)
            db.session.commit()

        with self.client as c:
            c.post('/login', data={
                'username': 'admin',
                'password': 'adminpassword'
            })

            response = c.post('/create_event', data={
                'event_name': 'Past Event',
                'event_date': '2020-01-01',  # Past date
                'event_location': 'Test Location',
                'event_description': 'Test Description'
            })
            self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_view_events_not_logged_in(self):
        response = self.client.get('/events')
        self.assertEqual(response.status_code, 302)  # Check for redirect (not logged in)

    def test_view_signups_for_event_not_logged_in(self):
        response = self.client.get('/view_signups/1')
        self.assertEqual(response.status_code, 302)  # Check for redirect (not logged in)

    def test_remove_signup_not_logged_in(self):
        response = self.client.post('/remove_signup/1')
        self.assertEqual(response.status_code, 302)  # Check for redirect (not logged in)

    def test_sign_up_for_event_not_logged_in(self):
        response = self.client.post('/sign_up/1', data={
            'first_name': 'Test',
            'last_name': 'User',
            'school_name': 'Test School'
        })
        self.assertEqual(response.status_code, 302)  # Check for redirect (not logged in)

    def test_load_json_malformed_file(self):
        with open('data/malformed.json', 'w') as f:
            f.write('{"key": "value"')  # Malformed JSON
        data = load_json('data/malformed.json', default={})
        self.assertEqual(data, {})

    def test_save_json_special_characters(self):
        save_json('data/test_special.json', {"key": "value with special char !@#$%^&*()"})
        data = load_json('data/test_special.json')
        self.assertEqual(data, {"key": "value with special char !@#$%^&*()"})

    def test_register_user_missing_fields(self):
        response = self.client.post('/register', data={})
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_login_user_missing_fields(self):
        response = self.client.post('/login', data={})
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_create_event_without_description(self):
        response = self.client.post('/create_event', data={
            'event_name': 'Test Event',
            'event_date': '2023-12-01',
            'event_location': 'Test Location'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_view_events_logged_in(self):
        with self.client as c:
            c.post('/login', data={
                'username': 'testuser',
                'password': 'testpassword'
            })
            response = c.get('/events')
            self.assertEqual(response.status_code, 200)  # Check for successful view

    def test_sign_up_for_event_missing_fields(self):
        response = self.client.post('/sign_up/1', data={
            'last_name': 'User'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request due to missing first_name

    def test_remove_signup_invalid_event_id(self):
        response = self.client.post('/remove_signup/999')  # Non-existent event
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_view_signups_invalid_event_id(self):
        response = self.client.get('/view_signups/999')  # Non-existent event
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_create_event_future_date(self):
        response = self.client.post('/create_event', data={
            'name': 'Future Event',
            'date': '2030-12-01',  # Future date
            'description': 'An event in the future.'
        })
        self.assertEqual(response.status_code, 302)  # Check for redirect after successful event creation

    def test_load_non_json_file(self):
        with open('data/test.txt', 'w') as f:
            f.write('This is a text file.')
        data = load_json('data/test.txt', default={})
        self.assertEqual(data, {})

    def test_save_json_read_only_location(self):
        # This is a conceptual test; actual implementation may vary based on environment
        try:
            save_json('/root/test.json', {"key": "value"})
            self.fail("Expected an exception due to read-only location")
        except Exception:
            pass

    def test_create_event_long_name(self):
        long_name = 'A' * 256  # Assuming 255 is the max length
        response = self.client.post('/create_event', data={
            'event_name': long_name,
            'event_date': '2023-12-01',
            'event_location': 'Test Location',
            'event_description': 'Test Description'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_sign_up_for_event_invalid_user_id(self):
        user = self.create_test_user()
        event = self.create_test_event()
        response = self.client.post('/sign_up/1', data={
            'first_name': 'Test',
            'last_name': 'User',
            'school_name': user.school_name,
            'user_id': 999  # Invalid user ID
        })
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_login_unregistered_user(self):
        response = self.client.post('/login', data={
            'username': 'unregistered_user',
            'password': 'testpassword'
        })
        self.assertEqual(response.status_code, 401)  # Check for unauthorized

    def test_create_event_long_location(self):
        long_location = 'A' * 256  # Assuming 255 is the max length
        response = self.client.post('/create_event', data={
            'event_name': 'Test Event',
            'event_date': '2023-12-01',
            'event_location': long_location,
            'event_description': 'Test Description'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_view_events_no_events(self):
        response = self.client.get('/events')
        self.assertEqual(response.status_code, 200)  # Check for successful view
        self.assertIn('No events found', response.data.decode())  # Check for no events message

    def test_sign_up_for_full_event(self):
        # Assuming we have a way to set an event to full
        response = self.client.post('/sign_up/1', data={
            'first_name': 'Test',
            'last_name': 'User',
            'school_name': 'Test School'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_remove_nonexistent_signup(self):
        response = self.client.post('/remove_signup/999')  # Non-existent signup
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_view_signups_full_event(self):
        response = self.client.get('/view_signups/1')  # Assuming event 1 is full
        self.assertEqual(response.status_code, 200)  # Check for successful view
        self.assertIn('Event is full', response.data.decode())  # Check for full event message

    def test_create_event_with_future_date(self):
        # Test creating an event with a future date
        with self.app.app_context():
            with self.client as c:
                c.post('/login', data={'username': 'admin', 'password': 'adminpassword'})
                response = c.post('/create_event', data={
                    'event_name': 'Future Event',
                    'event_date': '2024-12-01',
                    'event_location': 'Test Location',
                    'event_description': 'Test Description'
                })
                self.assertEqual(response.status_code, 302)  # Check for redirect after successful event creation

    def test_create_event_with_past_date(self):
        # Test creating an event with a past date
        with self.app.app_context():
            with self.client as c:
                c.post('/login', data={'username': 'admin', 'password': 'adminpassword'})
                response = c.post('/create_event', data={
                    'event_name': 'Past Event',
                    'event_date': '2020-01-01',
                    'event_location': 'Test Location',
                    'event_description': 'Test Description'
                })
                self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_create_event_with_invalid_location(self):
        # Test creating an event with an invalid location
        with self.app.app_context():
            with self.client as c:
                c.post('/login', data={'username': 'admin', 'password': 'adminpassword'})
                response = c.post('/create_event', data={
                    'event_name': 'Invalid Location Event',
                    'event_date': '2023-12-01',
                    'event_location': '',  # Invalid location
                    'event_description': 'Test Description'
                })
                self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_register_user_with_invalid_email(self):
        # Test user registration with an invalid email format
        response = self.client.post('/register', data={
            'username': 'testuser3',
            'password': 'testpassword',
            'email': 'invalid-email',  # Invalid email
            'name': 'Test User'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request due to invalid email

    def test_register_user_with_short_password(self):
        # Test user registration with a password that is too short
        response = self.client.post('/register', data={
            'username': 'testuser4',
            'password': 'short',  # Short password
            'email': 'testuser4@example.com',
            'name': 'Test User'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request due to short password

    def test_register_user_missing_username(self):
        # Test user registration without a username
        response = self.client.post('/register', data={
            'password': 'testpassword',
            'email': 'testuser5@example.com',
            'name': 'Test User'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_register_user_missing_password(self):
        # Test user registration without a password
        response = self.client.post('/register', data={
            'username': 'testuser6',
            'email': 'testuser6@example.com',
            'name': 'Test User'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_login_nonexistent_user(self):
        # Test login with a username that does not exist
        response = self.client.post('/login', data={
            'username': 'nonexistentuser',
            'password': 'testpassword'
        })
        self.assertEqual(response.status_code, 401)  # Check for unauthorized

    def test_login_empty_credentials(self):
        # Test login with empty username and password
        response = self.client.post('/login', data={})
        self.assertEqual(response.status_code, 400)  # Check for bad request

    def test_delete_event_by_admin(self):
        # Test that an admin can delete an event
        with self.app.app_context():
            with self.client as c:
                c.post('/login', data={'username': 'admin', 'password': 'adminpassword'})
                response = c.post('/create_event', data={
                    'event_name': 'Event to Delete',
                    'event_date': '2023-12-01',
                    'event_location': 'Test Location',
                    'event_description': 'Test Description'
                })
                event_id = ...  # Get the event ID from the response or database
                response = c.post(f'/delete_event/{event_id}')
                self.assertEqual(response.status_code, 302)  # Check for redirect after deletion

    def test_delete_event_by_non_admin(self):
        # Test that a non-admin cannot delete an event
        with self.app.app_context():
            with self.client as c:
                c.post('/login', data={'username': 'testuser', 'password': 'testpassword'})
                event_id = ...  # Get the event ID from the database
                response = c.post(f'/delete_event/{event_id}')
                self.assertEqual(response.status_code, 403)  # Check for forbidden

    def test_view_event_details(self):
        # Test viewing the details of a specific event
        event_id = ...  # Get the event ID from the database
        response = self.client.get(f'/event/{event_id}')
        self.assertEqual(response.status_code, 200)  # Check for successful view

    def test_view_user_profile(self):
        with self.app.app_context():
            user = User(username='testuser', password=generate_password_hash('testpassword'), school_name='Test School',
                        phone_number='1234567890', email='testuser@example.com', is_admin=False)
            db.session.add(user)
            db.session.commit()

        with self.client as c:
            # Try viewing profile without login
            response = c.get('/profile')
            self.assertEqual(response.status_code, 302)  # Should redirect to login
            self.assertNotIn('user_id', session)

            # Login and try again
            c.post('/login', data={
                'username': 'testuser',
                'password': 'testpassword'
            })
            self.assertIn('user_id', session)
            self.assertEqual(session['username'], 'testuser')
            self.assertFalse(session.get('is_admin', False))

            response = c.get('/profile')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'testuser', response.data)
            self.assertIn(b'Test School', response.data)

    def test_update_user_profile(self):
        with self.app.app_context():
            user = User(username='testuser', password=generate_password_hash('testpassword'), school_name='Test School',
                        phone_number='1234567890', email='testuser@example.com', is_admin=False)
            db.session.add(user)
            db.session.commit()

        with self.client as c:
            # Try updating profile without login
            response = c.post('/update_profile', data={
                'school_name': 'New School',
                'phone_number': '9876543210',
                'email': 'newemail@example.com'
            })
            self.assertEqual(response.status_code, 302)  # Should redirect to login
            self.assertNotIn('user_id', session)

            # Login and try again
            c.post('/login', data={
                'username': 'testuser',
                'password': 'testpassword'
            })
            self.assertIn('user_id', session)
            self.assertEqual(session['username'], 'testuser')

            response = c.post('/update_profile', data={
                'school_name': 'New School',
                'phone_number': '9876543210',
                'email': 'newemail@example.com'
            })
            self.assertEqual(response.status_code, 302)  # Should redirect to profile page

            # Verify changes
            with self.app.app_context():
                updated_user = User.query.filter_by(username='testuser').first()
                self.assertEqual(updated_user.school_name, 'New School')
                self.assertEqual(updated_user.email, 'newemail@example.com')

    def test_view_signups_for_event(self):
        with self.app.app_context():
            # Create admin user
            admin = User(username='admin', password=generate_password_hash('adminpass'), school_name='Admin School',
                        phone_number='1234567890', email='admin@example.com', is_admin=True)
            # Create regular user
            user = User(username='user', password=generate_password_hash('userpass'), school_name='User School',
                        phone_number='1234567890', email='user@example.com', is_admin=False)
            db.session.add(admin)
            db.session.add(user)
            
            event = Event(event_name='Test Event', event_date='2023-12-01', event_location='Test Location',
                          event_description='Test Description')
            db.session.add(event)
            db.session.commit()

            # Add a signup
            signup = Signup(user_id=user.id, event_id=event.id)
            db.session.add(signup)
            db.session.commit()

        with self.client as c:
            # Try viewing signups without login
            response = c.get(f'/view_signups/{event.id}')
            self.assertEqual(response.status_code, 302)  # Should redirect to login
            self.assertNotIn('user_id', session)

            # Try with regular user
            c.post('/login', data={
                'username': 'user',
                'password': 'userpass'
            })
            self.assertIn('user_id', session)
            self.assertFalse(session.get('is_admin', False))
            
            response = c.get(f'/view_signups/{event.id}')
            self.assertEqual(response.status_code, 302)  # Should redirect (not admin)

            # Logout regular user
            c.get('/logout')
            self.assertNotIn('user_id', session)

            # Try with admin
            c.post('/login', data={
                'username': 'admin',
                'password': 'adminpass'
            })
            self.assertIn('user_id', session)
            self.assertTrue(session.get('is_admin', False))

            response = c.get(f'/view_signups/{event.id}')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'User School', response.data)  # Should show the signup details

    def test_remove_signup(self):
        user = self.create_test_user()
        event = self.create_test_event()
        signup = Signup(user_id=user.id, event_id=event.id, first_name='Test', last_name='User', school_name=user.school_name)
        with self.app.app_context():
            db.session.add(user)  # Ensure user is added to the session
            db.session.add(event)  # Ensure event is added to the session
            db.session.add(signup)  # Add signup to the session
            db.session.commit()  # Commit all changes

        with self.client as c:
            # Try removing signup without login
            response = c.post(f'/remove_signup/{event.id}')
            self.assertEqual(response.status_code, 302)  # Should redirect to login
            self.assertNotIn('user_id', session)

            # Login and try again
            c.post('/login', data={
                'username': user.username,
                'password': 'testpassword'
            })
            self.assertIn('user_id', session)
            self.assertEqual(session['username'], user.username)
            self.assertEqual(session['user_id'], user.id)

            response = c.post(f'/remove_signup/{event.id}')
            self.assertEqual(response.status_code, 302)  # Should redirect after removal

            # Verify removal
            with self.app.app_context():
                signup = Signup.query.filter_by(user_id=user.id, event_id=event.id).first()
                self.assertIsNone(signup)

    def test_register_user_invalid_email(self):
        response = self.client.post('/register', data={
            'username': 'testuser2',
            'password': 'testpassword',
            'email': 'invalid-email',
            'phone_number': '1234567890',
            'school_name': 'Test School'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request due to invalid email

    def test_register_user_short_password(self):
        response = self.client.post('/register', data={
            'username': 'testuser3',
            'password': 'short',
            'email': 'testuser3@example.com',
            'phone_number': '1234567890',
            'school_name': 'Test School'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request due to short password

    def test_create_event_invalid_date_format(self):
        response = self.client.post('/create_event', data={
            'event_name': 'Test Event',
            'event_date': 'invalid-date',
            'event_location': 'Test Location',
            'event_description': 'Test Description'
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request due to invalid date format

    def test_sign_up_for_full_event(self):
        # Assuming there's a way to create a full event in your test setup
        event = self.create_test_event(name='Full Event', date='2030-12-01')
        # Mark this event as full in your application logic
        response = self.client.post('/sign_up', data={
            'event_id': event.id,
            'user_id': 1  # Assuming user with ID 1 exists
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request due to full event

    def test_view_events_no_events(self):
        response = self.client.get('/events')
        self.assertEqual(response.status_code, 200)  # Check for successful view
        self.assertIn(b'No events available', response.data)  # Check for the message indicating no events

    def test_sign_up_for_event_invalid_user_id(self):
        user = self.create_test_user()
        event = self.create_test_event()
        response = self.client.post('/sign_up/999', data={
            'first_name': 'Test',
            'last_name': 'User',
            'school_name': user.school_name
        })
        self.assertEqual(response.status_code, 404)  # Check for 404 error

    def test_sign_up_for_event_missing_fields(self):
        user = self.create_test_user()
        event = self.create_test_event()
        response = self.client.post(f'/sign_up/{event.id}', data={
            'last_name': 'User',
            'school_name': user.school_name
        })
        self.assertEqual(response.status_code, 400)  # Check for bad request due to missing first_name

    def test_remove_signup(self):
        user = self.create_test_user()
        event = self.create_test_event()
        signup = Signup(user_id=user.id, event_id=event.id, first_name='Test', last_name='User', school_name=user.school_name)
        with self.app.app_context():
            db.session.add(user)  # Ensure user is added to the session
            db.session.add(event)  # Ensure event is added to the session
            db.session.add(signup)  # Add signup to the session
            db.session.commit()  # Commit all changes

        with self.client as c:
            # Try removing signup without login
            response = c.post(f'/remove_signup/{event.id}')
            self.assertEqual(response.status_code, 302)  # Should redirect to login
            self.assertNotIn('user_id', session)

            # Login and try again
            c.post('/login', data={
                'username': user.username,
                'password': 'testpassword'
            })
            self.assertIn('user_id', session)
            self.assertEqual(session['username'], user.username)
            self.assertEqual(session['user_id'], user.id)

            response = c.post(f'/remove_signup/{event.id}')
            self.assertEqual(response.status_code, 302)  # Should redirect after removal

            # Verify removal
            with self.app.app_context():
                signup = Signup.query.filter_by(user_id=user.id, event_id=event.id).first()
                self.assertIsNone(signup)

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

def load_signups():
    if not os.path.exists('data/signups.json'):
        return {}
    with open('data/signups.json', 'r') as f:
        return json.load(f)

def save_signups(signups):
    with open('data/signups.json', 'w') as f:
        json.dump(signups, f)

def load_signups_for_event(event_id):
    signups = load_signups()
    return signups.get(str(event_id), [])

def load_event(event_id):
    events = load_events()
    return events.get(str(event_id), None)

def load_events():
    if not os.path.exists('data/events.json'):
        return {}
    with open('data/events.json', 'r') as f:
        return json.load(f)

def save_events(events):
    with open('data/events.json', 'w') as f:
        json.dump(events, f)

if __name__ == '__main__':
    unittest.main()