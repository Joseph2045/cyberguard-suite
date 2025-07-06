from flask import Flask, render_template
from flask_login import LoginManager, login_required, current_user
from routes.auth import auth_bp
from database.db_connection import create_connection
from models.app_user import AppUser
from datetime import timedelta
import mysql.connector

app = Flask(__name__)
app.secret_key = "your_secret_key_here"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=220)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    conn = None
    cursor = None
    try:
        conn = create_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return AppUser(user_data['id'], user_data['username'], user_data['email'])
        return None
    except mysql.connector.Error as err:
        print(f"Error loading user: {err}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

app.register_blueprint(auth_bp)

@app.route('/')
def index():
    return render_template('index.html')

# Remove the duplicate dashboard route since it's in auth.py
# This prevents potential conflicts

if __name__ == '__main__':
    app.run(debug=True)
