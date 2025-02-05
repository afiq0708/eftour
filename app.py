import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, logout_user, login_required, current_user
from flask_dance.contrib.google import make_google_blueprint, google

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to your own secret key

# Correct SQLite URI (check the path to your database file)
database_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Google OAuth Setup with Flask-Dance
google_bp = make_google_blueprint(client_id='YOUR_GOOGLE_CLIENT_ID',  # Replace with your Google Client ID
                                  client_secret='YOUR_GOOGLE_CLIENT_SECRET',  # Replace with your Google Client Secret
                                  redirect_to='google_authorized')
app.register_blueprint(google_bp, url_prefix='/google_login')

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Admin Flag

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Page Route
@app.route('/')
def home():
    return render_template("index.html")

# Register Route
@app.route('/register', methods=['POST'])
def register():
    name = request.form['name']
    email = request.form['email']
    username = request.form['username']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

    if User.query.filter_by(email=email).first():
        flash("Email already exists!", "danger")
        return redirect(url_for('home'))

    new_user = User(name=name, email=email, username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    flash("Registration successful!", "success")
    return redirect(url_for('home'))

# Login Route
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid Credentials", "danger")
    return redirect(url_for('home'))

# Google OAuth Route
@app.route('/google-authorized')
def google_authorized():
    if not google.authorized:
        flash("Google login failed", "danger")
        return redirect(url_for("home"))

    # Get user info from Google
    google_info = google.get('/plus/v1/people/me')
    user_data = google_info.json()
    email = user_data['emails'][0]['value']
    name = user_data['displayName']

    # Check if user exists in the database
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(name=name, email=email, username=email.split('@')[0], password="Google_OAuth")
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash("Google Login Successful!", "success")
    return redirect(url_for("dashboard"))

# Dashboard Route
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

# Admin Route
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied!", "danger")
        return redirect(url_for("dashboard"))
    return render_template("admin.html", users=User.query.all())

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("home"))

# Main Program Setup
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist already
    app.run(debug=True)

