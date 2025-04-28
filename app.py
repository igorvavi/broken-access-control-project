from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                return abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    user_count = User.query.count()
    if user_count > 0 and (not current_user.is_authenticated or current_user.role not in ['admin']):
        return abort(403)

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')

        if User.query.filter_by(username=username).first():
            return "Username already exists."

        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', role=current_user.role)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role in ['admin', 'superadmin']:
        return render_template('admin.html', access_granted=True)
    return render_template('admin.html', access_granted=False)

# Vulnerability: This route does not call the decorator "role_required" so any LOGGED-IN user can escalate to admin
@app.route('/adminify_me_plz')
@login_required
def adminify():
    user = User.query.filter_by(id=current_user.id).first()
    user.role = 'admin'
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/seed-users', methods=['GET', 'POST'])
def seeder():
    new_user = User(username="bob", password="p@ssword", role="user")
    new_user_admin = User(username="alice", password="p@ssword", role="admin")
    db.session.add(new_user)
    db.session.add(new_user_admin)
    db.session.commit()
    
    return redirect(url_for('login'))

@app.route('/demote')
@login_required
def demote():
    user = User.query.filter_by(id=current_user.id).first()
    if user.role == 'admin':
        user.role = 'user'
        db.session.commit()
        return "You have been demoted to a regular user."
    return "You are already a regular user."

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
