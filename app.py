
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), default='user')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/demote')
@login_required
def demote():
    user = User.query.filter_by(id=current_user.id).first()
    if user.role == 'admin':
        user.role = 'user'
        db.session.commit()
        return "You have been demoted to a regular user."
    return "You are already a regular user."

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
            session['username'] = user.username
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')  # padrão: user

        # Evitar duplicidade
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "User already exists!"

        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return '''
        <h2>Register</h2>
        <form method="POST">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            Role: <select name="role">
                    <option value="user">user</option>
                    <option value="admin">admin</option>
                  </select><br>
            <input type="submit" value="Register">
        </form>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

# VULNERABILIDADE: qualquer usuário pode se tornar admin
@app.route('/make_admin')
def make_admin():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            user.role = 'admin'
            db.session.commit()
            return "You are now an admin!"
    return "Unauthorized", 403

# PAINEL ADMIN COM
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role == 'admin':
        return render_template('admin.html', access_granted=True)
    else:
        return render_template('admin.html', access_granted=False)
@app.route('/exploit')
@login_required
def exploit():
    return render_template('exploit.html')

@app.route('/execute_exploit')
@login_required
def execute_exploit():
    if current_user.role != 'admin':
        user = User.query.filter_by(id=current_user.id).first()
        user.role = 'admin'
        db.session.commit()
    return redirect(url_for('dashboard'))
@app.route('/adminify_me_plz')
@login_required
def adminify():
    if current_user.role != 'admin':
        user = User.query.filter_by(id=current_user.id).first()
        user.role = 'admin'
        db.session.commit()
    return redirect(url_for('dashboard'))

import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

