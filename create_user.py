from app import app, db, User

with app.app_context():
    username = input("Username: ")
    password = input("Password: ")

    existing = User.query.filter_by(username=username).first()
    if existing:
        print("User already exists.")
    else:
        role = input("Role (user/admin): ").strip().lower()
        if role not in ['user', 'admin']:
            role = 'user'
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        print(f"User '{username}' created successfully with role '{role}'.")

