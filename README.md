# broken-access-control-project

This project is a simple Flask web app designed to **demonstrate common Broken Access Control vulnerabilities** in a controlled and educational environment. It includes both **vulnerable** and **patched** versions of the app, so you can learn by seeing exactly what goes wrong—and how to fix it.

## About the Project

Access control is one of the most misunderstood areas in web app security. This project makes it easier to understand by showing:

- How users can escalate privileges to become admins  
- How unauthorized users can register and gain system access  
- How role-based access should be enforced in real apps  

The app uses Flask, SQLAlchemy, and Bootstrap for a clean full-stack experience.

## Real-World Vulnerability References

This app is inspired by two real-world CVEs that demonstrate the risks of improper access control.

### CVE-2018-10561 - GoAhead Web Server

In some routers, admin pages were accessible without authentication. This maps directly to our `/adminify_me_plz` route, where logged-in users can become admins without any permission check.  
Referenced CWE: **CWE-269: Improper Privilege Management**

### CVE-2021-32849 - Parse Server

Authenticated users could assign themselves elevated roles due to missing logic in role control. Similarly, in our vulnerable version, anyone can access `/register` and create users.  
Referenced CWE: **CWE-284: Improper Access Control**

## App Features

### Vulnerable Version

- Public `/register` route (anyone can create users)  
- Open `/adminify_me_plz` route (any logged-in user can become admin)  
- No role checks on sensitive pages like `/admin`  
- Planned IDOR via predictable `/user/<id>` (coming soon)  

### Secure Version

- Role-based decorators like `@role_required('admin')`  
- Only the first registered user can register freely; all others must be created by admins  
- Protected dashboard and admin routes  
- Clean layout using Bootstrap 5  

## Project Structure

broken-access-control-project
├── app.py              # Flask application logic
├── templates/          # HTML templates using Bootstrap
├── static/             # CSS/JS (optional)
├── users.db            # SQLite database (auto-created)
└── Dockerfile          # Optional containerized deployment

## How to Run Locally

# 1. Clone the repo
git clone https://github.com/igorvavi/broken-access-control-project.git
cd broken-access-control-project

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py

By default, the app runs at `http://127.0.0.1:5000`.
