# broken-access-control-project

This project is a simple Flask web app designed to **demonstrate common Broken Access Control vulnerabilities** in a controlled and educational environment. It includes both **vulnerable** and **patched** versions of the app, so you can learn by seeing exactly what goes wrong—and how to fix it.

---

## 📌 About the Project

Access control is one of the most misunderstood areas in web app security. This project makes it easier to understand by showing:

- How users can **escalate privileges** to become admins
- How **unauthorized users** can register and gain system access
- How **role-based access** should be enforced in real apps

You’ll also find clean, readable code using **Flask**, **SQLAlchemy**, and **Bootstrap** for a solid frontend/backend experience.

---

## 🚨 Real-World Vulnerability References

This app is inspired by two real-world CVEs that show how dangerous Broken Access Control flaws can be:

### ✅ CVE-2018-10561 - GoAhead Web Server
> In some routers, admin pages could be accessed without any authentication. That’s exactly what happens in our `/adminify_me_plz` route—users can become admins with no permission checks.  
➡️ **CWE-269: Improper Privilege Management**

### ✅ CVE-2021-32849 - Parse Server
> Authenticated users could assign themselves elevated roles because of missing logic in role creation. Similarly, our app’s vulnerable version lets users access `/register` and create new accounts freely.  
➡️ **CWE-284: Improper Access Control**

---

## 🚀 App Features

### 🔓 Vulnerable Version
- Public `/register` route (anyone can create users)
- Open `/adminify_me_plz` route (any logged-in user can become admin)
- No role checks on sensitive pages like `/admin`
- Planned IDOR via predictable `/user/<id>` (coming soon)

### 🔒 Secure Version
- Role-based decorators like `@role_required('admin')`
- Only the **first registered user** can register freely; others need admin
- Dashboard and admin routes protected
- Visual layout with **Bootstrap 5**

---

## 📂 Project Structure

📁 broken-access-control-project 
├── app.py # Flask application logic 
├── templates/ # HTML templates using Bootstrap 
├── static/ # CSS/JS (optional) 
├── users.db # SQLite database (auto-created) 
└── Dockerfile # Optional containerized deployment

---

## 🔧 How to Run Locally


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
