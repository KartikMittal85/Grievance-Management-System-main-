# app.py
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import os

# ----------------- App Setup -----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisasecretkey'
db_path = os.path.join(os.path.dirname(__file__), 'grievance.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ----------------- Flask-Login Setup -----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ----------------- Models -----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # student, vip, admin
    # optional email - keep consistent with your models.py if needed
    email = db.Column(db.String(150), unique=True, nullable=True)

class Grievance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='Submitted')
    remarks = db.Column(db.Text, default='')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    escalated_at = db.Column(db.DateTime, nullable=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

# ----------------- User Loader -----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------- Routes -----------------
@app.route('/')
def home():
    return redirect(url_for('login'))

# ----------------- Register -----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'student')

        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('User created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# ----------------- Login -----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'student':
                return redirect(url_for('student_dashboard'))
            elif user.role == 'vip':
                return redirect(url_for('vip_dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

# ----------------- Logout -----------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ----------------- Fetch Grievances (AJAX for Student) -----------------
@app.route('/fetch_grievances')
@login_required
def fetch_grievances():
    if current_user.role != 'student':
        return jsonify({"error": "Unauthorized"}), 403

    grievances = Grievance.query.filter_by(student_id=current_user.id).order_by(Grievance.last_updated.desc()).all()
    data = []
    for g in grievances:
        data.append({
            "id": g.id,
            "title": g.title,
            "category": g.category,
            "description": g.description,
            "status": g.status,
            "remarks": g.remarks.replace("\n", "<br>") if g.remarks else "",
            "last_updated": (g.last_updated or g.date_created).strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify(data)

# ----------------- Student Dashboard -----------------
@app.route('/student_dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return "Unauthorized", 403

    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        description = request.form['description']

        new_grievance = Grievance(
            title=title,
            category=category,
            description=description,
            student_id=current_user.id
        )
        db.session.add(new_grievance)
        db.session.commit()
        flash('Grievance submitted successfully!', 'success')

    return render_template('student_dashboard.html')

# ----------------- VIP Dashboard -----------------
@app.route('/vip_dashboard', methods=['GET'])
@login_required
def vip_dashboard():
    if current_user.role != 'vip':
        return "Unauthorized", 403
    # Only escalated grievances
    grievances = Grievance.query.filter_by(status='Escalated').order_by(Grievance.last_updated.desc()).all()
    return render_template('vip_dashboard.html', grievances=grievances)

# ----------------- Admin Dashboard -----------------
@app.route('/admin_dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return "Unauthorized", 403
    # Admin sees non-escalated grievances
    grievances = Grievance.query.filter(Grievance.status != 'Escalated').order_by(Grievance.last_updated.desc()).all()
    return render_template('admin_dashboard.html', grievances=grievances)

# ----------------- Update Grievance (Admin) -----------------
@app.route('/update_grievance/<int:grievance_id>', methods=['POST'])
@login_required
def update_grievance(grievance_id):
    if current_user.role != 'admin':
        return "Unauthorized", 403

    grievance = Grievance.query.get_or_404(grievance_id)
    status = request.form.get('status')
    new_remarks = (request.form.get('remarks') or '').strip()

    # admin may update to any of the allowed statuses
    grievance.status = status
    grievance.last_updated = datetime.utcnow()

    if new_remarks:
        prefix = "[Admin]: "
        if grievance.remarks:
            grievance.remarks += f"\n{prefix}{new_remarks}"
        else:
            grievance.remarks = f"{prefix}{new_remarks}"

    # If admin resolves or rejects, clear escalated_at (if previously escalated)
    if status in ('Resolved', 'Rejected'):
        grievance.escalated_at = None

    db.session.commit()
    flash(f'Grievance ID {grievance_id} updated successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# ----------------- Update Grievance (VIP) -----------------
@app.route('/update_grievance_vip/<int:grievance_id>', methods=['POST'])
@login_required
def update_grievance_vip(grievance_id):
    if current_user.role != 'vip':
        return "Unauthorized", 403

    grievance = Grievance.query.get_or_404(grievance_id)
    status = request.form.get('status')
    new_remarks = (request.form.get('remarks') or '').strip()

    # VIP limited to Seen and In Progress and can move to Resolved if appropriate
    if status not in ['Seen', 'In Progress', 'Resolved', 'Rejected']:
        flash('Invalid status for VIP.', 'danger')
        return redirect(url_for('vip_dashboard'))

    grievance.status = status
    grievance.last_updated = datetime.utcnow()

    if new_remarks:
        prefix = "[VIP]: "
        if grievance.remarks:
            grievance.remarks += f"\n{prefix}{new_remarks}"
        else:
            grievance.remarks = f"{prefix}{new_remarks}"

    # If VIP resolves, ensure escalated_at is preserved/cleared appropriately
    if status in ('Resolved', 'Rejected'):
        grievance.escalated_at = None

    db.session.commit()
    flash(f'Grievance ID {grievance_id} updated successfully!', 'success')
    return redirect(url_for('vip_dashboard'))

# ----------------- Feedback Form -----------------
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        if not name or not email or not message:
            flash('All fields are required!', 'danger')
            return jsonify({"error": "All fields are required"}), 400

        new_feedback = Feedback(name=name, email=email, message=message)
        db.session.add(new_feedback)
        db.session.commit()

        flash('Thank you for your feedback!', 'success')
        # if AJAX: return JSON ok, else redirect
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"success": True})
        return redirect(url_for('feedback'))

    # For GET, return JSON for admin quick view (used by your admin JS)
    if request.args.get('json') == '1' or request.is_json:
        data = [{
            "id": f.id,
            "name": f.name,
            "message": f.message,
            "email": f.email,
            "created_at": f.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "is_read": f.is_read
        } for f in Feedback.query.order_by(Feedback.created_at.desc()).all()]
        return jsonify(data)

    return render_template('feedback.html')

# ----------------- Admin Feedback Viewing -----------------
@app.route('/admin_feedbacks')
@login_required
def admin_feedbacks():
    if current_user.role != 'admin':
        return "Unauthorized", 403

    feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return render_template('admin_feedbacks.html', feedbacks=feedbacks)

@app.route('/feedback/read/<int:fid>', methods=['POST'])
@login_required
def mark_feedback_read(fid):
    if current_user.role != 'admin':
        return "Unauthorized", 403
    f = Feedback.query.get_or_404(fid)
    f.is_read = True
    db.session.commit()
    return ('', 204)

# ----------------- Escalation Job -----------------
def escalate_old_grievances(days=7):
    """Find grievances older than `days` days with no resolution and mark them Escalated."""
    with app.app_context():
        threshold_days = days
        all_pending = Grievance.query.filter(Grievance.status.notin_(['Resolved', 'Rejected', 'Escalated'])).all()
        now = datetime.utcnow()
        escalated_count = 0
        for g in all_pending:
            delta = now - (g.date_created or g.last_updated)
            if delta.days >= threshold_days:
                g.status = 'Escalated'
                g.escalated_at = now
                g.last_updated = now
                escalated_count += 1
        if escalated_count:
            db.session.commit()
            app.logger.info(f"Escalation job: escalated {escalated_count} grievances.")
        else:
            app.logger.debug("Escalation job: nothing to escalate.")

# ----------------- Scheduler Setup -----------------
scheduler = BackgroundScheduler()
# run every hour — adjust as needed (or change to 'cron' for daily checks)
scheduler.add_job(func=lambda: escalate_old_grievances(days=7), trigger='interval', hours=1, id='escalate_job')
scheduler.start()

# shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown(wait=False))

# ----------------- Initialize DB & Run App -----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # optional: run escalate once at startup
        escalate_old_grievances(days=7)
    app.run(debug=True)
