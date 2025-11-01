# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='student')  # 'student', 'admin', 'vip'
    
    # relationship to grievances (as student)
    grievances = db.relationship('Grievance', backref='student', lazy=True)

class Grievance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100))
    title = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='Submitted')  # Submitted, Seen, In Progress, Resolved, Rejected, Escalated
    remarks = db.Column(db.Text, default='')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)   # submission time
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    escalated_at = db.Column(db.DateTime, nullable=True)  # set when escalated

    def needs_escalation(self, days=7):
        """Return True if grievance is older than `days` and still not handled."""
        if self.status in ('Resolved', 'Rejected', 'Escalated'):
            return False
        elapsed = datetime.utcnow() - (self.date_created or self.last_updated or datetime.utcnow())
        return elapsed.days >= days
