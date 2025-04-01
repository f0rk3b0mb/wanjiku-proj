from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email= db.Column(db.String(50))
    role_id = db.Column(db.Integer, nullable=False)
    is_approved= db.Column(db.String(10))
    date_registered = db.Column(db.String(20))
    otp= db.Column(db.Integer)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    ipfs_hash = db.Column(db.String(255), nullable=False)  # IPFS hash
    blockchain_tx = db.Column(db.String(66), nullable=False)  # Blockchain transaction hash
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    file_size = db.Column(db.Integer, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    is_pending_deletion = db.Column(db.String(5), default="False")
    certificate_id = db.Column(db.String(255), nullable=True)


class Backups(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(60))
    date_created = db.Column(db.String(60))
    file_size= db.Column(db.String(60))
    sha256sum= db.Column(db.Integer)


class Role(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('user.role_id'), primary_key=True)
    role_name = db.Column(db.String(255), nullable=False)

