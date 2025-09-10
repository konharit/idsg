from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

def db_init(app):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids_project.db'
    db.init_app(app)

from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

def get_db():
    return db
