
from flask import Flask
from auth.login import auth_bp, login_manager
from ids.detection import ids_bp
from crypto.crypto_tool import crypto_bp
from scanner.port_scan import scanner_bp
from dashboard.dashboard import dashboard_bp
from database.db import db_init, get_db


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
login_manager.init_app(app)



# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(ids_bp)
app.register_blueprint(crypto_bp)
app.register_blueprint(scanner_bp)
app.register_blueprint(dashboard_bp)


db_init(app)
with app.app_context():
    db = get_db()
    db.create_all()

# Home route
from flask import render_template
@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
