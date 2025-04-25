from flask import Flask
from database import db, bcrypt
from blueprints.routes import web, api
from database import User , Role # Replace 'YourModel' with your actual model
from datetime import timedelta
from dotenv import load_dotenv
import os
#from flask_sslify import SSLify

app = Flask(__name__)
load_dotenv()
#sslify = SSLify(app)

app.permanent_session_lifetime = timedelta(minutes=5)

# Load your Flask app configuration here
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.secret_key =  os.environ['APP_SECRET_KEY']# should be sored in environ

# Initialize Flask extensions
db.init_app(app)
bcrypt.init_app(app)

# Register your blueprints
app.register_blueprint(web, url_prefix='/')
app.register_blueprint(api, url_prefix='/api')

# Function to insert a default record
def add_default_record():
    with app.app_context():
        # Create a default record using your model
        default_admin = User(username="admin", password=os.environ['ADMIN_PASS'] , email="admin@admin.com", role_id=1, is_approved="True")
        db.session.add(default_admin)
        default_user = User(username="test", password=os.environ['TEST_PASS'] , email="test@test.com", role_id=2, is_approved="True")
        db.session.add(default_user)
        admin_role = Role(id=1 , role_name="admin")
        db.session.add(admin_role)
        user_role = Role(id=2 , role_name="Staff")
        db.session.add(user_role)
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        #db.drop_all()  #for testing purposes
        db.create_all()
        #add_default_record()  # for testing purposes
    app.run(host="0.0.0.0", port=1234, debug=True)#,ssl_context=('https_certs/cert.pem', 'https_certs/key.pem'))
