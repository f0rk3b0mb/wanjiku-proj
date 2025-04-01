import hashlib
from cryptography.fernet import Fernet
import os
from io import BytesIO
from flask import make_response
from functools import wraps
from flask import session, redirect, url_for
from database import User
import pyotp


# encryptor
# Generate a random encryption key (you should keep this key secret)
#SECRET_KEY = Fernet.generate_key()
SECRET_KEY = "jd59OShUKDxZTNRrTs4orSPFTmk0fjhk67PT119olAc=" # secret should be stored in environ
cipher_suite = Fernet(SECRET_KEY)

def encrypt_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            encrypted_data = cipher_suite.encrypt(file_data)

        # Save the encrypted data back to the file
        with open(file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        return True, "File encrypted successfully"
    except Exception as e:
        return False, str(e)



# decryptor

def decrypt_file(file_path):
    try:
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)

        # Create a BytesIO object with the decrypted data
        decrypted_io = BytesIO(decrypted_data)

        # Create a Flask response with the decrypted data as content
        response = make_response(decrypted_io.getvalue())

        # Set appropriate headers for the response
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename={os.path.basename(file_path)}'

        return True, response
    except Exception as e:
        return False, str(e)

# integrity checking



def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)  # Read in 64 KB chunks
            if not data:
                break
            sha256_hash.update(data)
    return sha256_hash.hexdigest()


# backup


#login check

def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("web.login"))
        return func(*args, **kwargs)
    return decorated_function


def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")

        if user_id is None:
            return redirect(url_for("web.login"))

        user = User.query.get(user_id)

        if not user:
            return redirect(url_for("web.login"))

        if session.get("role") != 1:
            return "Only admin is allowed to access this page"

        return func(*args, **kwargs)
    return decorated_function

def generate_otp():
    # Replace this with your secret key used for OTP generation
    secret_key = os.environ['OTP_SECRET_KEY'] # store in environ

    # Create a TOTP object using the secret key and the user's email
    totp = pyotp.TOTP(secret_key)

    # Generate the OTP
    otp_code = totp.now()

    return otp_code