from flask import Blueprint, render_template, redirect, url_for, request, session ,jsonify , make_response
import os
from database import db, bcrypt , User , File , Backups, Role 
from utils import calculate_sha256, encrypt_file , decrypt_file , login_required , generate_otp, admin_required
import datetime
from  report_generator import generate_files_report, generate_users_report , generate_backups_report
import subprocess
from blockchain_utils import BlockchainUtils

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

# Initialize BlockchainUtils
blockchain_utils = BlockchainUtils(ganache_url="http://127.0.0.1:7545")


@web.route("/")
def index():
    return render_template("landing.html")


@web.before_request
def before_request():
    if 'user_id' in session and session.permanent:
        session.modified = True  # Reset the session timer on each request

    # Define a list of allowed endpoints for non-logged-in users
    allowed_endpoints = ['web.login', 'web.register', 'web.index' , 'web.faq']  # Add more endpoints as needed

    # Check if the user is not logged in and not accessing allowed endpoints
    if not session.get('user_id') and request.endpoint not in allowed_endpoints:
        return redirect(url_for('web.login'))

@web.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session['username'])

@web.route("/upload")
@login_required
def upload():
    return render_template("upload.html")

@web.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Check if the user exists
        user = User.query.filter((User.username == email) | (User.email == email)).first()

        if user:
            # Check if the user is approved
            if user.is_approved == "True":
                if bcrypt.check_password_hash(user.password, password):
                    otp_code = generate_otp()
                    user.otp = otp_code
                    print(otp_code)
                    db.session.commit()
                    session["user_id"] = user.id
                    session["username"] = user.username
                    session["role"] = user.role_id
                    if otp_code:
                        return redirect(url_for("web.dashboard"))
                else:
                    return render_template("login.html", message="Incorrect username or password")
            else:
                return render_template("login.html", message="Await admin approval")
        else:
            return render_template("login.html", message="Incorrect username or password")

    return render_template("login.html")


@web.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")  # Get the OTP entered by the user

        # For demonstration purposes, let's assume the generated OTP is stored in the db
        user = User.query.get(session.get('user_id'))

        if int(entered_otp) == user.otp:
            if user.role_id == 1:
                return redirect(url_for("web.dashboard"))
            else:
                return redirect(url_for("web.dashboard")) 
        else:
            # Incorrect OTP, display an error message
            return render_template("verify_otp.html", message="Incorrect OTP. Please try again.")

    return render_template("verify_otp.html")

@web.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        role = 3


        #remove bad characters
        for i in ["{","}","(",")","<",">","/","\\"]:
            if i in username:
                return render_template("register.html",message="Illegal characters in username")


        # Check if the username is already taken
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template("register.html",message="Username already taken.")
        else:
            # Hash the password and create a new user
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            new_user = User(username=username, password=hashed_password , email=email, role_id=role, is_approved="False", date_registered=datetime.date.today())
            db.session.add(new_user)
            db.session.commit()
            return render_template("login.html", message="Await admin approval") # Redirect to the login route

    return render_template("register.html")

@web.route("/faq")
def faq():
    return render_template("faq.html")
    

@web.route("/logout")
def logout():
    session.pop("user_id",None)
    session.pop("username",None)
    session.pop("role",None)
    return redirect(url_for("web.login")) 

@web.route("/admin")
@admin_required  # Apply the decorator to protect this admin route
def admin():
    user = User.query.all()
    files = File.query.all()

    return render_template("admin.html", username= session["username"]) 




@api.route("/viewFiles")
@login_required
def viewFile():
    # Fetch private files from the database for the current user
    private_files = File.query.filter_by(owner_id=session["user_id"]).all()
    private_file_names = [file.file_name for file in private_files]

    return jsonify({"private": private_file_names})    ## fix display 
    

@api.route('/addFiles', methods=['POST'])
@login_required
def add_files():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    permission_level = request.form.get('permission', '1')  # Default to private (1)
    
    if file:
        # Create temp directory if it doesn't exist
        temp_dir = 'temp'
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save file temporarily
        temp_path = os.path.join(temp_dir, file.filename)
        file.save(temp_path)
        
        try:
            # Calculate file hash
            file_hash = calculate_sha256(temp_path)
            
            # Store hash in blockchain
            contract_address = os.getenv('CONTRACT_ADDRESS')
            contract_abi = '[{"inputs": [], "stateMutability": "nonpayable", "type": "constructor"}, {"anonymous": false, "inputs": [{"indexed": true, "internalType": "string", "name": "certificateId", "type": "string"}, {"indexed": false, "internalType": "string", "name": "ipfsHash", "type": "string"}, {"indexed": true, "internalType": "address", "name": "issuer", "type": "address"}], "name": "CertificateIssued", "type": "event"}, {"inputs": [{"internalType": "string", "name": "certificateId", "type": "string"}], "name": "getIssuer", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "certificateId", "type": "string"}, {"internalType": "string", "name": "ipfsHash", "type": "string"}], "name": "issueCertificate", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [], "name": "owner", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "certificateId", "type": "string"}], "name": "verifyCertificate", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"}]'  # Add your contract ABI here
            account_address = os.getenv('ACCOUNT_ADDRESS')  # Set in environment
            private_key = os.getenv('PRIVATE_KEY')  # Set in environment
            
            # Generate a unique certificate ID using file name and timestamp
            certificate_id = f"{file.filename}_{int(datetime.datetime.now().timestamp())}"
            
            success, tx_hash = blockchain_utils.store_file_hash(
                contract_address,
                contract_abi,
                file_hash,
                account_address,
                private_key,
                certificate_id
            )
            
            if not success:
                return jsonify({'error': 'Failed to store hash in blockchain'}), 500
            
            # Encrypt the file
            success, message = encrypt_file(temp_path)
            if not success:
                return jsonify({'error': f'Failed to encrypt file: {message}'}), 500
            
            # Determine permission level and set target directory
            if permission_level == '1':  # Private file
                target_dir = os.path.join('uploads', 'private')
            else:  # Public file
                target_dir = os.path.join('uploads', 'public')
            
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, file.filename)
            os.rename(temp_path, target_path)
            
            # Save file information to database
            new_file = File(
                file_name=file.filename,
                file_path=target_path,
                ipfs_hash=file_hash,  # Store the file hash instead of IPFS hash
                blockchain_tx=tx_hash,  # Store the transaction hash
                upload_date=datetime.datetime.now(),
                file_size=os.path.getsize(target_path),  # Get file size in bytes
                owner_id=session['user_id'],
                is_archived=False,
                certificate_id=certificate_id  # Store the certificate ID
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            return render_template("upload.html", status="File uploaded successfully") 
            
        except Exception as e:
            # Clean up temp file if it exists
            if os.path.exists(temp_path):
                os.remove(temp_path)
            return jsonify({'error': str(e)}), 500
            
        finally:
            # Clean up temp file if it still exists
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    return jsonify({'error': 'Invalid file'}), 400

@api.route("/deleteFiles", methods=["POST"])
@login_required
def delete_file():
    file_name = request.form.get("file_name")

    if file_name:
        file_path = os.path.join("uploads", session["username"], file_name)

        if os.path.exists(file_path):
            # Mark the file as pending for deletion in the database
            file = File.query.filter_by(file_name=file_name).first()

            if file:
                file.is_pending_deletion = "True"
                db.session.commit()
                return "File will be archived"
            else:
                return "File not found or already archived"



@api.route('/download/<file_name>')
@login_required
def download_file(file_name):
        
        for i in ["/","../","\\","..\\"]:
            if i in file_name:
                return "illegal characters in filename"
        
        file_path = os.path.join('uploads',"public", file_name)

        # Decrypt the file and get the Flask response
        success, response = decrypt_file(file_path)

        if success:
            return response
        else:
            return f'Failed to decrypt the file {response}'

##admin functionaties



@api.route('/pending_users', methods=['GET'])
@admin_required
def get_pending_users():
    # Query the database to get pending user registrations
    pending_users = User.query.filter_by(is_approved="False").all()
    # Create a list to store user details
    pending_user_details = []

    for user in pending_users:
        user_detail = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': None
        }
        if user.role_id:
            role = Role.query.get(user.role_id)
            if role:
                user_detail['role'] = role.role_name

        pending_user_details.append(user_detail)

    # Return the pending user details in JSON format using jsonify
    return jsonify(pending_user_details)

@api.route("/archived_files", methods=["GET"])
@admin_required
def get_archived_requests():
    # Find all files that are pending deletion
    pending_deletion_files = File.query.filter_by(is_pending_deletion="True").all()
    
    pending_files_details = []

    for file in pending_deletion_files:
        file_detail = {
            'file_id': file.id,
            'filename': file.file_name,
            'owner': file.user_id,
            'permission': None
        }
        if file.permission_level:
            perm = Permission.query.get(file.permission_level)
            if perm:
                file_detail['permission'] = perm.permission
        pending_files_details.append(file_detail)
    
    return jsonify(pending_files_details)


@api.route("/restore_file/<int:file_id>", methods=["POST"])
@admin_required
def restore_file(file_id):
    # Find the file by name
    file = File.query.filter_by(id=file_id).first()

    if file and file.is_pending_deletion:
        file.is_pending_deletion = "False"
        db.session.commit()
        return jsonify({"message": "File Restored to system"})
    else:
        return jsonify({"message": "File not found or not archived."})


@api.route('/approve_user/<int:user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    # Check if the request is a POST request
    if request.method == 'POST':
        # Find the user by ID
        user = User.query.get(user_id)
        
        if user:
            # Mark the user as approved
            user.is_approved = "True"
            db.session.commit()
            user_folder = os.path.join("uploads", user.username)
            os.makedirs(user_folder, exist_ok=True)
            return jsonify({'message': 'User has been approved.'}), 200
        else:
            return jsonify({'error': 'User not found.'}), 404

    return jsonify({'error': 'Invalid request method.'}), 405

@api.route('/reject_user/<int:user_id>', methods=['POST'])
@admin_required
def reject_user(user_id):
    # Check if the request is a POST request
    if request.method == 'POST':
        # Find the user by ID
        user = User.query.get(user_id)
        rejection_reason = request.json.get('rejectionReason')
        
        if user: 
            reasons_file_path = os.path.join('logs', 'rejection_reasons.log')
            with open(reasons_file_path, 'a') as reasons_file:
                reasons_file.write(f"Username: {user.username}, Email: {user.email}, Reason: {rejection_reason}\n")
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User has been removed'}), 200
        else:
            return jsonify({'error': 'User not found.'}), 404

    return jsonify({'error': 'Invalid request method.'}), 405



@web.route("/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        # Handle the user deletion based on the submitted form data
        user_id_to_delete = request.form.get("user_id_to_delete")
        
        # Check if the user_id_to_delete is valid (e.g., exists and is not the admin)
        user_to_delete = User.query.get(user_id_to_delete)
        user_to_delete_files = File.query.filter_by(user_id=user_id_to_delete)
        if user_to_delete and user_to_delete.role != "admin":
            db.session.delete(user_to_delete)
            db.session.commit()
            #db.session.delete(user_to_delete_files)
            #db.session.commit
            #user_folder = os.path.join("uploads", user_to_delete.username)
            #os.rmdir(user_folder, exist_ok=True)
            

            # Redirect to the same page after user deletion
            return redirect(url_for("web.manage_users"))

    # Retrieve a list of all users from the database
    users = User.query.all()

    return render_template("users.html", users=users)

@web.route("/files", methods=["GET"])
@admin_required
def files():
    files = File.query.all()

    return render_template("files.html", files=files)



@web.route("/viewBackups", methods=["GET"])
@admin_required
def viewBackups():
    backups = Backups.query.all()

    return render_template("backups.html", files=backups)



# TO-DO


## generate report

@web.route("/report", methods=["GET","POST"])
@admin_required
def generate_report():

    if request.method == "GET":
        return render_template("report.html")
    elif request.method == "POST":
        if request.form.get("selected_type") == "users":
            users = User.query.all()
            pdf_data = generate_users_report(users)
            filename = datetime.datetime.now().isoformat() + '.pdf'
            response = make_response(pdf_data)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'inline; filename=users_report.pdf'        
            return response
        elif request.form.get("selected_type") == "files":
            files = File.query.all()
            pdf_data = generate_files_report(files)
            filename = datetime.datetime.now().isoformat() + '.pdf'
            response = make_response(pdf_data)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'inline; filename=files_report.pdf'        
            return response
        elif request.form.get("selected_type") == "backups":
            backups = Backups.query.all()
            pdf_data = generate_backups_report(backups)
            filename = datetime.datetime.now().isoformat() + '.pdf'
            response = make_response(pdf_data)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'inline; filename=backups_report.pdf'        
            return response


##backup

## works on linux only
@web.route("/backup",methods=["GET"])
@admin_required
def create_backup():
    # Define the backup directory using the current date and time in ISO format
    backup_dir_name = datetime.datetime.now().isoformat()
    backup_dir = os.path.join('backups', backup_dir_name)
    os.makedirs(backup_dir, exist_ok=True)

    new_backup = Backups(file_name=backup_dir_name , file_path=backup_dir,date_created=datetime.datetime.now())
    db.session.add(new_backup)
    db.session.commit()


    #copy files
    cmd= f"mkdir {backup_dir}/files && cp -r uploads/* {backup_dir}/files"
    subprocess.Popen(cmd, shell=True)
    #copy db
    cmd2= f"mkdir {backup_dir}/db && cp -r instance/* {backup_dir}/db"
    subprocess.Popen(cmd2, shell=True)

    #copy logs
    cmd3= f"mkdir {backup_dir}/logs && cp -r logs/* {backup_dir}/logs"
    subprocess.Popen(cmd3, shell=True)

    subprocess.Popen(cmd2,shell=True)
    



    return render_template("admin.html",username=session['username'],message=f"Created backup {backup_dir_name} succesfully")
        

@api.route('/verify', methods=['POST'])
def verify_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        # Create temp directory if it doesn't exist
        temp_dir = 'temp'
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save file temporarily
        temp_path = os.path.join(temp_dir, file.filename)
        file.save(temp_path)
        
        try:
            # Calculate file hash
            file_hash = calculate_sha256(temp_path)
            
            # Get contract details from environment
            contract_address = os.getenv('CONTRACT_ADDRESS')
            contract_abi = '[{"inputs": [], "stateMutability": "nonpayable", "type": "constructor"}, {"anonymous": false, "inputs": [{"indexed": true, "internalType": "string", "name": "certificateId", "type": "string"}, {"indexed": false, "internalType": "string", "name": "ipfsHash", "type": "string"}, {"indexed": true, "internalType": "address", "name": "issuer", "type": "address"}], "name": "CertificateIssued", "type": "event"}, {"inputs": [{"internalType": "string", "name": "certificateId", "type": "string"}], "name": "getIssuer", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "certificateId", "type": "string"}, {"internalType": "string", "name": "ipfsHash", "type": "string"}], "name": "issueCertificate", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [], "name": "owner", "outputs": [{"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"internalType": "string", "name": "certificateId", "type": "string"}], "name": "verifyCertificate", "outputs": [{"internalType": "string", "name": "", "type": "string"}], "stateMutability": "view", "type": "function"}]'
            
            # Look up the file in our database to get the file name and certificate ID
            db_file = File.query.filter_by(file_name=file.filename).first()
            if not db_file:
                return jsonify({
                    'verified': False,
                    'message': 'File not found in our records'
                }), 404
            
            # Extract certificate ID from the blockchain transaction hash
            # The certificate ID is stored in the format: filename_timestamp
            certificate_id = db_file.certificate_id if hasattr(db_file, 'certificate_id') else None
            
            if not certificate_id:
                return jsonify({
                    'verified': False,
                    'message': 'Certificate ID not found in database'
                }), 404
            
            # Get the stored hash from blockchain using the correct certificate ID
            stored_hash = blockchain_utils.get_stored_hash(
                contract_address,
                contract_abi,
                certificate_id
            )
            
            if not stored_hash:
                return jsonify({
                    'verified': False,
                    'message': 'File hash not found in blockchain'
                }), 404
            
            # Compare hashes
            is_verified = stored_hash.lower() == file_hash.lower()
            
            return jsonify({
                'verified': is_verified,
                'message': 'File verified successfully' if is_verified else 'File verification failed',
                'details': {
                    'file_name': file.filename,
                    'calculated_hash': file_hash,
                    'stored_hash': stored_hash,
                    'certificate_id': certificate_id
                }
            })
            
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        return jsonify({
            'verified': False,
            'message': f'Verification error: {str(e)}'
        }), 500

@web.route("/verify")
@login_required
def verify():
    return render_template("verify.html")



