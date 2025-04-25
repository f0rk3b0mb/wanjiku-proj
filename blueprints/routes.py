from flask import Blueprint, render_template, redirect, url_for, request, session ,jsonify , make_response, current_app as app
import os
from database import db, bcrypt , User , File , Backups, Role 
from utils import calculate_sha256, encrypt_file , decrypt_file , login_required , generate_otp, admin_required
import datetime
from  report_generator import generate_certificate_verification_report, generate_file_integrity_report, generate_backup_health_report, generate_verification_report
import subprocess
from blockchain_utils import BlockchainUtils
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

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
    allowed_endpoints = ['web.login', 'web.register', 'web.index' , 'web.faq', 'web.verify']  # Add more endpoints as needed

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
                    if user.role_id == 1:
                        return redirect(url_for("web.admin"))
                    else:
                        return redirect(url_for("web.dashboard"))
                    #if otp_code:
                    #    return redirect(url_for("web.dashboard"))
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
    
    # Check file extension
    allowed_extensions = {'pdf', 'docx'}
    file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_extension not in allowed_extensions:
        return jsonify({'error': 'Only PDF and DOCX files are allowed'}), 400
    
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
            contract_abi = os.getenv('CONTRACT_ABI')  # Add your contract ABI here
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
                target_dir = os.path.join('uploads', session['username'])
            
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
            
            return render_template("upload.html", success="File uploaded successfully") 
            
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

#@api.route("/deleteFiles", methods=["POST"])
#@login_required
#def delete_file():
#    file_name = request.form.get("file_name")
#
#    if file_name:
#        file_path = os.path.join("uploads", session["username"], file_name)
#
#        if os.path.exists(file_path):
#            # Mark the file as pending for deletion in the database
#            file = File.query.filter_by(file_name=file_name).first()
#
#            if file:
#                file.is_pending_deletion = "True"
#                db.session.commit()
#                return "File will be archived"
#            else:
#                return "File not found or already archived"



@api.route('/download/<file_name>')
@login_required
def download_file(file_name):
        
        for i in ["/","../","\\","..\\"]:
            if i in file_name:
                return "illegal characters in filename"
        
        file_path = os.path.join('uploads',session["username"], file_name)

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
        #user_to_delete_files = File.query.filter_by(user_id=user_id_to_delete)
        if user_to_delete and user_to_delete.role_name != "admin":
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



#@api.route("/archived_files", methods=["GET"])
#@admin_required
#def get_archived_requests():
#    # Find all files that are pending deletion
#    pending_deletion_files = File.query.filter_by(is_pending_deletion="True").all()
#    
#    pending_files_details = []
#
#    for file in pending_deletion_files:
#        file_detail = {
#            'file_id': file.id,
#            'filename': file.file_name,
#            'owner': file.user_id,
#            'permission': None
#        }
#        if file.permission_level:
#            perm = Permission.query.get(file.permission_level)
#            if perm:
#                file_detail['permission'] = perm.permission
#        pending_files_details.append(file_detail)
#    
#    return jsonify(pending_files_details)


#@api.route("/restore_file/<int:file_id>", methods=["POST"])
#@admin_required
#def restore_file(file_id):
#    # Find the file by name
#    file = File.query.filter_by(id=file_id).first()
#
#    if file and file.is_pending_deletion:
#        file.is_pending_deletion = "False"
#        db.session.commit()
#        return jsonify({"message": "File Restored to system"})
#    else:
#        return jsonify({"message": "File not found or not archived."})

#@web.route("/viewBackups", methods=["GET"])
#@admin_required
#def viewBackups():
#    backups = Backups.query.all()
#
#    return render_template("backups.html", files=backups)



# TO-DO


## generate report


##backup

## works on linux only
#@web.route("/backup",methods=["GET"])
#@admin_required
#def create_backup():
#    # Define the backup directory using the current date and time in ISO format
#    backup_dir_name = datetime.datetime.now().isoformat()
#    backup_dir = os.path.join('backups', backup_dir_name)
#    os.makedirs(backup_dir, exist_ok=True)
#
#    new_backup = Backups(file_name=backup_dir_name , file_path=backup_dir,date_created=datetime.datetime.now())
#    db.session.add(new_backup)
#    db.session.commit()
#
#
#    #copy files
#    cmd= f"mkdir {backup_dir}/files && cp -r uploads/* {backup_dir}/files"
#    subprocess.Popen(cmd, shell=True)
#    #copy db
#    cmd2= f"mkdir {backup_dir}/db && cp -r instance/* {backup_dir}/db"
#    subprocess.Popen(cmd2, shell=True)
#
#    #copy logs
#    cmd3= f"mkdir {backup_dir}/logs && cp -r logs/* {backup_dir}/logs"
#    subprocess.Popen(cmd3, shell=True)
#
#    subprocess.Popen(cmd2,shell=True)
#    
#
#
#
#    return render_template("admin.html",username=session['username'],message=f"Created backup {backup_dir_name} succesfully")
        

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
            contract_abi = os.getenv('CONTRACT_ABI')
            
            # Look up the file in our database to get the file name and certificate ID
            db_file = File.query.filter_by(ipfs_hash=file_hash).first()
            if not db_file:
                verification_result = {
                    'verified': False,
                    'message': 'File not found in our records',
                    'details': {
                        'file_name': file.filename,
                        'calculated_hash': file_hash,
                        'stored_hash': 'N/A',
                        'certificate_id': 'N/A'
                    }
                }
                report_data = generate_verification_report(verification_result)
                return jsonify({
                    'verification_result': verification_result,
                    'report_filename': report_data['filename']
                })
            
            # Extract certificate ID from the blockchain transaction hash
            certificate_id = db_file.certificate_id if hasattr(db_file, 'certificate_id') else None
            
            if not certificate_id:
                verification_result = {
                    'verified': False,
                    'message': 'Certificate ID not found in database',
                    'details': {
                        'file_name': file.filename,
                        'calculated_hash': file_hash,
                        'stored_hash': 'N/A',
                        'certificate_id': 'N/A'
                    }
                }
                report_data = generate_verification_report(verification_result)
                return jsonify({
                    'verification_result': verification_result,
                    'report_filename': report_data['filename']
                })
            
            # Get the stored hash from blockchain using the correct certificate ID
            stored_hash = blockchain_utils.get_stored_hash(
                contract_address,
                contract_abi,
                certificate_id
            )
            
            if not stored_hash:
                verification_result = {
                    'verified': False,
                    'message': 'File hash not found in blockchain',
                    'details': {
                        'file_name': file.filename,
                        'calculated_hash': file_hash,
                        'stored_hash': 'N/A',
                        'certificate_id': certificate_id
                    }
                }
                report_data = generate_verification_report(verification_result)
                return jsonify({
                    'verification_result': verification_result,
                    'report_filename': report_data['filename']
                })
            
            # Compare hashes
            is_verified = stored_hash.lower() == file_hash.lower()
            
            verification_result = {
                'verified': is_verified,
                'message': 'File verified successfully' if is_verified else 'File verification failed',
                'details': {
                    'file_name': file.filename,
                    'calculated_hash': file_hash,
                    'stored_hash': stored_hash,
                    'certificate_id': certificate_id
                }
            }
            
            # Generate the verification report
            report_data = generate_verification_report(verification_result)
            
            # Return verification result and report filename
            return jsonify({
                'verification_result': verification_result,
                'report_filename': report_data['filename']
            })
            
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        verification_result = {
            'verified': False,
            'message': f'Verification error: {str(e)}',
            'details': {
                'file_name': file.filename,
                'calculated_hash': 'N/A',
                'stored_hash': 'N/A',
                'certificate_id': 'N/A'
            }
        }
        report_data = generate_verification_report(verification_result)
        return jsonify({
            'verification_result': verification_result,
            'report_filename': report_data['filename']
        })

@api.route('/download_report/<filename>')
@login_required
def download_report(filename):
    # Ensure the filename is safe
    if any(char in filename for char in ['/', '\\', '..']):
        return "Invalid filename", 400
        
    report_path = os.path.join('reports', filename)
    
    if not os.path.exists(report_path):
        return "Report not found", 404
        
    try:
        with open(report_path, 'rb') as f:
            pdf_data = f.read()
            
        response = make_response(pdf_data)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename={filename}'
        return response
    except Exception as e:
        return str(e), 500

@web.route("/verify")
def verify():
    return render_template("verify.html")

@web.route("/generate_certificate")
@login_required
def generate_certificate():
    return render_template("generate_certificate.html", username=session['username'])

@api.route('/generate_certificate', methods=['POST'])
@login_required
def generate_certificate_api():
    try:
        # Get form data
        student_name = request.form.get('studentName')
        student_id = request.form.get('studentId')
        degree = request.form.get('degree')
        major = request.form.get('major')
        graduation_date = request.form.get('graduationDate')
        issuer_name = request.form.get('issuerName')
        issuer_title = request.form.get('issuerTitle')
        institution_name = request.form.get('institutionName')
        certificate_id = request.form.get('certificateId')

        # Validate required fields
        required_fields = ['studentName', 'studentId', 'degree', 'major', 'graduationDate', 
                         'issuerName', 'issuerTitle', 'institutionName', 'certificateId']
        for field in required_fields:
            if not request.form.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        # Create certificate data
        certificate_data = {
            'student_name': student_name,
            'student_id': student_id,
            'degree': degree,
            'major': major,
            'graduation_date': graduation_date,
            'issuer_name': issuer_name,
            'issuer_title': issuer_title,
            'institution_name': institution_name,
            'certificate_id': certificate_id
        }

        # Create certificate file and get its hash
        certificate_file, file_hash = create_certificate_file(certificate_data)
        if not certificate_file:
            return jsonify({'error': 'Failed to create certificate file'}), 500

        # Get contract details from environment
        contract_address = os.getenv('CONTRACT_ADDRESS')
        contract_abi = os.getenv('CONTRACT_ABI')
        account_address = os.getenv('ACCOUNT_ADDRESS')
        private_key = os.getenv('PRIVATE_KEY')

        # Store certificate in blockchain using the file hash
        success, tx_hash = blockchain_utils.store_file_hash(
            contract_address,
            contract_abi,
            file_hash,
            account_address,
            private_key,
            certificate_id
        )

        if not success:
            return jsonify({'error': 'Failed to store certificate in blockchain'}), 500

        # Save certificate file to database
        file = File(
            file_name=f"{student_name}_{certificate_id}.pdf",
            file_path=certificate_file,
            ipfs_hash=file_hash,
            blockchain_tx=tx_hash,
            upload_date=datetime.datetime.now(),
            file_size=os.path.getsize(certificate_file),
            owner_id=session['user_id'],
            is_archived=False,
            certificate_id=certificate_id
        )
        db.session.add(file)
        db.session.commit()

        return jsonify({
            'message': 'Certificate generated successfully',
            'certificate_id': certificate_id,
            'file_name': file.file_name
        })

    except Exception as e:
        print(f"Error generating certificate: {str(e)}")
        return jsonify({'error': f'An error occurred while generating the certificate: {str(e)}'}), 500

def create_certificate_file(certificate_data):
    try:
        # Create a temporary directory if it doesn't exist
        temp_dir = os.path.join('uploads', session['username'])
        os.makedirs(temp_dir, exist_ok=True)

        # Generate a unique filename
        filename = f"{certificate_data['student_name']}_{certificate_data['certificate_id']}.pdf"
        filepath = os.path.join(temp_dir, filename)

        # Create PDF using reportlab
        c = canvas.Canvas(filepath, pagesize=letter)
        
        # Add certificate content
        c.setFont("Helvetica-Bold", 24)
        c.drawCentredString(400, 750, "Certificate of Completion")
        
        c.setFont("Helvetica-Bold", 18)
        c.drawCentredString(400, 700, certificate_data['institution_name'])
        
        c.setFont("Helvetica", 14)
        c.drawCentredString(400, 650, "This is to certify that")
        
        c.setFont("Helvetica-Bold", 16)
        c.drawCentredString(400, 600, certificate_data['student_name'])
        
        c.setFont("Helvetica", 14)
        c.drawCentredString(400, 550, "has successfully completed the requirements for the degree of")
        
        c.setFont("Helvetica-Bold", 16)
        c.drawCentredString(400, 500, f"{certificate_data['degree']} in {certificate_data['major']}")
        
        # Format graduation date
        graduation_date = datetime.datetime.strptime(certificate_data['graduation_date'], '%Y-%m-%d')
        formatted_date = graduation_date.strftime('%B %d, %Y')
        c.drawCentredString(400, 450, f"on {formatted_date}")
        
        # Add certificate details (centered)
        c.setFont("Helvetica", 12)
        c.drawCentredString(400, 250, f"Certificate ID: {certificate_data['certificate_id']}")
        c.drawCentredString(400, 230, f"Student ID: {certificate_data['student_id']}")
        
        # Add issuer details (centered)
        c.drawCentredString(400, 200, certificate_data['issuer_name'])
        c.drawCentredString(400, 180, certificate_data['issuer_title'])
        
        # Save the PDF
        c.save()

        file_hash = calculate_sha256(filepath)
        
        # Calculate the hash of the generated file
        success, message = encrypt_file(filepath)
        if not success:
            return None, None
        
        
        
        return filepath, file_hash
    except Exception as e:
        print(f"Error creating certificate file: {str(e)}")
        return None, None



