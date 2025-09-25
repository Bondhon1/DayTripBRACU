from flask import Flask, redirect, render_template, request, make_response, session, abort, jsonify, url_for, flash
import secrets
from functools import wraps
import firebase_admin
from firebase_admin import credentials, firestore, auth
from datetime import timedelta, datetime
import os
import json
from dotenv import load_dotenv
from flask import Flask, send_file
from io import BytesIO
from openpyxl import Workbook
import math




load_dotenv()



app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configure session cookie settings
app.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Adjust session expiration as needed
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Can be 'Strict', 'Lax', or 'None'


service_account_info = os.getenv("FIREBASE_SERVICE_ACCOUNT")
cred_dict = json.loads(service_account_info)  # convert JSON string to dict

cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()



########################################
""" Authentication and Authorization """

# Decorator for routes that require authentication
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if 'user' not in session:
            return redirect(url_for('login'))
        
        else:
            return f(*args, **kwargs)
        
    return decorated_function


@app.route('/auth', methods=['POST'])
def authorize():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return "Unauthorized", 401

    token = token[7:]

    try:
        decoded_token = auth.verify_id_token(token, check_revoked=True, clock_skew_seconds=60)
        uid = decoded_token['uid']

        # Check if this UID exists in Firestore
        user_ref = db.collection("Users").document(uid).get()
        if not user_ref.exists:
            return "Unauthorized - User not registered", 401
        email_verified = decoded_token.get("email_verified", False)
        if not email_verified:
            return "Unauthorized - email not verified", 403


        session['user'] = decoded_token
        return redirect(url_for('dashboard'))

    except Exception as e:
        print("Auth error:", e)
        return "Unauthorized", 401

@app.route("/firebase-config")
def firebase_config():
    return jsonify({
        "apiKey": os.getenv("FIREBASE_API_KEY"),
        "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
        "projectId": os.getenv("FIREBASE_PROJECT_ID"),
        "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
        "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
        "appId": os.getenv("FIREBASE_APP_ID"),
        "measurementId": os.getenv("FIREBASE_MEASUREMENT_ID"),
    })

#####################
""" Public Routes """

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html')

@app.route('/signup')
def signup():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    else:
        return render_template('signup.html')

@app.route('/store-user', methods=['POST'])
def store_user():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return "Unauthorized", 401

    token = token[7:]
    try:
        decoded_token = auth.verify_id_token(token, check_revoked=True, clock_skew_seconds=60)
        uid = decoded_token['uid']
        email = decoded_token.get("email")

        # Restrict to g.bracu.ac.bd
        if not email.endswith("@g.bracu.ac.bd"):
            return jsonify({"message": "Only BRAC University emails are allowed"}), 403

        user_ref = db.collection("Users").document(uid)
        if user_ref.get().exists:
            return jsonify({"message": "User already exists"}), 200

        user_ref.set({
            "uid": uid,
            "email": email,
            "createdAt": request.json.get("createdAt"),
            "role": "user",
            "verified": decoded_token.get("email_verified", False)
        })

        return jsonify({"message": "User stored successfully"}), 200

    except Exception as e:
        print("Error storing user:", e)
        return "Unauthorized", 401


@app.route('/reset-password')
def reset_password():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    else:
        return render_template('forgot_password.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/logout')
def logout():
    session.pop('user', None)  # Remove the user from session
    response = make_response(redirect(url_for('login')))
    response.set_cookie('session', '', expires=0)  # Optionally clear the session cookie
    return response


##############################################
""" Private Routes (Require authorization) """



@app.route('/dashboard')
@auth_required
def dashboard():
    user = session.get('user')
    if not user:
        return redirect(url_for("login"))

    email = user.get('email')
    uid = user.get('uid')

    # Get user info
    user_ref = db.collection("Users").document(uid).get()
    if user_ref.exists:
        user_data = user_ref.to_dict()
    else:
        user_data = {}

    # Get payment info
    payment_ref = db.collection("Payments").document(uid).get()
    if payment_ref.exists:
        payment_data = payment_ref.to_dict()
    else:
        payment_data = None

    # Get admin settings (deadlines, receiver numbers etc.)
    settings_ref = db.collection("Settings").document("config").get()
    if settings_ref.exists:
        settings = settings_ref.to_dict()
        # Fix date formats here before passing to template
        settings["payment_deadline"] = settings.get("payment_deadline")
        settings["profile_update_deadline"] = settings.get("profile_update_deadline")
    else:
        settings = {}

    return render_template(
        "dashboard.html",
        email=email,
        user_data=user_data,
        payment=payment_data,
        settings=settings
    )


@app.route('/profile', methods=['GET', 'POST'])
@auth_required
def profile():
    user = session.get('user')
    uid = user.get('uid')

    user_ref = db.collection("Users").document(uid)
    settings_ref = db.collection("Settings").document("config")
    settings = settings_ref.get().to_dict() or {}

    payment_ref = db.collection("Payments").document(uid).get()
    payment = payment_ref.to_dict() if payment_ref.exists else None

    paid_full_amount = False
    if payment:
        amount = payment.get('amount', 0)
        status = payment.get('status', '')
        if (str(amount) == '2000' or amount == 2000) and status == 'paid':
            paid_full_amount = True

    if request.method == 'POST':
        profile_deadline = settings.get("profile_update_deadline")
        from datetime import datetime
        if profile_deadline and datetime.fromisoformat(profile_deadline) < datetime.now():
            flash("Profile update deadline has passed.", "error")
            return redirect(url_for('profile'))

        # Collect form data
        data_to_update = {
            "full_name": request.form.get('full_name'),
            "student_id": request.form.get('student_id'),
            "contact_number": request.form.get('contact_number'),
            "joining_semester": request.form.get('joining_semester'),
            "completed_credit": request.form.get('completed_credit'),
            "guardian_contact": request.form.get('guardian_contact'),
            "blood_group": request.form.get('blood_group')
        }

        # Update T-shirt size only if the field is visible
        t_shirt_size = request.form.get('t_shirt_size')
        if paid_full_amount or session.get('user', {}).get('role') == 'admin':
            data_to_update['t_shirt_size'] = t_shirt_size

        user_ref.update(data_to_update)
        flash("Profile updated successfully.", "success")
        return redirect(url_for('profile'))

    user_data = user_ref.get().to_dict() or {}
    return render_template(
        'profile.html',
        user=user_data,
        profile_update_deadline=settings.get("profile_update_deadline"),
        paid_full_amount=paid_full_amount
    )



@app.route('/payment')
@auth_required
def payment():
    user = session.get('user')
    uid = user["uid"]

    # Fetch user data
    user_ref = db.collection("Users").document(uid)
    user_doc = user_ref.get()
    user_data = user_doc.to_dict() if user_doc.exists else {}

    required_fields = ["full_name", "student_id", "contact_number", "blood_group"]
    missing_info = any(not user_data.get(f) for f in required_fields)
    not_verified = not user_data.get("verified", False)

    if missing_info or not_verified:
        flash("Please complete your profile and get verified before making a payment.", "warning")
        return redirect(url_for("profile"))

    # Fetch settings
    settings_doc = db.collection("Settings").document("config").get()
    settings = settings_doc.to_dict() if settings_doc.exists else {}

    payment_deadline = settings.get("payment_deadline")
    fixed_deadline = None
    deadline_over = False
    if payment_deadline:
        try:
            fixed_deadline = payment_deadline
            if fixed_deadline:
                deadline_date = datetime.fromisoformat(fixed_deadline).date()
                if datetime.utcnow().date() > deadline_date:
                    deadline_over = True
        except Exception as e:
            app.logger.error(f"Invalid deadline format: {payment_deadline} -> {e}")

    payment_ref = db.collection("Payments").document(uid).get()
    payment = payment_ref.to_dict() if payment_ref.exists else None
    
    reg_type = "pre"  # default
    if payment:
        status = payment.get("status")
        amount = payment.get('amount')
        if amount == 500 or amount == '500':
            reg_type = "remaining"
        elif status == "paid":
            reg_type = "done"

    return render_template(
        'payment.html',
        user=user_data,
        reg_type=reg_type,
        payment=payment,
        deadline_over=deadline_over,
        fixed_deadline=fixed_deadline,
        settings=settings
    )

@app.route('/submit-payment', methods=['POST'])
@auth_required
def submit_payment():
    user = session.get('user')
    uid = user["uid"]
    
    # Fetch student_id from Users collection because it's not in session
    user_doc = db.collection("Users").document(uid).get()
    student_id = user_doc.to_dict().get('student_id') if user_doc.exists else None

    reg_type = request.form.get("reg_type")
    method = request.form.get("method")
    trx_id = request.form.get("trx_id")
    number = request.form.get("number")
    receiver_number = request.form.get("receiver_number")
    date = request.form.get("date")
    time = request.form.get("time")

    payment_ref = db.collection("Payments").document(uid)

    base_amount = 0
    charge = 0
    status = ""

    if reg_type == 'pre':
        base_amount = 500
        charge = 10 if method == 'Bkash' else 5
        status = 'pending'
    elif reg_type == 'full':
        base_amount = 2000
        charge = 38 if method == 'Bkash' else 18
        status = 'pending'
    elif reg_type == 'remaining':
        base_amount = 2000  # Total amount stored for pre+remaining
        charge = 28 if method == 'Bkash' else 13
        status = 'pending'
    else:
        flash("Invalid registration type", "error")
        return redirect(url_for('payment'))

    def append_csv(field, new_value):
        existing_val = existing.get(field) if existing else None
        if existing_val:
            values = [v.strip() for v in existing_val.split(",")]
            if new_value not in values:
                return existing_val + "," + new_value
            else:
                return existing_val
        else:
            return new_value

    data = {
        "student_id": student_id,
        "email": user.get("email"),
        "status": status
    }

    doc = payment_ref.get()
    existing = doc.to_dict() if doc.exists else None

    if existing:
        if reg_type == 'remaining':
            data['amount'] = 2000

            if 'charge' in existing:
                charges = [c.strip() for c in existing['charge'].split(",")]
                if str(charge) not in charges:
                    data['charge'] = existing['charge'] + "," + str(charge)
                else:
                    data['charge'] = existing['charge']
            else:
                data['charge'] = str(charge)

            # Append csv fields including 'method'
            for key, val in {
                "method": method,
                "trx_id": trx_id,
                "number": number,
                "receiver_number": receiver_number,
                "date": date,
                "time": time,
            }.items():
                data[key] = append_csv(key, val)

        elif reg_type == 'pre' and status == 'pending':
            data['amount'] = base_amount
            data['charge'] = str(charge)
            for key, val in {
                "method": method,
                "trx_id": trx_id,
                "number": number,
                "receiver_number": receiver_number,
                "date": date,
                "time": time,
            }.items():
                data[key] = append_csv(key, val)

        else:
            data['amount'] = base_amount
            data['charge'] = str(charge)
            for key, val in {
                "method": method,
                "trx_id": trx_id,
                "number": number,
                "receiver_number": receiver_number,
                "date": date,
                "time": time,
            }.items():
                data[key] = val
    else:
        data['amount'] = 2000 if reg_type == 'remaining' else base_amount
        data['charge'] = str(charge)
        for key, val in {
            "method": method,
            "trx_id": trx_id,
            "number": number,
            "receiver_number": receiver_number,
            "date": date,
            "time": time,
        }.items():
            data[key] = val

    payment_ref.set(data, merge=True)

    flash(f"{reg_type.capitalize()} payment submitted successfully", "success")
    return redirect(url_for('dashboard'))

#################################################
""" Admin Routes """

@app.route('/admin_login')
def admin_login():
    if 'admin' in session:
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template('admin_login.html')

@app.route('/admin-auth', methods=['POST'])
def admin_auth():
    token = request.headers.get('Authorization')
    if not token or not token.startswith('Bearer '):
        return "Unauthorized", 401

    token = token[7:]
    try:
        decoded_token = auth.verify_id_token(token, check_revoked=True, clock_skew_seconds=60)
        uid = decoded_token['uid']

        user_ref = db.collection("Users").document(uid).get()
        if not user_ref.exists:
            return "Unauthorized - User not registered", 401

        user_data = user_ref.to_dict()

        # Check if user is admin
        if user_data.get('role') != 'admin':
            return "Forbidden - Not an admin", 403

        session['admin'] = user_data
        return "Authorized", 200

    except Exception as e:
        app.logger.error(f"Admin auth error: {e}")
        return "Unauthorized", 401

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session or session.get('admin', {}).get('role') != 'admin':
            abort(403)

        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin-dashboard')
@admin_required
def admin_dashboard():
    # Get settings from Firestore
    settings_ref = db.collection("Settings").document("config").get()
    settings = settings_ref.to_dict() if settings_ref.exists else {}

    # Your analytics code (users + payments)
    needed_amount = 800 * 2000
    total_users = len(db.collection("Users").get())
    payments = db.collection("Payments").stream()

    total_collection, partial_paid, full_paid = 0, 0, 0
    for doc in payments:
        amount = doc.to_dict().get("amount", 0)
        total_collection += amount
        if amount == 500:
            partial_paid += 1
        elif amount == 2000:
            full_paid += 1

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        partial_paid=partial_paid,
        full_paid=full_paid,
        total_collection=total_collection,
        needed_amount=needed_amount,
        settings=settings or {}
    )

@app.route('/update_settings', methods=['POST'])
@admin_required
def update_settings():
    payment_deadline = request.form.get("payment_deadline")
    profile_update_deadline = request.form.get("profile_update_deadline")
    bkash_number = request.form.get("bkash_number")
    nagad_number = request.form.get("nagad_number")

    admin_email = session.get("admin", {}).get("email")  # get admin email from session
    updated_at = datetime.utcnow().isoformat()          # store UTC timestamp

    db.collection("Settings").document("config").set({
        "payment_deadline": payment_deadline,
        "profile_update_deadline": profile_update_deadline,
        "bkash_number": bkash_number,
        "nagad_number": nagad_number,
        "admin_email": admin_email,
        "updated_at": updated_at
    })

    flash("Settings updated successfully!", "success")
    return redirect(url_for("admin_dashboard"))

# Admin Dashboard
@app.route('/admin-dashboard-page')
@admin_required
def admin_dashboard_page():
    admin = session.get('admin')

    uid = admin.get('uid')

    # Fetch settings
    settings_doc = db.collection("Settings").document("config").get()
    settings = settings_doc.to_dict() if settings_doc.exists else {}

    # Analytics
    needed_amount = 800 * 2000
    total_users = len(db.collection("Users").get())
    payments = db.collection("Payments").stream()

    total_collection, partial_paid, full_paid = 0, 0, 0
    for doc in payments:
        amount = doc.to_dict().get("amount", 0)
        total_collection += amount
        if amount == 500:
            partial_paid += 1
        elif amount == 2000:
            full_paid += 1

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        partial_paid=partial_paid,
        full_paid=full_paid,
        total_collection=total_collection,
        needed_amount=needed_amount,
        settings=settings
    )

# Admin Profile
@app.route('/admin-profile', methods=['GET', 'POST'])
@admin_required
def admin_profile():
    admin = session.get('admin')
    uid = admin.get('uid')
    user_ref = db.collection("Users").document(uid)
    settings_ref = db.collection("Settings").document("config")
    settings = settings_ref.get().to_dict() or {}

    if request.method == 'POST':
        profile_deadline = settings.get("profile_update_deadline")
        from datetime import datetime
        if profile_deadline and datetime.fromisoformat(profile_deadline) < datetime.now():
            flash("Profile update deadline has passed.", "error")
            return redirect(url_for('admin_profile'))

        user_ref.update({
            "full_name": request.form.get('full_name'),
            "student_id": request.form.get('student_id'),
            "contact_number": request.form.get('contact_number'),
            "joining_semester": request.form.get('joining_semester'),
            "completed_credit": request.form.get('completed_credit'),
            "guardian_contact": request.form.get('guardian_contact'),
            "blood_group": request.form.get('blood_group')
        })
        flash("Profile updated successfully.", "success")
        return redirect(url_for('admin_profile'))

    user_data = user_ref.get().to_dict()
    return render_template(
        'profile.html',
        user=user_data,
        profile_update_deadline=settings.get("profile_update_deadline")
    )

# Admin Payment
@app.route('/admin-payment')
@admin_required
def admin_payment():
    admin = session.get('admin')
    uid = admin.get('uid')

    # Fetch user data
    user_ref = db.collection("Users").document(uid)
    user_doc = user_ref.get()
    user_data = user_doc.to_dict() if user_doc.exists else {}

    required_fields = ["full_name", "student_id", "contact_number", "blood_group"]
    missing_info = any(not user_data.get(f) for f in required_fields)
    not_verified = not user_data.get("verified", False)

    if missing_info or not_verified:
        flash("Please complete your profile and get verified before making a payment.", "warning")
        return redirect(url_for("admin_profile"))

    # Fetch settings
    settings_doc = db.collection("Settings").document("config").get()
    settings = settings_doc.to_dict() if settings_doc.exists else {}

    payment_deadline = settings.get("payment_deadline")
    fixed_deadline = None
    deadline_over = False
    from datetime import datetime
    if payment_deadline:
        try:
            fixed_deadline = payment_deadline
            deadline_date = datetime.fromisoformat(fixed_deadline).date()
            if datetime.utcnow().date() > deadline_date:
                deadline_over = True
        except Exception as e:
            app.logger.error(f"Invalid deadline format: {payment_deadline} -> {e}")

    payment_ref = db.collection("Payments").document(uid).get()
    payment = payment_ref.to_dict() if payment_ref.exists else None

    reg_type = "pre"  # default
    if payment:
        status = payment.get("status")
        amount = payment.get('amount')
        if amount == 500 or amount == '500':
            reg_type = "remaining"
        elif status == "paid":
            reg_type = "done"

    return render_template(
        'payment.html',
        user=user_data,
        reg_type=reg_type,
        payment=payment,
        deadline_over=deadline_over,
        fixed_deadline=fixed_deadline,
        settings=settings
    )

@app.route('/add_admin', methods=['GET'])
@admin_required
def add_admin():
    return render_template('add_admin.html')

@app.route('/search_users')
@admin_required
def search_users():
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify([])

    users_ref = db.collection("Users")
    all_users = users_ref.stream()

    results = []
    for doc in all_users:
        data = doc.to_dict()
        email = data.get('email', '').lower()
        student_id = str(data.get('student_id', '')).lower()
        if query in email or query in student_id:
            results.append({
                'uid': doc.id,
                'full_name': data.get('full_name', ''),
                'email': data.get('email', ''),
                'student_id': data.get('student_id', '')
            })
    return jsonify(results)

@app.route('/promote_admin', methods=['POST'])
@admin_required
def promote_admin():
    uid = request.json.get('uid')
    if not uid:
        return jsonify({"error": "Missing UID"}), 400

    user_ref = db.collection("Users").document(uid)
    if not user_ref.get().exists:
        return jsonify({"error": "User not found"}), 404

    user_ref.update({"role": "admin"})
    return jsonify({"success": True})

@app.route('/view_users')
@admin_required
def view_users():
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = 50
    start = (page - 1) * per_page
    end = start + per_page

    # Sorting
    sort_by = request.args.get('sort_by', 'createdAt')  # 'createdAt' or 'email'
    sort_order = request.args.get('sort_order', 'desc')  # 'asc' or 'desc'

    # Search filters
    search_name = request.args.get('full_name', '').strip().lower()
    search_email = request.args.get('email', '').strip().lower()
    search_student = request.args.get('student_id', '').strip()
    search_date = request.args.get('createdAt', '').strip()  # YYYY-MM-DD

    # Fetch all users
    users_docs = db.collection("Users").stream()
    users = []

    for doc in users_docs:
        u = doc.to_dict()

        # Handle missing fields gracefully
        u.setdefault('full_name', '')
        u.setdefault('student_id', '')
        u.setdefault('email', '')
        u.setdefault('createdAt', '')

        # Filtering
        if search_name and search_name not in u['full_name'].lower():
            continue
        if search_email and search_email not in u['email'].lower():
            continue
        if search_student and search_student not in u['student_id']:
            continue
        if search_date:
            try:
                date_obj = datetime.fromisoformat(u['createdAt'].replace("Z",""))
                if search_date != date_obj.strftime("%Y-%m-%d"):
                    continue
            except:
                continue

        users.append(u)

    # Sorting
    if sort_by == 'createdAt':
        users.sort(key=lambda x: x.get('createdAt') or '', reverse=(sort_order=='desc'))
    elif sort_by == 'email':
        users.sort(key=lambda x: x.get('email','').lower(), reverse=(sort_order=='desc'))

    # Pagination slice
    total_users = len(users)
    total_pages = (total_users + per_page - 1) // per_page
    users_paginated = users[start:end]

    return render_template(
        'view_users.html',
        users=users_paginated,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        sort_order=sort_order,
        search_name=search_name,
        search_email=search_email,
        search_student=search_student,
        search_date=search_date
    )

@app.route("/download_users_excel")
def download_users_excel():
    users_ref = db.collection("Users")
    users_docs = users_ref.stream()

    # Create workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Users"

    # Headers (columns)
    headers = [
        "Email", "Full Name", "Student ID", "Contact Number",
        "Guardian Contact", "Blood Group", "Completed Credit",
        "Joining Semester", "T-shirt Size", "Verified", "Role", "Created At"
    ]
    ws.append(headers)

    # Add users
    for doc in users_docs:
        u = doc.to_dict()
        row = [
            u.get("email", ""),
            u.get("full_name", ""),
            u.get("student_id", ""),
            u.get("contact_number", ""),
            u.get("guardian_contact", ""),
            u.get("blood_group", ""),
            u.get("completed_credit", ""),
            u.get("joining_semester", ""),
            u.get("t_shirt_size", ""),
            u.get("verified", False),
            u.get("role", "user"),
            u.get("createdAt", "")
        ]
        ws.append(row)

    # Save workbook to a BytesIO stream
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    return send_file(
        output,
        download_name="users.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route("/update_user/<uid>", methods=["POST"])
def update_user(uid):
    data = request.get_json()
    user_ref = db.collection("Users").document(uid)
    user_ref.update(data)
    return jsonify({"status": "success"})

@app.route("/update_payment_status/<uid>", methods=["POST"])
def update_payment_status(uid):
    payment_ref = db.collection('Payments').document(uid)
    payment_ref.update({'status': 'paid'})
    return '', 200
@app.route("/view_payments")
def view_payments():
    # Pagination params
    page = int(request.args.get('page', 1))
    per_page = 50

    # Filters
    search_email = request.args.get('email', '').strip()
    search_student = request.args.get('student_id', '').strip()
    search_date = request.args.get('date', '').strip()

    # Sorting
    sort_by = request.args.get('sort_by', 'date')
    sort_order = request.args.get('sort_order', 'desc')

    payments_ref = db.collection('Payments')
    docs = [d.to_dict() | {'uid': d.id} for d in payments_ref.stream()]

    # Filter manually (since some fields are CSV)
    def matches(doc):
        if search_email and search_email.lower() not in doc.get('email', '').lower():
            return False
        if search_student and search_student != doc.get('student_id', ''):
            return False
        if search_date:
            # check if date exists in CSV
            dates = [d.strip() for d in doc.get('date', '').split(',')]
            if search_date not in dates:
                return False
        return True

    filtered = list(filter(matches, docs))

    # Sort
    def sort_key(doc):
        val = doc.get(sort_by, '')
        # For CSV fields, just take first value for sorting
        if ',' in str(val):
            val = str(val).split(',')[0].strip()
        return val

    reverse = sort_order == 'desc'
    filtered.sort(key=sort_key, reverse=reverse)

    # Pagination
    total = len(filtered)
    total_pages = math.ceil(total / per_page)
    start = (page - 1) * per_page
    end = start + per_page
    payments = filtered[start:end]

    return render_template("view_payments.html",
                           payments=payments,
                           page=page,
                           total_pages=total_pages,
                           search_email=search_email,
                           search_student=search_student,
                           search_date=search_date,
                           sort_by=sort_by,
                           sort_order=sort_order)

@app.route("/download_payments_excel")
def download_payments_excel():
    payments_ref = db.collection("Payments")
    docs = payments_ref.stream()

    # Create workbook and active sheet
    wb = Workbook()
    ws = wb.active
    ws.title = "Payments"

    # Header row
    headers = [
        "Email", "Student ID", "Amount", "Charge", "Method",
        "Number(s)", "Receiver Number", "Date", "Time", "Trx ID", "Status"
    ]
    ws.append(headers)

    # Add data rows
    data_found = False
    for doc in docs:
        data_found = True
        data = doc.to_dict()
        ws.append([
            data.get("email", ""),
            data.get("student_id", ""),
            data.get("amount", ""),
            data.get("charge", ""),
            data.get("method", ""),
            data.get("number", ""),
            data.get("receiver_number", ""),
            data.get("date", ""),
            data.get("time", ""),
            data.get("trx_id", ""),
            data.get("status", "")
        ])

    if not data_found:
        flash("No payments found to export", "error")
        return redirect("/view_payments")

    # Save workbook to a BytesIO stream
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Send as file
    return send_file(
        output,
        as_attachment=True,
        download_name="payments.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
if __name__ == '__main__':
    app.run(debug=True)