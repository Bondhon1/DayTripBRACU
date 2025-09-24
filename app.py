from flask import Flask, redirect, render_template, request, make_response, session, abort, jsonify, url_for, flash
import secrets
from functools import wraps
import firebase_admin
from firebase_admin import credentials, firestore, auth
from datetime import timedelta, datetime
import os
import json
from dotenv import load_dotenv


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

def fix_date_format(date_str):
    # Example input: "2025-10-10T23:59" (currently YYYY-DD-MM)
    if not date_str:
        return None
    try:
        # Split date and time parts
        date_part, time_part = date_str.split("T")
        year, day, month = date_part.split("-")  # Current wrong order: YYYY-DD-MM
        # Rearrange to correct ISO format: YYYY-MM-DD
        fixed_date = f"{year}-{month}-{day}T{time_part}"
        # Validate by parsing to datetime
        datetime.fromisoformat(fixed_date)
        return fixed_date
    except Exception as e:
        return None

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
        settings["payment_deadline"] = fix_date_format(settings.get("payment_deadline"))
        settings["profile_update_deadline"] = fix_date_format(settings.get("profile_update_deadline"))
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

    if request.method == 'POST':
        # Collect form data
        full_name = request.form.get('full_name')
        student_id = request.form.get('student_id')
        contact_number = request.form.get('contact_number')
        joining_semester = request.form.get('joining_semester')
        completed_credit = request.form.get('completed_credit')
        guardian_contact = request.form.get('guardian_contact')
        blood_group = request.form.get('blood_group')

        # Update Firestore
        user_ref.update({
            "full_name": full_name,
            "student_id": student_id,
            "contact_number": contact_number,
            "joining_semester": joining_semester,
            "completed_credit": completed_credit,
            "guardian_contact": guardian_contact,
            "blood_group": blood_group
        })

        return redirect(url_for('profile'))

    # GET method → load current data
    user_data = user_ref.get().to_dict()

    return render_template('profile.html', user=user_data)

@app.route('/payment')
@auth_required
def payment():
    user = session.get('user')
    uid = user["uid"]
    payment_ref = db.collection("Payments").document(uid).get()

    payment = payment_ref.to_dict() if payment_ref.exists else None
    

    # print to console/log to check amount type/value
    if payment:
        app.logger.debug(f"Payment amount type: {type(payment.get('amount'))}, value: {payment.get('amount')}")
    
    reg_type = "pre"  # default
    if payment:
        status = payment.get("status")
        # Check explicitly for numeric value 500 or string '500'
        amount = payment.get('amount')
        if amount == 500 or amount == '500':
            reg_type = "remaining"
        elif status == "paid":
            reg_type = "done"

    return render_template('payment.html', user=user, reg_type=reg_type, payment=payment)


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
        status = 'paid'
    elif reg_type == 'remaining':
        base_amount = 2000  # Total amount stored for pre+remaining
        charge = 28 if method == 'Bkash' else 13
        status = 'paid'
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

        # Get user document by UID
        user_ref = db.collection("Users").document(uid).get()
        if not user_ref.exists:
            return "Unauthorized - User not registered", 401

        user_data = user_ref.to_dict()

        # Only allow if role is admin
        if user_data.get('role') != 'admin':
            return "Forbidden - Not an admin", 403

        # Login successful: set session with user info
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

    db.collection("Settings").document("config").set({
        "payment_deadline": payment_deadline,
        "profile_update_deadline": profile_update_deadline,
        "bkash_number": bkash_number,
        "nagad_number": nagad_number
    })

    flash("Settings updated successfully!", "success")
    return redirect(url_for("admin_dashboard"))

if __name__ == '__main__':
    app.run(debug=True)