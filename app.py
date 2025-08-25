from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from functools import wraps

# For timezone conversion (Python 3.9+)
from zoneinfo import ZoneInfo

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loan_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    loans = db.relationship('Loan', backref='responsible_user', lazy=True)

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    borrower_name = db.Column(db.String(100), nullable=False)  # NAVN PÅ ELEV/ANSATT
    class_info = db.Column(db.String(50))  # KLASSE
    item = db.Column(db.String(100), nullable=False)  # HVA ER UTLÅNT
    reason = db.Column(db.String(200))  # HVORFOR
    checkout_date = db.Column(db.DateTime, default=datetime.utcnow)  # LEVERT UT, stored in UTC
    value = db.Column(db.String(100))  # VERDISAK
    return_date = db.Column(db.DateTime, nullable=True)  # LEVERT TILBAKE, stored in UTC
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_returned = db.Column(db.Boolean, default=False)

# Helper function to convert UTC datetime to local timezone
def utc_to_local(utc_dt):
    if utc_dt is None:
        return None
    local_tz = ZoneInfo('Europe/Oslo')  # Replace with your timezone
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=ZoneInfo('UTC'))
    return utc_dt.astimezone(local_tz)

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        username = request.form.get('username')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify current password
        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('user_profile'))
        
        # Check if username already exists (if changing username)
        if username != user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists!', 'danger')
                return redirect(url_for('user_profile'))
            user.username = username
            flash('Username updated successfully!', 'success')
        
        # Change password if provided
        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match!', 'danger')
                return redirect(url_for('user_profile'))
            
            user.password = generate_password_hash(new_password)
            flash('Password updated successfully!', 'success')
        
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    return render_template('user_profile.html', user=user)

@app.route('/dashboard')
@login_required
def dashboard():
    active_loans = Loan.query.filter_by(is_returned=False).all()
    returned_loans = Loan.query.filter_by(is_returned=True).all()
    user = User.query.get(session['user_id'])

    # Convert dates to local time for display
    for loan in active_loans + returned_loans:
        loan.checkout_date_local = utc_to_local(loan.checkout_date)
        loan.return_date_local = utc_to_local(loan.return_date)

    return render_template('dashboard.html', active_loans=active_loans, returned_loans=returned_loans, is_admin=user.is_admin)

@app.route('/loan/new', methods=['GET', 'POST'])
@login_required
def new_loan():
    if request.method == 'POST':
        borrower_name = request.form.get('borrower_name')
        class_info = request.form.get('class_info')
        item = request.form.get('item')
        reason = request.form.get('reason')
        value = request.form.get('value')
        
        if not borrower_name or not item:
            flash('Name and item are required!', 'danger')
            return redirect(url_for('new_loan'))
        
        loan = Loan(
            borrower_name=borrower_name,
            class_info=class_info,
            item=item,
            reason=reason,
            value=value,
            user_id=session['user_id']
        )
        
        db.session.add(loan)
        db.session.commit()
        
        flash('Loan registered successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('new_loan.html')

@app.route('/loan/return/<int:loan_id>')
@login_required
def return_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    
    if loan.is_returned:
        flash('This item has already been returned.', 'warning')
    else:
        loan.is_returned = True
        loan.return_date = datetime.utcnow()  # stored in UTC
        db.session.commit()
        flash('Item marked as returned successfully!', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/loan/detail/<int:loan_id>')
@login_required
def loan_detail(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    loan.checkout_date_local = utc_to_local(loan.checkout_date)
    loan.return_date_local = utc_to_local(loan.return_date)
    
    # Get current user to determine if they're an admin
    user = User.query.get(session['user_id'])
    
    return render_template('loan_detail.html', loan=loan, is_admin=user.is_admin)

@app.route('/loan/delete/<int:loan_id>')
@admin_required  # Only admins can delete loans
def delete_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    
    # Store loan info for the flash message
    loan_info = f"{loan.item} borrowed by {loan.borrower_name}"
    
    # Delete the loan
    db.session.delete(loan)
    db.session.commit()
    
    flash(f'Loan "{loan_info}" deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.all()
    return render_template('admin_panel.html', users=users)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('add_user'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, is_admin=is_admin)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('User added successfully!', 'success')
        return redirect(url_for('admin_panel'))
    
    return render_template('add_user.html')

@app.route('/admin/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    if session['user_id'] == user_id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('admin_panel'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle_admin/<int:user_id>')
@admin_required
def toggle_admin(user_id):
    if session['user_id'] == user_id:
        flash('You cannot change your own admin status!', 'danger')
        return redirect(url_for('admin_panel'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = 'granted' if user.is_admin else 'revoked'
    flash(f'Admin status {status} for {user.username}!', 'success')
    return redirect(url_for('admin_panel'))

# Create the first admin user if no users exist
@app.before_request
def create_initial_admin():
    with app.app_context():
        db.create_all()
        if not User.query.first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000, host="0.0.0.0")