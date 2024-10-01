from flask import Flask, render_template, request, redirect, url_for, session, flash
import psycopg2
import hashlib
import uuid

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required to handle session management

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Connect to your PostgreSQL database
def connect():
    return psycopg2.connect(
        database="gateapp",
        user="postgres",
        password="admin",
        host="localhost",
        port="5432"
    )

# Route for the home page
@app.route('/')
def index():
    return render_template('index.html')

# Route for Resident and Security Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        password_hash = hash_password(password)

        conn = connect()
        cursor = conn.cursor()

        if user_type == 'resident':
            cursor.execute("SELECT id, username FROM residents WHERE email = %s AND password_hash = %s", (email, password_hash))
        else:
            cursor.execute("SELECT id, name FROM security_personnel WHERE email = %s AND password_hash = %s", (email, password_hash))

        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['user_type'] = user_type
            flash(f'Welcome, {user[1]}!', 'success')

            if user_type == 'resident':
                return redirect(url_for('resident_portal'))
            else:
                return redirect(url_for('security_portal'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

# Route for Resident Portal
@app.route('/resident', methods=['GET', 'POST'])
def resident_portal():
    if 'user_id' not in session or session['user_type'] != 'resident':
        return redirect(url_for('login'))

    if request.method == 'POST':
        guest_name = request.form['guest_name']
        access_code = str(uuid.uuid4())[:8]  # Generate access code

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("INSERT INTO guests (resident_id, name, access_code) VALUES (%s, %s, %s)", 
                       (session['user_id'], guest_name, access_code))
        conn.commit()
        cursor.close()
        conn.close()

        flash(f'Guest {guest_name} added with access code {access_code}', 'success')

    return render_template('resident.html')

# Route for Security Portal
@app.route('/security', methods=['GET', 'POST'])
def security_portal():
    if 'user_id' not in session or session['user_type'] != 'security':
        return redirect(url_for('login'))

    if request.method == 'POST':
        access_code = request.form['access_code']

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("SELECT id, name FROM guests WHERE access_code = %s", (access_code,))
        guest = cursor.fetchone()

        if guest:
            cursor.execute("INSERT INTO access_logs (guest_id, security_personnel_id, access_granted) VALUES (%s, %s, %s)", 
                           (guest[0], session['user_id'], True))
            conn.commit()
            flash(f'Access granted for guest: {guest[1]}', 'success')
        else:
            flash('Invalid access code', 'danger')

        cursor.close()
        conn.close()

    return render_template('security.html')

# Route to log out
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
