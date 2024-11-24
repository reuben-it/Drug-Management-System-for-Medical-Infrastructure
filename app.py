from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database connection function
def get_db_connection():
    conn = sqlite3.connect('mini_project.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create tables if they don't exist
def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create 'users' table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # Create updated 'drugs' table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS drugs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        drug_name TEXT NOT NULL,
        manufacturer TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        expiry_date TEXT NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize the database tables
create_tables()

# Route for the home page
@app.route('/')
def home():
    return render_template('home.html')

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password for security
        hashed_password = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('inventory'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

# Route for user logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/inventory', methods=['GET', 'POST'])
def inventory():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            drug_name = request.form['drug_name']
            manufacturer = request.form['manufacturer']
            quantity = request.form['quantity']
            expiry_date = request.form['expiry_date']
            cursor.execute('INSERT INTO drugs (drug_name, manufacturer, quantity, expiry_date) VALUES (?, ?, ?, ?)', 
                           (drug_name, manufacturer, quantity, expiry_date))
            conn.commit()
            flash('Drug added successfully!', 'success')
        
        elif action == 'edit':
            drug_id = request.form['drug_id']
            drug_name = request.form['drug_name']
            manufacturer = request.form['manufacturer']
            quantity = request.form['quantity']
            expiry_date = request.form['expiry_date']
            cursor.execute('UPDATE drugs SET drug_name = ?, manufacturer = ?, quantity = ?, expiry_date = ? WHERE id = ?', 
                           (drug_name, manufacturer, quantity, expiry_date, drug_id))
            conn.commit()
            flash('Drug updated successfully!', 'success')
        
        elif action == 'delete':
            drug_id = request.form['drug_id']
            cursor.execute('DELETE FROM drugs WHERE id = ?', (drug_id,))
            conn.commit()
            flash('Drug deleted successfully!', 'success')

    drugs = cursor.execute('SELECT * FROM drugs').fetchall()
    conn.close()
    return render_template('inventory.html', drugs=drugs)

# Route to view all drugs
'''@app.route('/drugs')
def drugs():
    if 'username' in session:
        conn = get_db_connection()
        drugs = conn.execute('SELECT * FROM drugs').fetchall()
        conn.close()
        return render_template('drugs.html', drugs=drugs)
    else:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

# Route to add a new drug
@app.route('/addDrugs', methods=['GET', 'POST'])
def addDrugs():
    if 'username' in session:
        if request.method == 'POST':
            drug_name = request.form['drug_name']
            manufacturer = request.form['manufacturer']
            quantity = request.form['quantity']
            expiry_date = request.form['expiry_date']
            
            conn = get_db_connection()
            conn.execute('INSERT INTO drugs (drug_name, manufacturer, quantity, expiry_date) VALUES (?, ?, ?, ?)', 
                         (drug_name, manufacturer, quantity, expiry_date))
            conn.commit()
            conn.close()
            flash('Drug added successfully!', 'success')
            return redirect(url_for('drugs'))
        
        return render_template('addDrugs.html')
    else:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
'''
# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)