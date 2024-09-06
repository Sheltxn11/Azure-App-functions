from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from datetime import datetime, timedelta
import hashlib
import mysql.connector
from mysql.connector import Error
from decimal import Decimal
from flask_bcrypt import Bcrypt
from flask import send_file, abort, session
from io import BytesIO,StringIO
from oauthlib.oauth2 import WebApplicationClient
from requests_oauthlib import OAuth2Session
from azure.core.credentials import AzureKeyCredential
from azure.ai.formrecognizer import DocumentAnalysisClient
import csv
import requests
import json
import uuid
import time
import psycopg2
from psycopg2 import OperationalError


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Liquidmind.AI!@#$%^&*'
bcrypt = Bcrypt(app)


params = {
            "user": "user",
            "password": "Liquidmind@123",
            "host": "trialdb.postgres.database.azure.com",
            "port": "5432",
            "database": "postgres",
            "sslmode": "require" 
        }

connection = psycopg2.connect(**params)

GOOGLE_CLIENT_ID = "353457859863-da1isb23mdg7df41vk76v5hfa2n2lqgi.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

client = WebApplicationClient(GOOGLE_CLIENT_ID)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route('/google_login')
def google_login():
    # Get Google's authorization endpoint
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Create the authorization URL
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for('google_callback', _external=True),
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route('/google_callback')
def google_callback():
    
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    if not code:
        return "Authorization code missing", 400

    try:
        # Get Google's token endpoint
        google_provider_cfg = get_google_provider_cfg()
        token_endpoint = google_provider_cfg["token_endpoint"]

        # Prepare and send a request to get tokens from Google's token endpoint
        token_url, headers, body = client.prepare_token_request(
            token_endpoint,
            authorization_response=request.url,
            redirect_url=request.base_url,
            code=code
        )

        token_response = requests.post(
            token_url,
            headers=headers,
            data=body,
            auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
        )
        token_response.raise_for_status()  # Raise an exception for HTTP errors

        # Parse the tokens
        client.parse_request_body_response(json.dumps(token_response.json()))

        # Get user info from Google's userinfo endpoint
        userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
        uri, headers, body = client.add_token(userinfo_endpoint)
        userinfo_response = requests.get(uri, headers=headers, data=body)
        userinfo_response.raise_for_status()  # Raise an exception for HTTP errors

        # Extract user info
        user_info = userinfo_response.json()
        session['email'] = user_info.get('email')
        session['name'] = user_info.get('name')

    except requests.exceptions.RequestException as e:
        return f"An error occurred: {e}", 500

    return redirect(url_for('dashboard'))

def generate_msme_id(email):
    now = datetime.now()
    datetime_str = now.strftime('%Y%m%d%H%M%S%f')
    unique_str = email + datetime_str
    user_id = hashlib.sha256(unique_str.encode()).hexdigest()
    return user_id

def generate_vendor_id(name):
    now = datetime.now()
    datetime_str = now.strftime('%Y%m%d%H%M%S%f')
    unique_str = name + datetime_str
    user_id = hashlib.sha256(unique_str.encode()).hexdigest()
    return user_id





@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    phone_number = request.form['phone_number']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash('Passwords do not match!', 'error')
        return redirect(url_for('index'))

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        cursor = connection.cursor()
        msme_id = generate_msme_id(email)  # Generate a unique MSME ID

        insert_query = """
        INSERT INTO MSME (MSME_ID, MSME_FIRSTNAME, MSME_LASTNAME, MSME_PHONE, MSME_EMAIL, MSME_PASSWORD, MSME_CPASSWORD)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (msme_id, first_name, last_name, phone_number, email, hashed_password, hashed_password))
        connection.commit()

        session['MSME_ID'] = msme_id  # Store MSME ID in the session

        flash('Account created successfully!', 'success')
        return redirect(url_for('erp'))

    except Error as e:
        print(f"Error in registration: {e}")
        flash('Email or phone number already exists!', 'error')
        return redirect(url_for('index'))

    finally:
        cursor.close()


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    try:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM MSME WHERE MSME_EMAIL = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user['MSME_PASSWORD'], password):
            session['MSME_ID'] = user['MSME_ID']  # Consistent session key
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'error')
            return redirect(url_for('index'))

    except Error as e:
        print(f"Error in login: {e}")
        flash('Login failed. Please try again later.', 'error')
        return redirect(url_for('index'))

    finally:
        cursor.close()


@app.route('/erp', methods=['GET', 'POST'])
def erp():
    if request.method == 'POST':
        erp = request.form['erp']
        erp_id = request.form['erp_id']
        msme_industry = request.form['industry']

        try:
            cursor = connection.cursor()
            msme_id = session.get('MSME_ID')  # Retrieve the MSME_ID from the session

            # Insert the MSME ERP details into the database, including the MSME_ID
            insert_query = """
            INSERT INTO ERP(MSME_ID, MSME_ERP, MSME_ERP_ID, MSME_INDUSTRY)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(insert_query, (msme_id, erp, erp_id, msme_industry))
            connection.commit()

            flash('ERP registration successful!', 'success')
            return redirect(url_for('vendor_register'))

        except Error as e:
            print(f"Error in ERP registration: {e}")
            flash('Registration failed. Please try again later.', 'error')
            return redirect(url_for('index'))

        finally:
            cursor.close()
    else:
        return render_template('erp.html')





@app.route('/dashboard')
def dashboard():
    print(session)
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')



@app.route('/vendor_register', methods=['GET', 'POST'])
def vendor_register():
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    msme_id = session['MSME_ID']  
    
    if request.method == 'POST':
        # Assuming these are lists of vendor details
        vendor_names = request.form.getlist('vendorName')
        vendor_phone_numbers = request.form.getlist('phoneNumber')
        vendor_emails = request.form.getlist('vendorEmail')
        vendor_acc_names = request.form.getlist('accountantName')
        vendor_acc_numbers = request.form.getlist('accountNumber')
        vendor_ifsc_codes = request.form.getlist('ifscCode')
        vendor_industries = request.form.getlist('vendorIndustryName')

        print(f"Received data: {vendor_names}, {vendor_phone_numbers}, {vendor_emails}, {vendor_acc_names}, {vendor_acc_numbers}, {vendor_ifsc_codes}, {vendor_industries}")

        if not msme_id:
            flash('You need to log in first.', 'warning')
            return redirect(url_for('index'))

        try:
            cursor = connection.cursor()
            for i in range(len(vendor_names)):
                vendor_name = vendor_names[i]
                vendor_phone = vendor_phone_numbers[i]
                vendor_email = vendor_emails[i]
                vendor_acc_name = vendor_acc_names[i]
                vendor_acc_number = vendor_acc_numbers[i]
                vendor_ifsc_code = vendor_ifsc_codes[i]
                vendor_industry = vendor_industries[i]

                vendor_id = generate_vendor_id(vendor_name)

                insert_query = """
                INSERT INTO VENDOR (VENDOR_ID, MSME_ID, VENDOR_NAME, VENDOR_PHONE_NUMBER, VENDOR_EMAIL, VENDOR_ACC_NAME, VENDOR_ACC_NO, VENDOR_IFSC_CODE, VENDOR_INDUSTRY)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, (vendor_id, msme_id, vendor_name, vendor_phone, vendor_email, vendor_acc_name, vendor_acc_number, vendor_ifsc_code, vendor_industry))

            connection.commit()
            flash('Vendors registered successfully!', 'success')
            return redirect(url_for('vendor_register'))
        except Error as e:
            print(f"Error in vendor registration: {e}")
            flash('Vendor registration failed. Please try again later.', 'error')
            return redirect(url_for('vendor_register'))
        finally:
            cursor.close()

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT VENDOR_ID, VENDOR_NAME, VENDOR_PHONE_NUMBER, VENDOR_EMAIL, VENDOR_ACC_NAME, VENDOR_ACC_NO, VENDOR_IFSC_CODE, VENDOR_INDUSTRY FROM VENDOR WHERE MSME_ID = %s", (msme_id,))
        vendors = cursor.fetchall()
    except Error as e:
        print(f"Error in fetching vendors: {e}")
        vendors = []
    finally:
        cursor.close()

    return render_template('vendor_register.html', vendors=vendors)







@app.route('/edit_vendor/<vendor_id>', methods=['GET', 'POST'])
def edit_vendor(vendor_id):
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        vendor_name = request.form.getlist('vendorName')
        vendor_phone = request.form.getlist('phoneNumber')
        vendor_email = request.form.getlist('vendorEmail')
        vendor_acc_name = request.form.getlist('accountantName')
        vendor_acc_number = request.form.getlist('accountNumber')
        vendor_ifsc_code = request.form.getlist('ifscCode')
        vendor_industry = request.form.getlist('vendorIndustryName')
        try:
            cursor = connection.cursor()
            update_query = """
            UPDATE VENDOR
            SET VENDOR_NAME = %s, VENDOR_PHONE_NUMBER = %s, VENDOR_EMAIL = %s, VENDER_PAYMENT_GATEWAY = %s, VENDOR_PAYMENT_GATEWAY_LINK = %s, VENDOR_INDUSTRY = %s
            WHERE VENDOR_ID = %s
            """
            cursor.execute(update_query, (vendor_name, vendor_phone, vendor_email, vendor_acc_name, vendor_acc_number, vendor_ifsc_code, vendor_industry, vendor_id))
            connection.commit()
            flash('Vendor details updated successfully!', 'success')
            return redirect(url_for('vendor_register'))
        except Error as e:
            print(f"Error in updating vendor: {e}")
            flash('Failed to update vendor details. Please try again later.', 'error')
        finally:
            cursor.close()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM VENDOR WHERE VENDOR_ID = %s", (vendor_id,))
        vendor = cursor.fetchone()
    except Error as e:
        print(f"Error in fetching vendor details: {e}")
        vendor = None
    finally:
        cursor.close()
    if not vendor:
        flash('Vendor not found.', 'error')
        return redirect(url_for('vendor_register'))
    return render_template('edit_vendor.html', vendor=vendor)

@app.route('/delete_vendor/<vendor_id>', methods=['POST'])
def delete_vendor(vendor_id):
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    try:
        cursor = connection.cursor()
        delete_query = "DELETE FROM VENDOR WHERE VENDOR_ID = %s"
        cursor.execute(delete_query, (vendor_id,))
        connection.commit()
        flash('Vendor removed successfully!', 'success')
    except Error as e:
        print(f"Error in removing vendor: {e}")
        flash('Failed to remove vendor. Please try again later.', 'error')
    finally:
        cursor.close()
    return redirect(url_for('vendor_register'))

@app.route('/calendar', methods=['GET', 'POST'])
def calendar():
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    
    MSME_ID = session.get('MSME_ID')
    
    if request.method == 'POST':
        data = request.get_json()
        selected_date = data.get('selected_date')
        
        try:
            cursor = connection.cursor()
            query = """
                SELECT inst.*, v.VENDOR_NAME
                FROM INSTALLMENT inst
                JOIN INVOICE inv ON inst.INVOICE_ID = inv.INVOICE_ID
                JOIN VENDOR v ON inv.VENDOR_ID = v.VENDOR_ID
                WHERE inv.MSME_ID = %s
                    AND inst.SELECTED_DATE = %s
                    AND inst.STATUS = 'PENDING';
            """
            cursor.execute(query, (MSME_ID, selected_date))
            installments = cursor.fetchall()
        except Exception as e:
            print(f'Exception Raised: {e}')
            installments = []
        finally:
            cursor.close()

        return jsonify(installments=installments)
    
    else:
        current_date = datetime.now().date()
        selected_date = current_date.strftime('%Y-%m-%d')
        
        try:
            cursor = connection.cursor()
            query = """
                SELECT inst.*, v.VENDOR_NAME
                FROM INSTALLMENT inst
                JOIN INVOICE inv ON inst.INVOICE_ID = inv.INVOICE_ID
                JOIN VENDOR v ON inv.VENDOR_ID = v.VENDOR_ID
                WHERE inv.MSME_ID = %s
                    AND inst.SELECTED_DATE = %s
                    AND inst.STATUS = 'PENDING';
            """
            cursor.execute(query, (MSME_ID, selected_date))
            installments = cursor.fetchall()
        except Exception as e:
            print(f'Exception Raised: {e}')
            installments = []
        finally:
            cursor.close()

        return render_template('n_calendar.html', installments=installments)

@app.route('/get_selected_dates', methods=['GET'])
def get_selected_dates():
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    selected_dates = []
    try:
        cursor = connection.cursor()
        MSME_ID = session.get('MSME_ID')
        query = """
            SELECT DISTINCT SELECTED_DATE
            FROM INSTALLMENT inst
            JOIN INVOICE inv ON inst.INVOICE_ID = inv.INVOICE_ID
            WHERE inv.MSME_ID = %s
                AND inst.STATUS = 'PENDING';
        """
        cursor.execute(query, (MSME_ID,))
        result = cursor.fetchall()
        selected_dates = [row[0].strftime('%Y-%m-%d') for row in result]
    except Exception as e:
        print(f'Exception Raised: {e}')
    finally:
        cursor.close()
    return jsonify(selected_dates)


@app.route('/installment',methods=['GET', 'POST'])
def installment():
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    msme_id=session.get('MSME_ID')
    cursor=connection.cursor()
    query = """
    SELECT 
        i.INSTALLMENT_ID, 
        v.VENDOR_NAME, 
        v.VENDOR_INDUSTRY, 
        inv.INVOICE_NUMBER, 
        i.SELECTED_DATE,
        inv.DUE_DATE,
        i.AMOUNT
    FROM 
        INSTALLMENT i
    JOIN 
        INVOICE inv ON i.INVOICE_ID = inv.INVOICE_ID
    JOIN 
        VENDOR v ON inv.VENDOR_ID = v.VENDOR_ID
    WHERE 
        inv.MSME_ID = %s
        AND i.STATUS = 'PENDING'
    """

    cursor.execute(query, (msme_id,))
    results = cursor.fetchall()
    cursor.close()

    data = []
    for row in results:
        data.append({
            'installment_id': row[0],
            'vendor_name': row[1],
            'vendor_industry': row[2],
            'invoice_number': row[3],
            'selected_date' : row[4],
            'due_date' : row[5],
            'amount': row[6]
        })

    return render_template('pending_installments.html', data=data)

@app.route('/get_dashboard',methods=['GET'])
def get_dashboard():
    print(session)
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    msme_id = session['MSME_ID']
    cursor=connection.cursor()
    try:

        # Total Invoices Amount
        cursor.execute("SELECT SUM(INVOICE_TOTAL_AMOUNT) FROM INVOICE WHERE MSME_ID = %s", (msme_id,))
        total_invoices_amount = cursor.fetchone()[0] or Decimal('0.00')

        print(f'total_invoices_amount {total_invoices_amount}')

        # Total Amount Paid Still Now (including PAY_NOW and successful INSTALLMENTS)
        cursor.execute("""
        SELECT 
            COALESCE(SUM(PN.TOTAL_AMOUNT_PAID), 0) + COALESCE((SELECT SUM(AMOUNT) FROM INSTALLMENT WHERE INVOICE_ID IN (SELECT INVOICE_ID FROM INVOICE WHERE MSME_ID = %s) AND STATUS = 'PAID'), 0) AS total_paid
        FROM 
            PAY_NOW PN 
        JOIN 
            INVOICE I ON PN.INVOICE_ID = I.INVOICE_ID 
        WHERE 
            I.MSME_ID = %s
         """, (msme_id, msme_id))
        total_amount_paid = cursor.fetchone()[0] or Decimal('0.00')

        print(f'total_amount_paid {total_amount_paid}')

        #Due Amount To Paid
        cursor.execute(""" 
        SELECT 
            COALESCE((SELECT SUM(AMOUNT) FROM INSTALLMENT WHERE INVOICE_ID IN (SELECT INVOICE_ID FROM INVOICE WHERE MSME_ID = %s) AND STATUS = 'PENDING'), 0) AS total_paid
        """,(msme_id,))
        total_amount_due = cursor.fetchone()[0] or Decimal('0.00')
        print(f'Total Amount Due: {total_amount_due}')

        # Number of Invoice
        cursor.execute("SELECT COUNT(*) FROM INVOICE WHERE MSME_ID = %s", (msme_id,))
        number_of_invoices = cursor.fetchone()[0]

        print(f'number_of_invoices {number_of_invoices}')

        # Number of Invoice They Paid
        cursor.execute("SELECT COUNT(*) FROM INVOICE WHERE MSME_ID = %s AND INVOICE_STATUS = 'PAID'", (msme_id,))
        number_of_invoices_paid = cursor.fetchone()[0]

        print(f'number_of_invoices_paid {number_of_invoices_paid}')


        # Number of invoices in Due
        cursor.execute("SELECT COUNT(*) FROM INVOICE WHERE MSME_ID = %s AND INVOICE_STATUS = 'PENDING'", (msme_id,))
        number_of_invoices_due = cursor.fetchone()[0]

        print(f'number_of_invoices_due {number_of_invoices_due}')


        # Number of Invoice in Over Due
        cursor.execute("SELECT COUNT(*) FROM INVOICE WHERE MSME_ID = %s AND INVOICE_STATUS = 'Over Due'", (msme_id,))
        number_of_invoices_overdue = cursor.fetchone()[0]

        print(f'number_of_invoices_overdue {number_of_invoices_overdue}')


        # Invoices Due Today (count and sum amount)
        today = datetime.now().date()
        cursor.execute("SELECT COUNT(*), SUM(AMOUNT) FROM INSTALLMENT I JOIN INVOICE INV ON I.INVOICE_ID = INV.INVOICE_ID WHERE INV.MSME_ID = %s AND I.SELECTED_DATE = %s AND I.STATUS = 'PENDING'", (msme_id, today))
        invoices_due_today_count, amount_due_today = cursor.fetchone()
        amount_due_today = amount_due_today or Decimal('0.00')

        print(f'invoices_due_today_count {invoices_due_today_count}')
        print(f'amount_due_today {amount_due_today}')


        # Total Vendors
        cursor.execute("SELECT COUNT(DISTINCT VENDOR_NAME) FROM VENDOR WHERE MSME_ID = %s", (msme_id,))
        total_vendors = cursor.fetchone()[0]

        print(f'total_vendors {total_vendors}')


        # Next 7 Days Due Payments
        next_week = today + timedelta(days=7)
        cursor.execute("SELECT V.VENDOR_NAME, I.SELECTED_DATE, I.AMOUNT FROM INSTALLMENT I JOIN INVOICE INV ON I.INVOICE_ID = INV.INVOICE_ID JOIN VENDOR V ON INV.VENDOR_ID = V.VENDOR_ID WHERE INV.MSME_ID = %s AND I.SELECTED_DATE BETWEEN %s AND %s AND I.STATUS = 'PENDING'", (msme_id, today, next_week))        
        next_7_days_due_payments = cursor.fetchall()
        print(next_7_days_due_payments)

    except Exception as e:
        print(f"Error fetching data: {str(e)}")
    finally:
        cursor.close()

    return render_template('dashboard_page.html', 
                        total_invoices_amount=total_invoices_amount,
                        total_amount_paid=total_amount_paid,
                        total_amount_due=total_amount_due,
                        number_of_invoices=number_of_invoices,
                        number_of_invoices_paid=number_of_invoices_paid,
                        number_of_invoices_due=number_of_invoices_due,
                        number_of_invoices_overdue=number_of_invoices_overdue,
                        invoices_due_today_count=invoices_due_today_count,
                        amount_due_today=amount_due_today,
                        total_vendors=total_vendors,
                        next_7_days_due_payments=next_7_days_due_payments)







@app.route('/download_report')
def download_report():
    msme_id = session.get('MSME_ID')
    
    if not msme_id:
        return abort(403, description="Unauthorized access. No MSME ID found in session.")
    
    cursor = None
    try:
        cursor = connection.cursor(dictionary=True)

        query = """
        SELECT MSME_FIRSTNAME, MSME_LASTNAME, MSME_PHONE, MSME_EMAIL 
        FROM MSME 
        WHERE MSME_ID = %s
        """
        cursor.execute(query, (msme_id,))
        result = cursor.fetchall()

        if not result:
            return abort(404, description="No data found for the provided MSME ID.")

        # Initialize CSV output using StringIO
        output = StringIO()
        writer = csv.writer(output)

        # Write the header row
        header_row = ['MSME_FIRSTNAME', 'MSME_LASTNAME', 'MSME_PHONE', 'MSME_EMAIL']
        writer.writerow(header_row)

        # Write the data rows
        for row in result:
            writer.writerow([
                row.get('MSME_FIRSTNAME', ''),  
                row.get('MSME_LASTNAME', ''),
                row.get('MSME_PHONE', ''),
                row.get('MSME_EMAIL', '')
            ])

        output.seek(0)

        # Convert the StringIO content to bytes
        output_bytes = BytesIO(output.getvalue().encode('utf-8'))

        # Send the file as a downloadable CSV
        return send_file(output_bytes, 
                         mimetype='text/csv', 
                         as_attachment=True,
                         download_name=f'msme_{msme_id}_report.csv')

    except mysql.connector.Error as err:
        app.logger.error(f"Database error: {err}")
        return abort(500, description="Internal server error.")
    
    finally:
        if cursor:
            cursor.close()



@app.route('/logout')
def logout():
    if 'MSME_ID' not in session:
        return redirect(url_for('index'))
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('index'))

@app.route('/addVendor', methods=['POST'])
def add_vendor():
    # Retrieve email and name from the session
    email = session.get('email')
    name = session.get('name')

    # Function to generate a unique MSME ID
    def generate_msme_id(email):
        now = datetime.now()
        datetime_str = now.strftime('%Y%m%d%H%M%S%f')
        unique_str = email + datetime_str
        user_id = hashlib.sha256(unique_str.encode()).hexdigest()
        return user_id

    # Function to generate a unique Vendor ID
    def generate_vendor_id(name):
        now = datetime.now()
        datetime_str = now.strftime('%Y%m%d%H%M%S%f')
        unique_str = name + datetime_str
        user_id = hashlib.sha256(unique_str.encode()).hexdigest()
        return user_id

    # Get JSON data from the request
    data = request.json
    
    # Extracting data from the JSON request
    vendor_name = data.get('vendorName')
    vendor_phone = data.get('phoneNumber')
    vendor_email = data.get('vendorEmail')
    vendor_acc_name = data.get('accountantName')
    vendor_acc_no = data.get('accountNumber')
    vendor_ifsc = data.get('ifscCode')
    vendor_industry = data.get('vendorIndustryName')

    # Validate required fields
    if not vendor_email:
        return jsonify({"status": "failure", "message": "Vendor email is required"}), 400
    if not vendor_name:
        return jsonify({"status": "failure", "message": "Vendor name is required"}), 400
    if not vendor_phone:
        return jsonify({"status": "failure", "message": "Vendor phone number is required"}), 400

    # Check if MSME_ID is in the session
    msme_id = session.get('MSME_ID')
    if not msme_id:
        # Generate a new MSME_ID and insert it into the MSME table if not found
        msme_id = generate_msme_id(vendor_email)
        cursor = connection.cursor()
        try:
            # Prepare SQL query to insert data into the MSME table
            insert_query = """
            INSERT INTO MSME (MSME_ID, MSME_EMAIL) VALUES (%s, %s)
            """
            cursor.execute(insert_query, (msme_id, vendor_email))
            connection.commit()
            session['MSME_ID'] = msme_id
        except Exception as e:
            connection.rollback()
            return jsonify({"status": "failure", "message": str(e)}), 500
        finally:
            cursor.close()

    # Generate a unique ID for the vendor using vendor_name
    vendor_id = generate_vendor_id(vendor_name)

    # Prepare SQL query to insert data into the VENDOR table
    query = """
    INSERT INTO VENDOR (VENDOR_ID, MSME_ID, VENDOR_NAME, VENDOR_PHONE_NUMBER, VENDOR_EMAIL, VENDOR_ACC_NAME, VENDOR_ACC_NO, VENDOR_IFSC_CODE, VENDOR_INDUSTRY)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor = connection.cursor()
    try:
        # Execute the SQL query
        cursor.execute(query, (vendor_id, msme_id, vendor_name, vendor_phone, vendor_email, vendor_acc_name, vendor_acc_no, vendor_ifsc, vendor_industry))
        connection.commit()
        return jsonify({"status": "success", "message": "Vendor added successfully", "vendor_id": vendor_id})
    except Exception as e:
        connection.rollback()
        return jsonify({"status": "failure", "message": str(e)}), 500
    finally:
        cursor.close()



# @app.route('/verifyVendor', methods=['POST'])
# def verify_vendor():
#     data = request.json
    
#     # Extract vendor industry name
#     found_vendor_industry = data.get('vendorIndustryName')
    
#     cursor = connection.cursor(dictionary=True)
    
#     # SQL query to retrieve vendor names by industry
#     query = """
#     SELECT VENDOR.VENDOR_NAME
#     FROM VENDOR
#     JOIN MSME ON VENDOR.MSME_ID = MSME.MSME_ID
#     WHERE VENDOR.VENDOR_INDUSTRY = %s
#     """
#     cursor.execute(query, (found_vendor_industry,))
#     results = cursor.fetchall()
    
#     # Extract vendor names
#     vendor_names = [result['VENDOR_NAME'] for result in results]
    
#     if vendor_names:
#         # Return the first vendor name if available
#         return jsonify(vendor_names[0])
#     else:
#         # Return a message if no vendors are found
#         return jsonify("No vendor found"), 404

@app.route('/verifyVendors', methods=['POST'])
def verify_vendor():
    data = request.json
    
    # Extract vendor name pattern for similarity search
    vendor_name_pattern = data.get('vendorNamePattern')
    
    cursor = connection.cursor(dictionary=True)
    
    # SQL query to retrieve vendor names with similarity search
    query = """
    SELECT VENDOR.VENDOR_NAME
    FROM VENDOR
    WHERE VENDOR.VENDOR_NAME LIKE %s
    """
    # Add wildcards for the LIKE clause
    cursor.execute(query, (f'%{vendor_name_pattern}%',))
    results = cursor.fetchall()
    
    # Extract vendor names
    vendor_names = [result['VENDOR_NAME'] for result in results]
    
    if vendor_names:
        # Return the list of similar vendor names
        return jsonify(vendor_names)
    else:
        # Return a message if no vendors are found
        return jsonify("No vendor found"), 404

@app.route('/uploadInvoice', methods=['POST'])
def upload_invoice():
    azure_endpoint = os.getenv("AZURE_ENDPOINT", "https://trial3.cognitiveservices.azure.com/")
    azure_key = "df9c781b015546dcadbc3909de3aced2"

    if not azure_key:
        return jsonify({"status": "failure", "message": "Azure key not set"}), 500

    document_analysis_client = DocumentAnalysisClient(
        endpoint=azure_endpoint, credential=AzureKeyCredential(azure_key)
    )

    data = request.get_json()
    file_url = data.get('file_url')

    if not file_url:
        return jsonify({"status": "failure", "message": "No file URL provided"}), 400

    try:
        # Extract media_id from the file_url
        if '/whatsapp/media/' in file_url:
            media_id = file_url.split('/whatsapp/media/')[-1]
        else:
            return jsonify({"status": "failure", "message": "Invalid file URL format"}), 400

        # Construct Heltar API URL
        heltar_api_url = f"https://ai-bot-builder.heltar.com/api/typebots/cm00sttoe000g9y6zewh66qbm/whatsapp/media/{media_id}"
        headers = {"Authorization": "Bearer A9k1LvzeJn8AD4dkZJiVwiRu"}

        # Fetch media from Heltar API
        response = requests.get(heltar_api_url, headers=headers, timeout=10)

        if response.status_code == 401:
            return jsonify({"status": "failure", "message": "Unauthorized access to media URL"}), 401
        if response.status_code != 200:
            return jsonify({"status": "failure", "message": f"Failed to retrieve media content. HTTP status code: {response.status_code}"}), 400

    except requests.exceptions.RequestException as e:
        return jsonify({"status": "failure", "message": f"Error fetching file: {str(e)}"}), 500

    doc_file = BytesIO(response.content)

    try:
        # Analyze the document with Azure Form Recognizer
        poller = document_analysis_client.begin_analyze_document("prebuilt-invoice", doc_file)
        result = poller.result()

        if result.documents:
            invoice = result.documents[0]

            # Extract fields
            def extract_field_value(field):
                if field:
                    if hasattr(field.value, 'amount'):
                        return f"{field.value.currency if hasattr(field.value, 'currency') else ''} {field.value.amount}"
                    return field.value
                return 'N/A'

            fields = {name: extract_field_value(invoice.fields.get(name)) for name in [
                "VendorName", "InvoiceId", "InvoiceDate", "DueDate", "SubTotal", 
                "AdvancePayment", "Discount", "TotalTax", "InvoiceTotal"
            ]}

            items = invoice.fields.get("Items")
            ITEMS = []
            if items and items.value:
                for item in items.value:
                    ITEMS.append([
                        extract_field_value(item.value.get("Description")),
                        extract_field_value(item.value.get("Quantity")),
                        extract_field_value(item.value.get("UnitPrice")),
                        extract_field_value(item.value.get("Discount")),
                        extract_field_value(item.value.get("Tax")),
                        extract_field_value(item.value.get("Amount"))
                    ])

            return jsonify({
                "status": "success",
                "invoice": fields,
                "items": ITEMS
            })
        else:
            return jsonify({"status": "failure", "message": "No invoice found in the document"}), 404

    except Exception as e:
        return jsonify({"status": "failure", "message": f"Error processing document: {str(e)}"}), 500

    finally:
        doc_file.close()

# @app.route('/uploadInvoice', methods=['POST'])
# def upload_invoice():
#     azure_endpoint = "https://trial3.cognitiveservices.azure.com/"
#     azure_key = "df9c781b015546dcadbc3909de3aced2"

#     if not azure_key:
#         return jsonify({"status": "failure", "message": "Azure key not set"}), 500

#     document_analysis_client = DocumentAnalysisClient(
#         endpoint=azure_endpoint, credential=AzureKeyCredential(azure_key)
#     )

#     data = request.get_json()
#     file_url = data.get('file_url')
#     media_id = data.get('media_id')

#     if not file_url and not media_id:
#         return jsonify({"status": "failure", "message": "No file URL or media ID provided"}), 400

#     try:
#         if media_id:
#             # Fetch media from Heltar API
#             heltar_api_url = f"https://ai-bot-builder.heltar.com/api/typebots/cm00sttoe000g9y6zewh66qbm/whatsapp/media/{media_id}"
#             headers = {"Authorization": "Bearer A9k1LvzeJn8AD4dkZJiVwiRu"}

#             response = requests.get(heltar_api_url, headers=headers)

#             if response.status_code == 401:
#                 return jsonify({"status": "failure", "message": "Unauthorized access to media URL"}), 401
#             if response.status_code != 200:
#                 return jsonify({"status": "failure", "message": f"Failed to retrieve media content. HTTP status code: {response.status_code}"}), 400

#         else:
#             # Fetch file from provided file_url
#             response = requests.get(file_url)

#             if response.status_code == 401:
#                 return jsonify({"status": "failure", "message": "Unauthorized access to file URL"}), 401
#             if response.status_code != 200:
#                 return jsonify({"status": "failure", "message": f"Failed to retrieve file content. HTTP status code: {response.status_code}"}), 400

#     except requests.exceptions.RequestException as e:
#         return jsonify({"status": "failure", "message": f"Error fetching file: {str(e)}"}), 500

#     doc_file = BytesIO(response.content)

#     try:
#         # Analyze the document with Azure Form Recognizer
#         poller = document_analysis_client.begin_analyze_document("prebuilt-invoice", doc_file)
#         result = poller.result()

#         if result.documents:
#             invoice = result.documents[0]

#             # Extract fields
#             def extract_field_value(field):
#                 if field:
#                     if hasattr(field.value, 'amount'):
#                         return f"{field.value.currency if hasattr(field.value, 'currency') else ''} {field.value.amount}"
#                     return field.value
#                 return 'N/A'

#             company_name = extract_field_value(invoice.fields.get("VendorName"))
#             invoice_number = extract_field_value(invoice.fields.get("InvoiceId"))
#             invoice_date = extract_field_value(invoice.fields.get("InvoiceDate"))
#             due_date = extract_field_value(invoice.fields.get("DueDate"))
#             subtotal = extract_field_value(invoice.fields.get("SubTotal"))
#             advance = extract_field_value(invoice.fields.get("AdvancePayment"))
#             discount = extract_field_value(invoice.fields.get("Discount"))
#             total_tax = extract_field_value(invoice.fields.get("TotalTax"))
#             total = extract_field_value(invoice.fields.get("InvoiceTotal"))

#             # Extract items
#             items = invoice.fields.get("Items")
#             ITEMS = []
#             if items and items.value:
#                 for item in items.value:
#                     item_description = extract_field_value(item.value.get("Description"))
#                     item_quantity = extract_field_value(item.value.get("Quantity"))
                    
#                     unit_price_obj = item.value.get("UnitPrice")
#                     unit_price = extract_field_value(unit_price_obj)
                    
#                     discount_obj = item.value.get("Discount")
#                     discount = extract_field_value(discount_obj)
                    
#                     tax_obj = item.value.get("Tax")
#                     tax = extract_field_value(tax_obj)
                    
#                     amount_obj = item.value.get("Amount")
#                     amount = extract_field_value(amount_obj)

#                     ITEMS.append([item_description, item_quantity, unit_price, discount, tax, amount])

#             return jsonify({
#                 "status": "success",
#                 "invoice": {
#                     "company_name": company_name,
#                     "invoice_number": invoice_number,
#                     "invoice_date": invoice_date,
#                     "due_date": due_date,
#                     "subtotal": subtotal,
#                     "advance": advance,
#                     "discount": discount,
#                     "total_tax": total_tax,
#                     "total": total
#                 },
#                 "items": ITEMS
#             })
#         else:
#             return jsonify({"status": "failure", "message": "No invoice found in the document"}), 404

#     except Exception as e:
#         return jsonify({"status": "failure", "message": f"Error processing document: {str(e)}"}), 500

#     finally:
#         doc_file.close()


@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        data = request.json
        media_url = data.get('media_url')

        if not media_url:
            return jsonify({"status": "error", "message": "No media URL provided"}), 400

        # Define and create the downloads directory within the route
        DOWNLOAD_FOLDER = 'downloads'
        os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

        # Download the media file
        response = requests.get(media_url, stream=True)
        
        if response.status_code == 200:
            # Extract filename from URL or use a default name
            filename = os.path.basename(urllib.parse.urlparse(media_url).path)
            filepath = os.path.join(DOWNLOAD_FOLDER, filename)
            
            # Save the file
            with open(filepath, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
            
            print(f"File downloaded successfully: {filename}")
            return jsonify({"status": "received", "filename": filename})
        else:
            print(f"Failed to download file. Status code: {response.status_code}")
            return jsonify({"status": "error", "message": "Failed to download file"}), response.status_code
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500




if __name__ == '__main__':
    app.run(debug=True)
