from flask import Flask, jsonify
import psycopg2
from psycopg2 import OperationalError

app = Flask(__name__)

# Function to create the database connection
def create_connection():
    try:
        params = {
            "user": "user",
            "password": "Liquidmind@123",
            "host": "trialdb.postgres.database.azure.com",
            "port": "5432",
            "database": "postgres",
            "sslmode": "require"
        }
        
        connection = psycopg2.connect(**params)
        print("Successfully connected to the database!")
        return connection
    except OperationalError as e:
        print(f"Error connecting to the database: {e}")
        return None

# Function to fetch and return table names
def fetch_table_names():
    conn = create_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables
            WHERE table_schema = 'public';
        """)
        
        tables = cursor.fetchall()
        return [table[0] for table in tables]
    
    except psycopg2.Error as e:
        print(f"Error fetching table names: {e}")
        return []
    
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        print("Database connection closed.")

# Route to display table names in JSON format
@app.route('/tables', methods=['GET'])
def get_tables():
    tables = fetch_table_names()
    if not tables:
        return jsonify({"error": "No tables found or error connecting to the database."}), 500
    return jsonify({"tables": tables})

# Home route
@app.route('/', methods=['GET'])
def index():
    return "<h1>Welcome to the PostgreSQL Table Viewer</h1><p>Visit /tables to see the list of tables.</p>"

if __name__ == '__main__':
    app.run(debug=True)
