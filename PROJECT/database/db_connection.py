import mysql.connector
from database.db_config import db_config

def create_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

def execute_query(conn, query, params=None):
    cursor = conn.cursor()
    try:
        cursor.execute(query, params or ())
        conn.commit()
    except Exception as e:
        print(f"Query Error: {e}")

def execute_read_query(conn, query, params=None):
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(query, params or ())
        return cursor.fetchall()
    except Exception as e:
        print(f"Read Error: {e}")
        return []
