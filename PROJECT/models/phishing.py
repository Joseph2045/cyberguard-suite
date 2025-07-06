# models/phishing.py
from database.db_connection import create_connection, execute_query, execute_read_query

class PhishingDetector:
    @staticmethod
    def create_table():
        connection = create_connection()
        query = """
        CREATE TABLE IF NOT EXISTS phishing_results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            url VARCHAR(2048) NOT NULL,
            is_phishing BOOLEAN NOT NULL,
            confidence FLOAT,
            features JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
        execute_query(connection, query)
        connection.close()

    @staticmethod
    def save_result(user_id, url, is_phishing, confidence, features):
        connection = create_connection()
        query = """
        INSERT INTO phishing_results (user_id, url, is_phishing, confidence, features)
        VALUES (%s, %s, %s, %s, %s)
        """
        data = (user_id, url, is_phishing, confidence, features)
        execute_query(connection, query, data)
        connection.close()

    @staticmethod
    def get_user_history(user_id):
        connection = create_connection()
        query = "SELECT * FROM phishing_results WHERE user_id = %s ORDER BY created_at DESC"
        results = execute_read_query(connection, query, (user_id,))
        connection.close()
        return results