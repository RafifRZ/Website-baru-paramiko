import sqlite3
import os

db_path = 'instance/network.db'

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Add status column to device if missing
    try:
        cursor.execute("ALTER TABLE device ADD COLUMN status VARCHAR(20) DEFAULT 'Unknown'")
        print("Added 'status' column to 'device' table.")
    except sqlite3.OperationalError:
        print("'status' column already exists in 'device' table.")
        
    # Log table will be created by db.create_all() in app.py or here
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            level VARCHAR(20) DEFAULT 'INFO',
            action VARCHAR(200) NOT NULL,
            device_id INTEGER,
            user_id INTEGER,
            FOREIGN KEY (device_id) REFERENCES device (id),
            FOREIGN KEY (user_id) REFERENCES user (id)
        )
    ''')
    print("Ensured 'log' table exists.")
    
    conn.commit()
    conn.close()
else:
    print("Database not found. It will be created by app.py.")
