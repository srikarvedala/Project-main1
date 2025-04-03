import sqlite3

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect("malware_signatures.db")
cursor = conn.cursor()

# Drop the old table (optional, only if you want to reset)
cursor.execute("DROP TABLE IF EXISTS signatures")

# Create a new table with only required fields
cursor.execute('''
    CREATE TABLE IF NOT EXISTS signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        malware_name TEXT,
        hash TEXT UNIQUE,
        file_path TEXT
    )
''')

# Commit and close
conn.commit()
conn.close()

print("✅ Database and table created successfully!")
