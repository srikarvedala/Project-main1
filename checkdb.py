import sqlite3

# Connect to the database
conn = sqlite3.connect("malware_signatures.db")
cursor = conn.cursor()

# Check if the "signatures" table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='signatures';")
result = cursor.fetchone()

if result:
    print("✅ Table 'signatures' exists!")
else:
    print("❌ Table 'signatures' is missing!")

conn.close()
