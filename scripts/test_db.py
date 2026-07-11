import psycopg2

try:
    conn = psycopg2.connect(
        host="localhost",
        port=5432,
        user="postgres",
        password="YOUR_PASSWORD",
        dbname="postgres"
    )

    print("CONNECTED")

    conn.close()

except Exception as e:
    print("ERROR:", e)