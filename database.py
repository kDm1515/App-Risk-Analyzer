import sqlite3

DATABASE = "app_risk.db"


def init_db():
    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS app_analysis (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        app_name TEXT,

        package_name TEXT,

        version TEXT,

        risk_score INTEGER,

        verdict TEXT

    )
    """)

    conn.commit()
    conn.close()


def save_analysis(app_info, risk):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO app_analysis
    (app_name, package_name, version, risk_score, verdict)

    VALUES (?, ?, ?, ?, ?)
    """, (

        app_info["app_name"],
        app_info["package_name"],
        app_info["version_name"],
        risk["score"],
        risk["verdict"]

    ))

    conn.commit()
    conn.close()

def get_all_analysis():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
    app_name,
    package_name,
    version,
    risk_score,
    verdict
    FROM app_analysis
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows

def get_statistics():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM app_analysis")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM app_analysis WHERE verdict='High Risk'")
    high = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM app_analysis WHERE verdict='Medium Risk'")
    medium = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM app_analysis WHERE verdict='Low Risk'")
    low = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM app_analysis")
    avg = cursor.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "average": round(avg, 2) if avg else 0
    }