import json
import psycopg2

DB_CONFIG = {
    "dbname": "cvedb",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": 5432
}


def main():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    with open("result_task_2.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data:
        cve_id = item["ID"]

        # --- vulnerabilities ---
        cur.execute("""
            INSERT INTO vulnerability
            (id, vendor_release_date, vendor_release_url, url, published_date, updated_date, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, (
            cve_id,
            item.get("vendor_release_date"),
            item.get("vendor_release_url"),
            item.get("url"),
            item.get("published_date"),
            item.get("updated_date"),
            item.get("description")
        ))

        # --- cvss ---
        for cvss in item.get("cvss_list", []):
            cur.execute("""
                INSERT INTO cvss (cve_id, version, score, vector, severity)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                cve_id,
                cvss.get("version"),
                cvss.get("score"),
                cvss.get("vector"),
                cvss.get("severity")
            ))

        # --- cpe ---
        for cpe in item.get("cpe_list", []):
            cur.execute("""
                INSERT INTO cpe (cve_id, cpe_string)
                VALUES (%s, %s)
            """, (cve_id, cpe))

        # --- cwe ---
        for cwe_id, cwe_data in item.get("cwe", {}).items():

            # вставка CWE
            cur.execute("""
                INSERT INTO cwe (id, name, description)
                VALUES (%s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, (
                cwe_id,
                cwe_data.get("name"),
                cwe_data.get("description")
            ))

            # связь
            cur.execute("""
                INSERT INTO vulnerability_cwe (cve_id, cwe_id)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
            """, (cve_id, cwe_id))

    conn.commit()
    cur.close()
    conn.close()

    print("Данные успешно загружены")


if __name__ == "__main__":
    main()