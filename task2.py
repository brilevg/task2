from bs4 import BeautifulSoup
import httpx
import asyncio
import json

INPUT_FILE = "result_task_1.json"
OUTPUT_FILE = "result_task_2.json"

cwe_cache = {}
semaphore = asyncio.Semaphore(5)

async def fetch_cve(client, cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    try:
        r = await client.get(url, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"Ошибка CVE {cve_id}: {e}")
        return None

async def fetch_cwe_page(client, cwe_id):
    num = cwe_id.split("-")[1]
    url = f"https://cwe.mitre.org/data/definitions/{num}.html"

    try:
        r = await client.get(url, timeout=20)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"Ошибка CWE {cwe_id}: {e}")
        return None

def parse_cwe_html(html):
    soup = BeautifulSoup(html, "html.parser")

    try:
        # ищем текст "Description"
        header = soup.find("h2", string="Description")

        if not header:
            header = soup.find(string="Description")

        if header:
            parent = header.find_parent()
            desc_block = parent.find_next("div")

            if desc_block:
                return desc_block.get_text(strip=True)

    except Exception as e:
        print(f"Ошибка парсинга CWE HTML: {e}")

    return None



async def parse_cve_data(base_item, data, client):
    result = base_item.copy()

    try:
        cve = data.get("containers", {}).get("cna", {})

        result["url"] = f"https://www.cve.org/CVERecord?id={base_item['ID']}"

        result["published_date"] = data.get("cveMetadata", {}).get("datePublished")
        result["updated_date"] = data.get("cveMetadata", {}).get("dateUpdated")

        descriptions = cve.get("descriptions", [])
        result["description"] = descriptions[0]["value"] if descriptions else None

        # --- CVSS ---
        result["cvss_list"] = []
        for metric in cve.get("metrics", []):
            for key, value in metric.items():
                if key.startswith("cvss"):
                    result["cvss_list"].append({
                        "version": key,
                        "score": value.get("baseScore"),
                        "vector": value.get("vectorString"),
                        "severity": value.get("baseSeverity")
                    })

        # --- CPE ---
        result["cpe_list"] = []
        for item in cve.get("affected", []):
            vendor = (item.get("vendor") or "unknown").lower()
            product = (item.get("product") or "unknown").lower()

            versions = item.get("versions", [])

            for v in versions:
                version = v.get("version") or "*"
                cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                result["cpe_list"].append(cpe)

        result["cpe_list"] = list(set(result["cpe_list"]))

        # --- CWE ---
        result["cwe"] = {}

        for pt in cve.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")

                if not cwe_id:
                    continue

                if cwe_id not in cwe_cache:
                    async with semaphore:
                        html = await fetch_cwe_page(client, cwe_id)
                    description = parse_cwe_html(html) if html else None

                    cwe_cache[cwe_id] = {
                        "name": desc.get("description"),
                        "description": description
                    }

                result["cwe"][cwe_id] = cwe_cache[cwe_id]

    except Exception as e:
        print(f"Ошибка парсинга {base_item['ID']}: {e}")

    return result



async def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        base_data = json.load(f)

    async with httpx.AsyncClient(timeout=20) as client:
        tasks = [fetch_cve(client, item["ID"]) for item in base_data]
        responses = await asyncio.gather(*tasks)

        final_result = []

        for base_item, data in zip(base_data, responses):
            if data:
                enriched = await parse_cve_data(base_item, data, client)
                final_result.append(enriched)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_result, f, indent=2, ensure_ascii=False)

    print(f"Готово: {len(final_result)} записей")


if __name__ == "__main__":
    asyncio.run(main())