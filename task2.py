from bs4 import BeautifulSoup
import httpx
import asyncio
import json

INPUT_FILE = "result_task_1.json"
OUTPUT_FILE = "result_task_2.json"


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
        desc_header = soup.find(id="Description")

        if desc_header:
            desc_block = desc_header.find_next("div")
            text = desc_block.get_text(strip=True)
            return text

    except Exception as e:
        print(f"Ошибка парсинга CWE HTML: {e}")

    return None



async def parse_cve_data(client,base_item, data):
    result = base_item.copy()

    try:
        cve = data.get("containers", {}).get("cna", {})

        # ссылка на cve.org
        result["url"] = f"https://www.cve.org/CVERecord?id={base_item['ID']}"

        # даты
        result["published_date"] = data.get("cveMetadata", {}).get("datePublished")
        result["updated_date"] = data.get("cveMetadata", {}).get("dateUpdated")

        # описание
        descriptions = cve.get("descriptions", [])
        result["description"] = descriptions[0]["value"] if descriptions else None

        # CVSS
        result["cvss_list"] = []
        metrics = cve.get("metrics", [])

        for metric in metrics:
            for key, value in metric.items():
                if key.startswith("cvss"):
                    result["cvss_list"].append({
                        "version": key,
                        "score": value.get("baseScore"),
                        "vector": value.get("vectorString"),
                        "severity": value.get("baseSeverity")
                    })

        # CPE
        result["cpe_list"] = []
        affected = cve.get("affected", [])

        for item in affected:
            vendor = item.get("vendor", "").lower()
            product = item.get("product", "").lower()

            versions = item.get("versions", [])

            for v in versions:
                version = v.get("version")

                if vendor and product and version:
                    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                    result["cpe_list"].append(cpe)

        # CWE
        cwe_cache = {}
        result["cwe"] = {}

        problem_types = cve.get("problemTypes", [])

        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")

                if cwe_id:
                    if cwe_id not in cwe_cache:
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
    async with httpx.AsyncClient(timeout=20) as client:
        for base_item, data in zip(base_data, responses):
            if data:
                enriched = parse_cve_data(client,base_item, data)
                final_result.append(enriched)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final_result, f, indent=2, ensure_ascii=False)

    print(f"Готово: {len(final_result)} записей")


if __name__ == "__main__":
    asyncio.run(main())