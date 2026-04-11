import httpx
from bs4 import BeautifulSoup
import json
import re
import asyncio
from datetime import datetime

BASE_URL = "https://helpx.adobe.com"
START_URL = "https://helpx.adobe.com/security/security-bulletin.html"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml"
}


async def fetch(client, url):
    try:
        response = await client.get(
            url,
            headers=HEADERS,
            timeout=20,
            follow_redirects=True
        )
        response.raise_for_status()
        return response.text

    except Exception as e:
        print(f"Ошибка запроса {url}: {e}")
        return None

async def get_bulletin_links(client):
    html = await fetch(client, START_URL)
    soup = BeautifulSoup(html, "html.parser")

    links = set()

    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True).lower()
        href = a["href"]

        if "audition" in text:
            full_url = href if href.startswith("http") else BASE_URL + href
            links.add(full_url)

    return list(links)


def extract_date(soup):
    try:
        rows = soup.select("table tbody tr")
        if len(rows) > 1:
            cols = rows[1].find_all("td")
            if len(cols) > 1:
                text = cols[1].get_text(strip=True)
                date = datetime.strptime(text, "%B %d, %Y")
                return date.date().isoformat()

    except Exception as e:
        print(f"Ошибка парсинга даты: {e}")

    return None


def extract_cves(soup):
    text = soup.get_text()
    return set(re.findall(r"CVE-\d{4}-\d{4,7}", text))


async def parse_bulletin(client, url):
    html = await fetch(client, url)
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")

    cves = extract_cves(soup)
    date = extract_date(soup)

    results = []
    for cve in cves:
        results.append({
            "ID": cve,
            "vendor_release_date": date,
            "vendor_release_url": url
        })

    return results


async def main():
    async with httpx.AsyncClient(http2=True,headers=HEADERS,timeout=20) as client:
        links = await get_bulletin_links(client)
        print(f"Найдено страниц: {len(links)}")
        tasks = [parse_bulletin(client, link) for link in links]
        results_nested = await asyncio.gather(*tasks)
        all_results = [item for sublist in results_nested for item in sublist]
        unique = {
            (d["ID"], d["vendor_release_url"]): d
            for d in all_results
        }
        final_result = list(unique.values())
        with open("result_task_1.json", "w", encoding="utf-8") as f:
            json.dump(final_result, f, indent=2, ensure_ascii=False)
        print(f"Сохранено {len(final_result)} CVE")


if __name__ == "__main__":
    asyncio.run(main())