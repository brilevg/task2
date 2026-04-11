import json
import xml.etree.ElementTree as ET


INPUT_FILE = "result_task_2.json"
OUTPUT_FILE = "result_task_3.xml"


def create_text_element(parent, tag, text):
    elem = ET.SubElement(parent, tag)
    if text is not None:
        elem.text = str(text)
    return elem


def convert_to_xml(data):
    root = ET.Element("vulnerabilities")

    for item in data:
        vuln = ET.SubElement(root, "vulnerability")

        # --- поля 1 уровня ---
        create_text_element(vuln, "ID", item.get("ID"))
        create_text_element(vuln, "vendor_release_date", item.get("vendor_release_date"))
        create_text_element(vuln, "vendor_release_url", item.get("vendor_release_url"))
        create_text_element(vuln, "url", item.get("url"))
        create_text_element(vuln, "published_date", item.get("published_date"))
        create_text_element(vuln, "updated_date", item.get("updated_date"))
        create_text_element(vuln, "description", item.get("description"))

        # --- cvss_list ---
        cvss_list_elem = ET.SubElement(vuln, "cvss_list")

        for cvss in item.get("cvss_list", []):
            cvss_elem = ET.SubElement(cvss_list_elem, "cvss", {
                "version": str(cvss.get("version")),
                "score": str(cvss.get("score")),
                "severity": str(cvss.get("severity"))
            })
            cvss_elem.text = str(cvss.get("vector"))

        # --- cpe_list ---
        cpe_list_elem = ET.SubElement(vuln, "cpe_list")

        for cpe in item.get("cpe_list", []):
            cpe_elem = ET.SubElement(cpe_list_elem, "cpe")
            cpe_elem.text = cpe

        # --- cwe ---
        cwe_list_elem = ET.SubElement(vuln, "cwe_list")

        cwe_dict = item.get("cwe", {})
        for cwe_id, cwe_data in cwe_dict.items():
            cwe_elem = ET.SubElement(cwe_list_elem, "cwe", {
                "id": cwe_id,
                "name": str(cwe_data.get("name"))
            })
            cwe_elem.text = str(cwe_data.get("description"))

    return root


def save_xml(root):
    tree = ET.ElementTree(root)

    # красивое форматирование (Python 3.9+)
    try:
        ET.indent(tree, space="  ")
    except:
        pass

    tree.write(OUTPUT_FILE, encoding="utf-8", xml_declaration=True)


def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    root = convert_to_xml(data)
    save_xml(root)

    print(f"XML сохранён в {OUTPUT_FILE}")


if __name__ == "__main__":
    main()