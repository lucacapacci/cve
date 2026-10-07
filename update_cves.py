import os
import re
import json
import api_builder

# ==========================================
# Step 0: Create the required python sets
# ==========================================
REBUILD = set()
DESCRIPTION_FROM_REDHAT = set()
CVSS_FROM_REDHAT = set()
PRODUCT_FROM_REDHAT = set()
DESCRIPTION_FROM_GHSA = set()
CVSS_FROM_GHSA = set()
PRODUCT_FROM_GHSA = set()
GITHUB_POCS = set()
TOOLS_POCS = set()
DESCRIPTION_FROM_CISA_KEV = set()
PRODUCT_FROM_CISA_KEV = set()
CISA_KEV_FIELDS = set()
NEWS = set()

BASE_DIR = "."

# ==========================================
# Helper Functions
# ==========================================

def extract_cves_from_txt(filepath):
    """
    Reads a text file line by line, extracts paths, and returns a set of CVE IDs
    only if the path ends in .json or .csv and the filename is a valid CVE ID.
    """
    cves = set()
    if not os.path.exists(filepath):
        return cves
        
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            path = line.strip()
            if not path:
                continue
                
            filename = os.path.basename(path)
            if filename.lower().endswith('.json') or filename.lower().endswith('.csv'):
                base_name = os.path.splitext(filename)[0]
                # Validate that the base name matches CVE-YYYY-NNNNN format
                if re.match(r'^CVE-\d{4}-\d{4,}$', base_name, re.IGNORECASE):
                    cves.add(base_name.upper())
                    
    return cves

def get_cve_file_path(cve_id):
    """
    Determines the path to the CVE json file based on the YYYY directory structure.
    Example: CVE-2023-12345 -> 2023/CVE-2023-12345.json
    """
    year = cve_id.split('-')[1]
    return os.path.join(year, f"{cve_id}.json")

def check_cve_fields(cve_id):
    """
    Checks if the CVE JSON file exists. 
    Returns: None if it doesn't exist.
    Returns: (desc_empty, cvss_empty, prod_empty) booleans if it does exist.
    """
    path = get_cve_file_path(cve_id)
    if not os.path.exists(path):
        return None
        
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # In Python, empty strings "", empty lists [], and None all evaluate to False
        desc_empty = not bool(data.get("description"))
        cvss_empty = not bool(data.get("cvss"))
        prod_empty = not bool(data.get("products"))
        
        return desc_empty, cvss_empty, prod_empty
        
    except (json.JSONDecodeError, OSError):
        # If the file exists but is corrupted/unreadable, we treat it as missing to trigger a rebuild
        return None

def get_year_from_cve(cve_id):
    parts = cve_id.split('-')
    if len(parts) >= 3 and parts[0].upper() == 'CVE':
        year = parts[1]
        return year
    else:
        return cve_id  # if can't extract CVE I just create a dir named like the CVE itself

def make_year_dir(base_dir, year):
    year_dir = os.path.join(base_dir, year)
    os.makedirs(year_dir, exist_ok=True)
    return year_dir

def save_cve(cve_id, cve_json):
    year = get_year_from_cve(cve_id)
    year_dir = make_year_dir(BASE_DIR, year)

    # Save the JSON string to the target file
    output_file_path = os.path.join(year_dir, f"{cve_id}.json")
    with open(output_file_path, 'w', encoding='utf-8') as out_f:
        out_f.write(cve_json)

# ==========================================
# Main Execution Steps
# ==========================================

# Step 1: nvd_files.txt
nvd_cves = extract_cves_from_txt("nvd_files.txt")
REBUILD.update(nvd_cves)

# Step 2: cvelistV5_files.txt
cvelist_cves = extract_cves_from_txt("cvelistV5_files.txt")
REBUILD.update(cvelist_cves)

# Step 3: ghsa_cve_files.txt
ghsa_cves = extract_cves_from_txt("ghsa_cve_files.txt")
for cve in ghsa_cves:
    fields = check_cve_fields(cve)
    if fields is None:
        REBUILD.add(cve)
    else:
        desc_empty, cvss_empty, prod_empty = fields
        if desc_empty: DESCRIPTION_FROM_GHSA.add(cve)
        if cvss_empty: CVSS_FROM_GHSA.add(cve)
        if prod_empty: PRODUCT_FROM_GHSA.add(cve)

# Step 4: cisa_kev_files.txt
cisa_kev_cves = extract_cves_from_txt("cisa_kev_files.txt")
for cve in cisa_kev_cves:
    fields = check_cve_fields(cve)
    if fields is None:
        REBUILD.add(cve)
    else:
        CISA_KEV_FIELDS.add(cve)
        desc_empty, cvss_empty, prod_empty = fields
        if desc_empty and cve not in DESCRIPTION_FROM_GHSA: DESCRIPTION_FROM_CISA_KEV.add(cve)
        if prod_empty and cve not in PRODUCT_FROM_GHSA: PRODUCT_FROM_CISA_KEV.add(cve)

# Step 5: redhat_vex_files.txt
redhat_cves = extract_cves_from_txt("redhat_vex_files.txt")
for cve in redhat_cves:
    fields = check_cve_fields(cve)
    if fields is None:
        REBUILD.add(cve)
    else:
        desc_empty, cvss_empty, prod_empty = fields
        if desc_empty and cve not in DESCRIPTION_FROM_GHSA and cve not in DESCRIPTION_FROM_CISA_KEV: DESCRIPTION_FROM_REDHAT.add(cve)
        if cvss_empty and cve not in CVSS_FROM_GHSA: CVSS_FROM_REDHAT.add(cve)
        if prod_empty and cve not in PRODUCT_FROM_GHSA and cve not in PRODUCT_FROM_CISA_KEV: PRODUCT_FROM_REDHAT.add(cve)

# Step 6: PoC-in-GitHub_files.txt
github_pocs_cves = extract_cves_from_txt("PoC-in-GitHub_files.txt")
for cve in github_pocs_cves:
    if check_cve_fields(cve) is None:
        REBUILD.add(cve)
    else:
        GITHUB_POCS.add(cve)

# Step 7: pocs_files.txt
tools_pocs_cves = extract_cves_from_txt("pocs_files.txt")
for cve in tools_pocs_cves:
    if check_cve_fields(cve) is None:
        REBUILD.add(cve)
    else:
        TOOLS_POCS.add(cve)

# Step 8: cve_news_files.txt
news_cves = extract_cves_from_txt("cve_news_files.txt")
for cve in news_cves:
    if check_cve_fields(cve) is None:
        REBUILD.add(cve)
    else:
        NEWS.add(cve)

# Step 9: epss_files.txt
EPSS_HAS_CHANGED = False
if os.path.exists("epss_files.txt"):
    with open("epss_files.txt", "r", encoding="utf-8") as f:
        content = f.read()
        if "epss_scores.csv" in content:
            EPSS_HAS_CHANGED = True


# Step 10: update data

print(f"REBUILD count: {len(REBUILD)}")

print(f"DESCRIPTION_FROM_GHSA count: {len(DESCRIPTION_FROM_GHSA)}")
print(f"CVSS_FROM_GHSA count: {len(CVSS_FROM_GHSA)}")
print(f"PRODUCT_FROM_GHSA count: {len(PRODUCT_FROM_GHSA)}")

print(f"DESCRIPTION_FROM_REDHAT count: {len(DESCRIPTION_FROM_REDHAT)}")
print(f"CVSS_FROM_REDHAT count: {len(CVSS_FROM_REDHAT)}")
print(f"PRODUCT_FROM_REDHAT count: {len(PRODUCT_FROM_REDHAT)}")

print(f"DESCRIPTION_FROM_CISA_KEV count: {len(DESCRIPTION_FROM_CISA_KEV)}")
print(f"PRODUCT_FROM_CISA_KEV count: {len(PRODUCT_FROM_CISA_KEV)}")
print(f"CISA_KEV_FIELDS count: {len(CISA_KEV_FIELDS)}")

print(f"GITHUB_POCS count: {len(GITHUB_POCS)}")
print(f"TOOLS_POCS count: {len(GITHUB_POCS)}")

print(f"NEWS count: {len(NEWS)}")

print(f"EPSS_HAS_CHANGED: {EPSS_HAS_CHANGED}")

for cve_id in REBUILD:
    cve_json = api_builder.process_cve(cve_id)
    save_cve(cve_id, cve_json)

for cve_id in DESCRIPTION_FROM_GHSA:
    api_builder.description_from_ghsa(get_cve_file_path(cve_id))

for cve_id in CVSS_FROM_GHSA:
    api_builder.cvss_from_ghsa(get_cve_file_path(cve_id))

for cve_id in PRODUCT_FROM_GHSA:
    api_builder.product_from_ghsa(get_cve_file_path(cve_id))

for cve_id in DESCRIPTION_FROM_REDHAT:
    api_builder.description_from_redhat(get_cve_file_path(cve_id))

for cve_id in CVSS_FROM_REDHAT:
    api_builder.cvss_from_redhat(get_cve_file_path(cve_id))

for cve_id in PRODUCT_FROM_REDHAT:
    api_builder.product_from_redhat(get_cve_file_path(cve_id))

for cve_id in DESCRIPTION_FROM_CISA_KEV:
    api_builder.description_from_cisa_kev(get_cve_file_path(cve_id))

for cve_id in PRODUCT_FROM_CISA_KEV:
    api_builder.product_from_cisa_kev(get_cve_file_path(cve_id))

for cve_id in CISA_KEV_FIELDS:
    api_builder.cisa_kev_fields(get_cve_file_path(cve_id))

for cve_id in GITHUB_POCS:
    api_builder.github_pocs(get_cve_file_path(cve_id))

for cve_id in TOOLS_POCS:
    api_builder.tools_pocs(get_cve_file_path(cve_id))

for cve_id in NEWS:
    api_builder.news(get_cve_file_path(cve_id))

if EPSS_HAS_CHANGED:
    api_builder.fetch_and_process_daily_epss(".")
