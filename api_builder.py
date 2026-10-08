import json
import os
import re
import urllib.request
import urllib.error
from urllib.parse import quote
from datetime import datetime, timedelta
from typing import Any, Dict, List, NamedTuple, Optional, Tuple, Union
import gzip
import csv


def capitalize(s: str) -> str:
    if not s:
        return ""
    if s.lower() == "poc":
        return "PoC"
    words = re.split(r'[\s_]+', s)
    return ' '.join([(w[0].upper() + w[1:]) if len(w) > 0 else '' for w in words])

def process_string(input_str: str) -> str:
    exact_map = {
        "kernel": "Linux Kernel",
        "kernel.src": "Linux Kernel",
    }
    prefix_map = {
        "kernel-": "Linux Kernel"
    }
    if input_str in exact_map:
        return exact_map[input_str]
    
    for prefix, replacement in prefix_map.items():
        if input_str.startswith(prefix):
            return replacement
            
    return input_str

def clean_poc_links(urls: List[str]) -> List[str]:
    if not urls:
        return []
    unique_map = {}
    for u in urls:
        clean = u.strip().rstrip('/')
        if "securityfocus.com/bid/" in clean:
            clean_https = clean
            if clean_https.startswith("http://"):
                clean_https = "https://" + clean_https[7:]
            clean = f"https://web.archive.org/web/2018/{clean_https}"
        
        path = clean
        if clean.startswith("https://"):
            path = clean[8:]
        elif clean.startswith("http://"):
            path = clean[7:]
            
        if path not in unique_map or clean.startswith("https"):
            unique_map[path] = clean
            
    return list(unique_map.values())

def get_cvss_severity(score: float) -> str:
    if not isinstance(score, (int, float)) or score < 0 or score > 10:
        return "Invalid Score"
    if score == 0.0: return "None"
    if score <= 3.9: return "Low"
    if score <= 6.9: return "Medium"
    if score <= 8.9: return "High"
    return "Critical"

def calculate_cvss3_base_score(vector: str) -> float:
    if not vector or not vector.startswith("CVSS:3"): return 0.0
    w = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {'U': {'N': 0.85, 'L': 0.62, 'H': 0.27}, 'C': {'N': 0.85, 'L': 0.68, 'H': 0.5}},
        'UI': {'N': 0.85, 'R': 0.62},
        'C': {'N': 0, 'L': 0.22, 'H': 0.56},
        'I': {'N': 0, 'L': 0.22, 'H': 0.56},
        'A': {'N': 0, 'L': 0.22, 'H': 0.56}
    }
    m = {}
    parts = vector.split('/')[1:]
    for p in parts:
        if ':' in p:
            k, v = p.split(':')
            m[k] = v
            
    scope = m.get('S', 'U')
    c_val = w['C'].get(m.get('C'), 0)
    i_val = w['I'].get(m.get('I'), 0)
    a_val = w['A'].get(m.get('A'), 0)
    
    iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
    if scope == 'U':
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02)**15
        
    pr_w = w['PR'].get(scope, {}).get(m.get('PR'), 0)
    av_w = w['AV'].get(m.get('AV'), 0)
    ac_w = w['AC'].get(m.get('AC'), 0)
    ui_w = w['UI'].get(m.get('UI'), 0)
    
    exploit = 8.22 * av_w * ac_w * pr_w * ui_w
    if impact <= 0: return 0.0
    
    if scope == 'U':
        base_score = min(impact + exploit, 10.0)
    else:
        base_score = min(1.08 * (impact + exploit), 10.0)
        
    import math
    return math.ceil(base_score * 10) / 10.0

def reconstruct_nvd_style_data(rh_cvss: dict) -> dict:
    return {
        "version": rh_cvss.get("version", "3.1"),
        "baseScore": rh_cvss.get("baseScore"),
        "vectorString": rh_cvss.get("vectorString"),
        "baseSeverity": str(rh_cvss.get("baseSeverity", "UNKNOWN")).upper(),
        "attackVector": rh_cvss.get("attackVector") or rh_cvss.get("attack_vector"),
        "attackComplexity": rh_cvss.get("attackComplexity") or rh_cvss.get("attack_complexity"),
        "privilegesRequired": rh_cvss.get("privilegesRequired") or rh_cvss.get("privileges_required"),
        "userInteraction": rh_cvss.get("userInteraction") or rh_cvss.get("user_interaction"),
        "scope": rh_cvss.get("scope"),
        "confidentialityImpact": rh_cvss.get("confidentialityImpact") or rh_cvss.get("confidentiality_impact"),
        "integrityImpact": rh_cvss.get("integrityImpact") or rh_cvss.get("integrity_impact"),
        "availabilityImpact": rh_cvss.get("availabilityImpact") or rh_cvss.get("availability_impact")
    }

def fetch_json(url: str) -> Optional[dict]:
    try:
        if url.startswith("http://") or url.startswith("https://"):
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode())
        else:
            with open(url, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        return None

def fetch_text(url: str) -> Optional[str]:
    try:
        if url.startswith("http://") or url.startswith("https://"):
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.read().decode()
        else:
            with open(url, 'r', encoding='utf-8') as f:
                return f.read()
    except Exception:
        return None

# =============================================================================
# CVE ENRICHMENT
# -----------------------------------------------------------------------------
# Every public function below takes an already-existing CVE JSON (either a file
# path, a JSON string, or a dict), fetches ONE source and updates ONE field.
#
# Common contract:
#   * cve_source     -> path to a CVE JSON file | JSON string | dict.
#                       Dicts are updated in place.
#   * base_repos     -> base URL / local dir of the data repos (same as process_cve)
#   * only_if_missing-> (description / cvss / products) True = leave the field
#                       alone if it already has a value (fallback-chain mode).
#   * save           -> True (default): if the input was a file, the updated JSON
#                       is written back to it (atomically), only when something
#                       actually changed. Use output_path to write elsewhere.
#   * returns        -> the updated dict, or None if the input is unusable.
#                       A failed fetch is not an error: data is left untouched.
#
# The CVE id is read from data["cve_id"] (falls back to the file name).
# Derived fields (ssvc, bod_sla, references) are NOT recomputed.
# =============================================================================

DEFAULT_BASE_REPOS = "https://lucacapacci.github.io"
DEFAULT_BASE_RH = "https://raw.githubusercontent.com/lucacapacci/redhat_vex_feed/refs/heads/main"
DESCRIPTION_PLACEHOLDER = "Description not available."
JUNK_PRODUCTS = ('n/a', 'unknown', 'n/a n/a', '*', '')

CveSource = Union[dict, str, os.PathLike]


# --- CVE id / file IO ---------------------------------------------------------

def normalize_cve_id(cve_input: str) -> Optional[str]:
    """Same normalisation as the original process_cve. Returns None if invalid."""
    if not isinstance(cve_input, str):
        return None
    cve_id = quote(cve_input).upper().replace('–', '-').replace('—', '-').replace('−', '-').replace('‑', '-').replace('―', '-')
    return cve_id if re.match(r'CVE-\d{4}-\d+', cve_id) else None


def load_cve_data(cve_source: CveSource):
    """Returns (data, path). data is None if the source cannot be used;
    path is set only when the data was read from a file."""
    if isinstance(cve_source, dict):
        return cve_source, None

    if isinstance(cve_source, str) and cve_source.lstrip().startswith("{"):
        try:
            data = json.loads(cve_source)
        except ValueError as e:
            print(f"[cve-json] Invalid JSON string: {e}")
            return None, None
        if not isinstance(data, dict):
            print("[cve-json] JSON string is not an object")
            return None, None
        return data, None

    if isinstance(cve_source, (str, os.PathLike)):
        path = os.fspath(cve_source)
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            print(f"[cve-json] Cannot read '{path}': {e}")
            return None, path
        if not isinstance(data, dict):
            print(f"[cve-json] '{path}' does not contain a JSON object")
            return None, path
        return data, path

    print(f"[cve-json] Unsupported input type: {type(cve_source).__name__}")
    return None, None


def save_cve_data(data: dict, path: str) -> bool:
    """Atomic write (temp file + rename) so a crash can't leave a half-written JSON."""
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        os.replace(tmp_path, path)
        return True
    except (OSError, TypeError, ValueError) as e:
        print(f"[cve-json] Cannot write '{path}': {e}")
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return False


class _CveCtx(NamedTuple):
    data: dict
    path: Optional[str]
    cve_id: str
    year: str
    snapshot: str


def _snapshot(data: dict) -> str:
    return json.dumps(data, sort_keys=True, default=str)


def _open_cve(cve_source: CveSource) -> Optional[_CveCtx]:
    data, path = load_cve_data(cve_source)
    if data is None:
        return None
    raw_id = data.get("cve_id") or (os.path.splitext(os.path.basename(path))[0] if path else "")
    cve_id = normalize_cve_id(raw_id)
    if not cve_id:
        print(f"[cve-json] Cannot determine a valid CVE id (got {raw_id!r})")
        return None
    return _CveCtx(data, path, cve_id, cve_id.split('-')[1], _snapshot(data))


def _close_cve(ctx: _CveCtx, save: bool, output_path: Optional[str]) -> dict:
    if save:
        target = output_path or ctx.path
        changed = _snapshot(ctx.data) != ctx.snapshot
        if target and (changed or output_path):
            save_cve_data(ctx.data, target)
    return ctx.data


# --- Pure extractors: source payload -> values (shared with process_cve) -----

def normalize_product(vendor: str, product: str) -> Optional[str]:
    v = (vendor or "").replace('\\', '').replace('_', ' ')
    p = (product or "").replace('\\', '').replace('_', ' ')
    is_vendor_na = v.lower() == 'n/a' or v == '' or v.lower() == 'unknown'
    if is_vendor_na:
        return capitalize(p) if p else None
    v_lower, p_lower = v.lower(), p.lower()
    if p_lower in v_lower:
        return capitalize(v)
    if v_lower in p_lower:
        return capitalize(p)
    return f"{capitalize(v)} {capitalize(p)}".strip()


def build_display_products(names: List[str], filter_junk: bool = True) -> str:
    product_map = {}
    for n in names:
        if n:
            product_map[n.lower()] = n
    if filter_junk:
        for k in JUNK_PRODUCTS:
            product_map.pop(k, None)
    display = sorted(product_map.values(), key=str.casefold)
    return ", ".join(display) if display else "N/A"


def add_cvss_entry(cvss_list: List[dict], source_name: str, cvss_data: dict,
                   seen_cisa_adp_vectors: Optional[set] = None,
                   skip_duplicates: bool = False) -> bool:
    """Append one normalised CVSS entry. Returns True if it was added."""
    vec = cvss_data.get("vectorString")
    if not vec or vec in ("N/A", "Vector N/A"):
        return False

    if "CISA-ADP" in source_name or "134c704f-9b21-4f2e-91b3-4a467353bcc0" in source_name:
        if seen_cisa_adp_vectors is not None:
            if vec in seen_cisa_adp_vectors:
                return False
            seen_cisa_adp_vectors.add(vec)
        source_name = "CISA-ADP"
    if source_name == "NVD (nvd@nist.gov)":
        source_name = "NVD"

    new_data = {"version": cvss_data["version"],
                "vectorString": cvss_data["vectorString"],
                "baseScore": cvss_data["baseScore"]}
    new_data["source"] = source_name

    if skip_duplicates and any(
        e.get("source") == source_name and e.get("vectorString") == vec
        and e.get("version") == new_data["version"] for e in cvss_list
    ):
        return False
    cvss_list.append(new_data)
    return True


def parse_kev_csv(kev_text: Optional[str]) -> Optional[List[str]]:
    """CISA KEV single-row CSV -> list of columns (None if no data row)."""
    if not kev_text:
        return None
    lines = kev_text.split('\n')
    if len(lines) > 1:
        cols = re.split(r',(?=(?:(?:[^"]*"){2})*[^"]*$)', lines[1])
        return [c.strip().strip('"') if c else '' for c in cols]
    return None


def extract_kev_description(kev_cols: Optional[List[str]]) -> Optional[str]:
    return kev_cols[5] if kev_cols and len(kev_cols) > 5 else None


def extract_kev_product(kev_cols: Optional[List[str]]) -> Optional[str]:
    if kev_cols and len(kev_cols) > 2:
        return normalize_product(kev_cols[1] or "", kev_cols[2] or "")
    return None


def extract_kev_fields(kev_cols: Optional[List[str]]) -> Dict[str, Any]:
    fields = {"in_cisa_kev": False, "added_date": None, "ransomware_campaign_use": False}
    if kev_cols and len(kev_cols) > 4:
        date = kev_cols[4]
        ransomware_use = kev_cols[8].strip() if len(kev_cols) > 8 and kev_cols[8] else ""
        if date:
            fields["in_cisa_kev"] = True
            fields["added_date"] = date
            if ransomware_use == "Known":
                fields["ransomware_campaign_use"] = True
    return fields


def extract_ghsa_description(ghsa_res: Optional[dict]) -> Optional[str]:
    return (ghsa_res.get("details") or ghsa_res.get("summary")) if ghsa_res else None


def extract_ghsa_cvss(ghsa_res: Optional[dict]) -> List[dict]:
    entries = []
    for s in (ghsa_res or {}).get("severity") or []:
        vector = s.get("score") or "N/A"
        if vector.startswith("CVSS:"):
            score = calculate_cvss3_base_score(vector) if vector.startswith("CVSS:3") else 0
            entries.append({
                "version": "4.0" if vector.startswith("CVSS:4") else "3.1",
                "baseScore": score,
                "vectorString": vector,
                "baseSeverity": get_cvss_severity(score).upper()
            })
    return entries


def extract_ghsa_products(ghsa_res: Optional[dict]) -> List[str]:
    names = []
    if isinstance(ghsa_res, dict):
        for a in ghsa_res.get("affected") or []:
            pkg_name = (a.get("package") or {}).get("name")
            if pkg_name:
                names.append(capitalize(process_string(pkg_name)))
    return names


def _redhat_vulnerability(rh_vex_res: Optional[dict]) -> Optional[dict]:
    if rh_vex_res and "vulnerabilities" in rh_vex_res and rh_vex_res["vulnerabilities"]:
        return rh_vex_res["vulnerabilities"][0]
    return None


def extract_redhat_description(rh_vex_res: Optional[dict]) -> Optional[str]:
    vuln = _redhat_vulnerability(rh_vex_res)
    if not vuln:
        return None
    notes = vuln.get("notes", [])
    return next((n.get("text") for n in notes if n.get("category") == 'description'), None)


def extract_redhat_cvss(rh_vex_res: Optional[dict]) -> List[dict]:
    vuln = _redhat_vulnerability(rh_vex_res)
    entries = []
    if vuln:
        for score_item in vuln.get("scores", []):
            rh_score_obj = score_item.get("cvss_v3") or score_item.get("cvss_v4") or score_item.get("cvss_v2")
            if rh_score_obj:
                entries.append(reconstruct_nvd_style_data(rh_score_obj))
    return entries


def extract_redhat_products(rh_vex_res: Optional[dict]) -> List[str]:
    vuln = _redhat_vulnerability(rh_vex_res)
    names = []
    if vuln:
        for prod_id in vuln.get("product_status", {}).get("known_affected", []):
            if prod_id and ':' in prod_id:
                name = capitalize(process_string(prod_id.split(':', 1)[1]))
                if name:
                    names.append(name)
    return names


def extract_github_pocs(poc_res: Any) -> List[str]:
    if not isinstance(poc_res, list):
        return []
    return [p["html_url"] for p in poc_res if isinstance(p, dict) and "html_url" in p]


def extract_tools_pocs(all_pocs_res: Any, cve_id: str) -> List[str]:
    if not isinstance(all_pocs_res, dict) or cve_id not in all_pocs_res:
        return []
    return [m["file"] for m in all_pocs_res[cve_id] if isinstance(m, dict) and "file" in m]


def _news_date(article: Any) -> str:
    return str(article.get("date") or "") if isinstance(article, dict) else ""


def extract_news(news_res: Any) -> List[dict]:
    """News repo payload -> list of articles, newest first."""
    if not isinstance(news_res, list):
        return []
    return sorted((a for a in news_res if isinstance(a, dict)), key=_news_date, reverse=True)


# --- Field updaters -----------------------------------------------------------

def _set_description(data: dict, new_desc: Optional[str], only_if_missing: bool) -> None:
    if not new_desc:
        return
    if only_if_missing:
        current = data.get("description")
        if isinstance(current, str) and current.strip() and current != DESCRIPTION_PLACEHOLDER:
            return
    data["description"] = new_desc


def _set_products(data: dict, names: List[str], only_if_missing: bool, filter_junk: bool = True) -> None:
    if not names:
        return
    if only_if_missing:
        current = data.get("products")
        if current and not (isinstance(current, str) and current.strip() in ("", "N/A")):
            return
    display = build_display_products(names, filter_junk)
    if display != "N/A":
        data["products"] = display


def _set_cvss(data: dict, source_name: str, entries: List[dict], only_if_missing: bool) -> None:
    """Replaces this source's previous entries with fresh ones; other sources are kept."""
    if not entries:
        return
    current = data.get("cvss")
    current = current if isinstance(current, list) else []
    if only_if_missing and current:
        return
    fresh: List[dict] = []
    for entry in entries:
        add_cvss_entry(fresh, source_name, entry, skip_duplicates=True)
    if not fresh:
        return
    kept = [e for e in current if not (isinstance(e, dict) and e.get("source") == source_name)]
    data["cvss"] = kept + fresh


def _poc_key(url: str) -> str:
    u = url.strip().rstrip('/')
    for scheme in ("https://", "http://"):
        if u.startswith(scheme):
            return u[len(scheme):]
    return u


def _merge_pocs(data: dict, new_urls: List[str]) -> None:
    existing = data.get("pocs")
    existing = list(existing) if isinstance(existing, list) else []
    seen = {_poc_key(u) for u in existing if isinstance(u, str)}
    candidates = [u for u in new_urls if isinstance(u, str) and u.strip()]
    # clean_poc_links is NOT idempotent (it re-wraps securityfocus links), so it is
    # only applied to the new URLs, never to what is already stored.
    for url in clean_poc_links(candidates):
        key = _poc_key(url)
        if key not in seen:
            seen.add(key)
            existing.append(url)
    data["pocs"] = existing


def _news_key(article: Any):
    if not isinstance(article, dict):
        return ("raw", json.dumps(article, sort_keys=True, default=str))
    link = article.get("link") or article.get("url")
    if isinstance(link, str) and link.strip():
        return ("link", _poc_key(link).lower())
    title = article.get("title")
    if isinstance(title, str) and title.strip():
        return ("title", title.strip().lower())
    return ("raw", json.dumps(article, sort_keys=True, default=str))


def _merge_news(data: dict, new_articles: List[dict]) -> None:
    existing = data.get("news")
    existing = list(existing) if isinstance(existing, list) else []
    seen = {_news_key(a) for a in existing}
    for article in new_articles:
        key = _news_key(article)
        if key not in seen:
            seen.add(key)
            existing.append(article)
    existing.sort(key=_news_date, reverse=True)
    data["news"] = existing


# =============================================================================
# PUBLIC FUNCTIONS
# =============================================================================

# --- GHSA ---------------------------------------------------------------------

def description_from_ghsa(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
                          only_if_missing: bool = False, save: bool = True,
                          output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `description` from GHSA (details, else summary)."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    ghsa_res = fetch_json(f"{base_repos}/ghsa_cve/{ctx.year}/{ctx.cve_id}.json")
    _set_description(ctx.data, extract_ghsa_description(ghsa_res), only_if_missing)
    return _close_cve(ctx, save, output_path)


def cvss_from_ghsa(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
                   only_if_missing: bool = False, save: bool = True,
                   output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `cvss` with the GHSA entries (previous "GHSA" entries are replaced,
    entries from other sources are kept). only_if_missing=True mimics the original
    behaviour: only when `cvss` is empty."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    ghsa_res = fetch_json(f"{base_repos}/ghsa_cve/{ctx.year}/{ctx.cve_id}.json")
    _set_cvss(ctx.data, "GHSA", extract_ghsa_cvss(ghsa_res), only_if_missing)
    return _close_cve(ctx, save, output_path)


def product_from_ghsa(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
                      only_if_missing: bool = False, save: bool = True,
                      output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `products` from the GHSA affected package names."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    ghsa_res = fetch_json(f"{base_repos}/ghsa_cve/{ctx.year}/{ctx.cve_id}.json")
    _set_products(ctx.data, extract_ghsa_products(ghsa_res), only_if_missing)
    return _close_cve(ctx, save, output_path)


# --- CISA KEV -----------------------------------------------------------------

def description_from_cisa_kev(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
                              only_if_missing: bool = False, save: bool = True,
                              output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `description` from the CISA KEV short description."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    kev_cols = parse_kev_csv(fetch_text(f"{base_repos}/cisa_kev/data_single/{ctx.year}/{ctx.cve_id}.csv"))
    _set_description(ctx.data, extract_kev_description(kev_cols), only_if_missing)
    return _close_cve(ctx, save, output_path)


def product_from_cisa_kev(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
                          only_if_missing: bool = False, save: bool = True,
                          output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `products` from the CISA KEV vendor/product columns."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    kev_cols = parse_kev_csv(fetch_text(f"{base_repos}/cisa_kev/data_single/{ctx.year}/{ctx.cve_id}.csv"))
    name = extract_kev_product(kev_cols)
    # filter_junk=False: same as the original KEV fallback in process_cve
    _set_products(ctx.data, [name] if name else [], only_if_missing, filter_junk=False)
    return _close_cve(ctx, save, output_path)


def cisa_kev_fields(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
                    save: bool = True, output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `cisa_kev` (in_cisa_kev, added_date and ransomware_campaign_use, which
    comes from the same KEV row). If nothing can be fetched, existing values are kept
    and missing keys get their defaults (False / None / False)."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    kev_cols = parse_kev_csv(fetch_text(f"{base_repos}/cisa_kev/data_single/{ctx.year}/{ctx.cve_id}.csv"))
    fields = extract_kev_fields(kev_cols)
    section = ctx.data.get("cisa_kev")
    section = section if isinstance(section, dict) else {}
    if kev_cols:
        section.update(fields)
    else:
        for k, v in fields.items():
            section.setdefault(k, v)
    ctx.data["cisa_kev"] = section
    return _close_cve(ctx, save, output_path)


# --- Red Hat VEX --------------------------------------------------------------

def description_from_redhat(cve_source: CveSource, *, base_rh: str = DEFAULT_BASE_RH,
                            only_if_missing: bool = False, save: bool = True,
                            output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `description` from the Red Hat VEX description note."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    rh_vex_res = fetch_json(f"{base_rh}/{ctx.year}/{ctx.cve_id.lower()}.json")
    _set_description(ctx.data, extract_redhat_description(rh_vex_res), only_if_missing)
    return _close_cve(ctx, save, output_path)


def cvss_from_redhat(cve_source: CveSource, *, base_rh: str = DEFAULT_BASE_RH,
                     only_if_missing: bool = False, save: bool = True,
                     output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `cvss` with the "RedHat VEX" entries (previous ones are replaced,
    other sources are kept)."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    rh_vex_res = fetch_json(f"{base_rh}/{ctx.year}/{ctx.cve_id.lower()}.json")
    _set_cvss(ctx.data, "RedHat VEX", extract_redhat_cvss(rh_vex_res), only_if_missing)
    return _close_cve(ctx, save, output_path)


def product_from_redhat(cve_source: CveSource, *, base_rh: str = DEFAULT_BASE_RH,
                        only_if_missing: bool = False, save: bool = True,
                        output_path: Optional[str] = None) -> Optional[dict]:
    """Populate `products` from the Red Hat VEX known_affected list."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    rh_vex_res = fetch_json(f"{base_rh}/{ctx.year}/{ctx.cve_id.lower()}.json")
    _set_products(ctx.data, extract_redhat_products(rh_vex_res), only_if_missing)
    return _close_cve(ctx, save, output_path)


# --- PoCs ---------------------------------------------------------------------

def github_pocs(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
                save: bool = True, output_path: Optional[str] = None) -> Optional[dict]:
    """Add new PoCs from PoC-in-GitHub to `pocs`. Existing entries are kept; no duplicates
    (compared ignoring http/https and trailing slashes)."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    poc_res = fetch_json(f"{base_repos}/PoC-in-GitHub/{ctx.year}/{ctx.cve_id}.json")
    _merge_pocs(ctx.data, extract_github_pocs(poc_res))
    return _close_cve(ctx, save, output_path)


def tools_pocs(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
               save: bool = True, output_path: Optional[str] = None) -> Optional[dict]:
    """Add new PoCs from the pocs repo to `pocs`. Existing entries are kept; no duplicates."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    all_pocs_res = fetch_json(f"{base_repos}/pocs/data_single/{ctx.year}/{ctx.cve_id}.json")
    _merge_pocs(ctx.data, extract_tools_pocs(all_pocs_res, ctx.cve_id))
    return _close_cve(ctx, save, output_path)


# --- News ---------------------------------------------------------------------

def news(cve_source: CveSource, *, base_repos: str = DEFAULT_BASE_REPOS,
         save: bool = True, output_path: Optional[str] = None) -> Optional[dict]:
    """Add new articles from the news repo to `news` (deduplicated by link, or by title
    when an article has no link), newest first."""
    ctx = _open_cve(cve_source)
    if ctx is None:
        return None
    news_res = fetch_json(f"{base_repos}/cve_news/cves/{ctx.year}/{ctx.cve_id}.json")
    _merge_news(ctx.data, extract_news(news_res))
    return _close_cve(ctx, save, output_path)


def process_cve(
    cve_input: str, 
    base_repos: str = DEFAULT_BASE_REPOS,
    base_rh: str = DEFAULT_BASE_RH
) -> str:
    # 1. Parsing input
    cve_id = normalize_cve_id(cve_input)
    if not cve_id:
        return json.dumps({"error": "Invalid CVE format"})

    parts = cve_id.split('-')
    year = parts[1]
    id_number = parts[2]
    id_prefix = id_number[:-3] + 'xxx' if len(id_number) > 3 else '0xxx'

    # 2. Fetch URLs
    nvd_res = fetch_json(f"{base_repos}/nvd/cve/{year}/{cve_id}.json")
    epss_res = fetch_text(f"{base_repos}/epss/data_single/{year}/{cve_id}.csv")
    kev_res = fetch_text(f"{base_repos}/cisa_kev/data_single/{year}/{cve_id}.csv")
    poc_res = fetch_json(f"{base_repos}/PoC-in-GitHub/{year}/{cve_id}.json")
    cve_project_res = fetch_json(f"{base_repos}/cvelistV5/cves/{year}/{id_prefix}/{cve_id}.json")
    all_pocs_res = fetch_json(f"{base_repos}/pocs/data_single/{year}/{cve_id}.json")
    news_res = fetch_json(f"{base_repos}/cve_news/cves/{year}/{cve_id}.json")

    kev_cols = parse_kev_csv(kev_res)

    rh_vex_res = None
    ghsa_res = None
    if not nvd_res and not cve_project_res:
        print(f"Checking {cve_id} from RedHat VEX")
        rh_vex_res = fetch_json(f"{base_rh}/{year}/{cve_id.lower()}.json")
        if not rh_vex_res:
            ghsa_res = fetch_json(f"{base_repos}/ghsa_cve/{year}/{cve_id.upper()}.json")
            if not ghsa_res:
                has_poc_github = bool(poc_res and len(poc_res) > 0)
                has_poc_single = bool(all_pocs_res and cve_id in all_pocs_res and len(all_pocs_res[cve_id]) > 0)
                has_news = bool(news_res and len(news_res) > 0)
                if not has_poc_github and not has_poc_single and not has_news:
                    return json.dumps({"error": "CVE Data not found in NVD, CVEProject, RedHat VEX, GHSA, PoCs, or News"})

    cve = nvd_res.get('cve', {}) if nvd_res else {}
    
    # Extract Description
    rh_desc = extract_redhat_description(rh_vex_res)
    ghsa_desc = extract_ghsa_description(ghsa_res)
    
    cve_title = None
    cve_project_desc = None
    if cve_project_res and "containers" in cve_project_res and "cna" in cve_project_res["containers"]:
        cve_title = cve_project_res["containers"]["cna"].get("title", None)
        descs = cve_project_res["containers"]["cna"].get("descriptions", [])
        cve_project_desc = next((d.get("value") for d in descs if d.get("lang") in ('en', 'en-US')), None)
        if not cve_project_desc and descs:
            cve_project_desc = descs[0].get("value")

    if not cve_title:
        for adp in ((cve_project_res or {}).get("containers") or {}).get("adp", []):
            adp_title = adp.get("title", None)
            if adp_title and adp_title.lower().strip() not in ["cve program container", "cisa adp vulnrichment"]:
                cve_title = adp_title
                break
            
    kev_desc = extract_kev_description(kev_cols)
    
    nvd_desc = None
    if "descriptions" in cve and cve["descriptions"]:
        nvd_desc = next((d.get("value") for d in cve["descriptions"] if d.get("lang") == 'en'), None)
        if not nvd_desc:
            nvd_desc = cve["descriptions"][0].get("value")

    description = nvd_desc or cve_project_desc or rh_desc or ghsa_desc or kev_desc or DESCRIPTION_PLACEHOLDER

    # Products extraction
    product_map = {}
    def add_product(name):
        if name:
            product_map[name.lower()] = name

    def process_product(v, p):
        add_product(normalize_product(v, p))

    if cve_project_res and "containers" in cve_project_res and "cna" in cve_project_res["containers"]:
        for a in cve_project_res["containers"]["cna"].get("affected", []):
            if a.get("product") == "n/a" and a.get("vendor") == "n/a":
                continue
            if a.get("vendor") or a.get("product"):
                if a.get("packageName") and a.get("packageName", "").strip() != "":
                    process_product(a.get("vendor", ""), f'{a.get("product", "")} ({a.get("packageName", "")})')
                else:
                    process_product(a.get("vendor", ""), a.get("product", ""))

    if len(product_map) == 0 and "configurations" in cve:
        for node in cve.get("configurations", []):
            for n in node.get("nodes", []):
                for m in n.get("cpeMatch", []):
                    c = m.get("criteria", "").split(':')
                    if len(c) >= 5:
                        process_product(c[3], c[4])

    if len(product_map) == 0:
        for name in extract_redhat_products(rh_vex_res):
            add_product(name)

    if len(product_map) == 0:
        for name in extract_ghsa_products(ghsa_res):
            add_product(name)

    for k in ['n/a', 'unknown', 'n/a n/a', '*', '']:
        if k in product_map:
            del product_map[k]

    if len(product_map) == 0:
        add_product(extract_kev_product(kev_cols))

    display_products_list = sorted(list(product_map.values()), key=str.casefold)
    display_products = ", ".join(display_products_list) if display_products_list else "N/A"

    # Raw Affected Data
    raw_affected = {}
    if cve_project_res and "containers" in cve_project_res and "cna" in cve_project_res["containers"]:
        affected = cve_project_res["containers"]["cna"].get("affected", [])
        filtered = []
        for item in affected:
            is_placeholder = (item.get("product") == "n/a" and item.get("vendor") == "n/a" and 
                              item.get("versions") and len(item["versions"]) == 1 and 
                              item["versions"][0].get("status") == "affected" and 
                              item["versions"][0].get("version") == "n/a")
            if not is_placeholder:
                filtered.append(item)
        if filtered:
            raw_affected["cna_affected"] = filtered

    if "configurations" in cve and cve["configurations"]:
        def remove_matchCriteriaId(obj):
            if isinstance(obj, dict):
                return {k: remove_matchCriteriaId(v) for k, v in obj.items() if k != 'matchCriteriaId'}
            elif isinstance(obj, list):
                return [remove_matchCriteriaId(i) for i in obj]
            return obj
        
        parsed_cpes = remove_matchCriteriaId(cve["configurations"])
        if parsed_cpes:
            raw_affected["nvd_cpes"] = parsed_cpes

    # --- NEW CVSS COLLECTION ---
    all_cvss = []
    seen_cisa_adp_vectors = set()

    def add_cvss(source_name, cvss_data):
        add_cvss_entry(all_cvss, source_name, cvss_data, seen_cisa_adp_vectors)

    # 1. From NVD
    for v_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        for metric in cve.get("metrics", {}).get(v_key, []):
            if "cvssData" in metric:
                provider = metric.get("source", "NVD")
                add_cvss(f"NVD ({provider})", metric["cvssData"])

    # 2. From CVELIST
    if cve_project_res and "containers" in cve_project_res:
        for am in cve_project_res["containers"].get("cna", {}).get("metrics", []):
            cvss_obj = am.get("cvssV4_0") or am.get("cvssV3_1") or am.get("cvssV3_0") or am.get("cvssV2_0")
            if cvss_obj:
                data_copy = dict(cvss_obj)
                data_copy["version"] = cvss_obj.get("version") or ("4.0" if am.get("cvssV4_0") else "3.1" if am.get("cvssV3_1") else "3.0" if am.get("cvssV3_0") else "2.0")
                data_copy["baseSeverity"] = (cvss_obj.get("baseSeverity") or get_cvss_severity(cvss_obj.get("baseScore", 0))).upper()
                add_cvss("CVELIST (CNA)", data_copy)
                
        for adp in cve_project_res["containers"].get("adp", []):
            provider = adp.get("providerMetadata", {}).get("shortName", "ADP")
            for am in adp.get("metrics", []):
                cvss_obj = am.get("cvssV4_0") or am.get("cvssV3_1") or am.get("cvssV3_0") or am.get("cvssV2_0")
                if cvss_obj:
                    data_copy = dict(cvss_obj)
                    data_copy["version"] = cvss_obj.get("version") or ("4.0" if am.get("cvssV4_0") else "3.1" if am.get("cvssV3_1") else "3.0" if am.get("cvssV3_0") else "2.0")
                    data_copy["baseSeverity"] = (cvss_obj.get("baseSeverity") or get_cvss_severity(cvss_obj.get("baseScore", 0))).upper()
                    add_cvss(f"CVELIST ({provider})", data_copy)

    # Goal 4: ONLY check backups if NVD and CVELIST had absolutely no CVSS data
    if not all_cvss:
        # 3. From RedHat
        if not rh_vex_res:
            rh_vex_res = fetch_json(f"{base_rh}/{year}/{cve_id.lower()}.json")
        for entry in extract_redhat_cvss(rh_vex_res):
            add_cvss("RedHat VEX", entry)

        # 4. From GHSA (GitHub Security Advisories)
        if not all_cvss:
            for entry in extract_ghsa_cvss(ghsa_res):
                add_cvss("GHSA", entry)

    m = cve.get("metrics", {})
    # --- END NEW CVSS COLLECTION ---

    # Proceed to select best metric exactly like original
    def get_best_metric(metric_array):
        if not metric_array: return None
        for metric in metric_array:
            if metric.get("type") == "Primary":
                return metric
        return metric_array[0]

    best_metric = (get_best_metric(m.get("cvssMetricV40")) or 
                   get_best_metric(m.get("cvssMetricV31")) or 
                   get_best_metric(m.get("cvssMetricV30")) or 
                   get_best_metric(m.get("cvssMetricV2")))
                   
    data = best_metric.get("cvssData") if best_metric else None
    
    if not data and cve_project_res and "containers" in cve_project_res:
        all_metrics = list(cve_project_res["containers"].get("cna", {}).get("metrics", []))
        for adp in cve_project_res["containers"].get("adp", []):
            all_metrics.extend(adp.get("metrics", []))
            
        for am in all_metrics:
            cvss_obj = am.get("cvssV4_0") or am.get("cvssV3_1") or am.get("cvssV3_0") or am.get("cvssV2_0")
            if cvss_obj:
                data = {
                    "version": cvss_obj.get("version") or ("4.0" if am.get("cvssV4_0") else "3.1" if am.get("cvssV3_1") else "3.0" if am.get("cvssV3_0") else "2.0"),
                    "baseScore": cvss_obj.get("baseScore", 0),
                    "vectorString": cvss_obj.get("vectorString", "N/A"),
                    "baseSeverity": (cvss_obj.get("baseSeverity") or get_cvss_severity(cvss_obj.get("baseScore", 0))).upper(),
                }
                data.update(cvss_obj)
                best_metric = {"type": "Primary", "baseSeverity": data["baseSeverity"], "cvssData": data}
                break

    # (Around line 249 inside best_metric assignment)
    if not data:
        if not rh_vex_res:
            rh_vex_res = fetch_json(f"{base_rh}/{year}/{cve_id.lower()}.json")
        if rh_vex_res and "vulnerabilities" in rh_vex_res and rh_vex_res["vulnerabilities"]:
            scores = rh_vex_res["vulnerabilities"][0].get("scores", [])
            if scores:
                rh_score_obj = scores[0].get("cvss_v3") or scores[0].get("cvss_v4") or scores[0].get("cvss_v2")
                if rh_score_obj:
                    data = reconstruct_nvd_style_data(rh_score_obj)
                    best_metric = {"type": "Primary", "baseSeverity": data["baseSeverity"], "cvssData": data}

    if not data and ghsa_res and ghsa_res.get("severity"):
        ghsa_severity_item = next((s for s in ghsa_res["severity"] if s.get("score", "").startswith("CVSS:4.0")), None)
        if not ghsa_severity_item:
            ghsa_severity_item = ghsa_res["severity"][0]
            
        vector = ghsa_severity_item.get("score", "N/A")
        score = 0
        sev = ghsa_res.get("database_specific", {}).get("severity", "UNKNOWN").upper()
        ghsa_cvss_version = "3.1"
        
        if vector.startswith("CVSS:4.0"):
            # Without CVSS40.js it's hard to get exact cvss4 score, but we try to mock or leave 0 since no standard python built-in
            # According to JS: try/catch. Let's leave score=0 for CVSS:4 fallback as it would fail JS CVSS40 missing
            score = 0.0 # calculateCVSS4BaseScore not fully ported as it's complex JS lib 
            sev = get_cvss_severity(score).upper()
            ghsa_cvss_version = "4.0"
        elif vector.startswith("CVSS:3"):
            score = calculate_cvss3_base_score(vector)
            sev = get_cvss_severity(score).upper()
            ghsa_cvss_version = "3.1"
            
        data = {
            "version": ghsa_cvss_version,
            "baseScore": score,
            "vectorString": vector,
            "baseSeverity": sev
        }
        best_metric = {"type": "Primary", "baseSeverity": sev, "cvssData": data}

    display_score = f"{data['baseScore']:.1f}" if data and data.get("baseScore") is not None else "—"
    raw_sev = (best_metric.get("baseSeverity") if best_metric else None) or (data.get("baseSeverity") if data else None) or "N/A"
    sev = str(raw_sev).upper()
    display_vector = (data.get("vectorString") if data else None) or "N/A"
    
    metrics = {}
    if data:
        fields = []
        if data.get("version") == "4.0":
            fields = ['attackVector', 'attackComplexity', 'attackRequirements', 'privilegesRequired', 'userInteraction', 'vulnConfidentialityImpact', 'vulnIntegrityImpact', 'vulnAvailabilityImpact', 'subConfidentialityImpact', 'subIntegrityImpact', 'subAvailabilityImpact', 'exploitMaturity', 'safety', 'automatable', 'recovery', 'valueDensity', 'vulnerabilityResponseEffort', 'providerUrgency']
        elif data.get("version") in ("3.0", "3.1"):
            fields = ['attackVector', 'attackComplexity', 'privilegesRequired', 'userInteraction', 'scope', 'confidentialityImpact', 'integrityImpact', 'availabilityImpact']
        elif data.get("version") == "2.0":
            fields = ['accessVector', 'accessComplexity', 'authentication', 'confidentialityImpact', 'integrityImpact', 'availabilityImpact']
            
        for f in fields:
            if f in data and data[f] is not None:
                metrics[f] = capitalize(str(data[f]).lower())

    # Weakness Logic
    cwe_list = []
    capec_list = []
    seen_ids = set()
    
    def process_weakness_string(raw_text):
        if not raw_text: return
        matches = re.finditer(r'(CWE|CAPEC)-\d+', raw_text, re.IGNORECASE)
        for match in matches:
            upper_id = match.group(0).upper()
            if upper_id in seen_ids:
                continue
            seen_ids.add(upper_id)
            
            clean_desc = re.sub(r'\(?' + re.escape(upper_id) + r'\)?', '', raw_text, flags=re.IGNORECASE)
            clean_desc = clean_desc.replace('|', ' ').strip()
            clean_desc = re.sub(r'(CWE|CAPEC)-\d+', '', clean_desc, flags=re.IGNORECASE).strip()
            if clean_desc.startswith(':'):
                clean_desc = clean_desc[1:].strip()
                
            item = {
                "id": upper_id,
                "description": clean_desc if len(clean_desc) > 1 else None
            }
            if upper_id.startswith("CWE"):
                cwe_list.append(item)
            else:
                capec_list.append(item)

    if cve_project_res and "containers" in cve_project_res and "cna" in cve_project_res["containers"]:
        for pt in cve_project_res["containers"]["cna"].get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId") or ""
                description_val = desc.get("description") or ""
                if cwe_id.startswith("CWE-") and not description_val.startswith("CWE-"):
                    description_val = cwe_id + " " + description_val
                process_weakness_string(description_val or cwe_id)
                
    if cve_project_res and "containers" in cve_project_res and "adp" in cve_project_res["containers"]:
        for adp in cve_project_res["containers"]["adp"]:
            for pt in adp.get("problemTypes", []):
                for desc in pt.get("descriptions", []):
                    process_weakness_string(desc.get("description") or desc.get("cweId") or "")

    if "weaknesses" in cve:
        for w in cve["weaknesses"]:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                parts = val.split("-")
                process_weakness_string(val + " " + (parts[1] if len(parts)>1 else ""))

    if cve_project_res and "containers" in cve_project_res and "cna" in cve_project_res["containers"]:
        for imp in cve_project_res["containers"]["cna"].get("impacts", []):
            impact_text = (imp.get("descriptions", [{}])[0].get("value") if imp.get("descriptions") else None) or imp.get("capecId") or ""
            process_weakness_string(impact_text)

    if len(seen_ids) == 0 and rh_vex_res and "vulnerabilities" in rh_vex_res and rh_vex_res["vulnerabilities"]:
        rh_cwe = rh_vex_res["vulnerabilities"][0].get("cwe", {})
        if rh_cwe.get("id"):
            process_weakness_string(f"{rh_cwe['id']} {rh_cwe.get('name', '')}")
            
    if len(seen_ids) == 0 and ghsa_res and "database_specific" in ghsa_res and "cwe_ids" in ghsa_res["database_specific"]:
        for cwe in ghsa_res["database_specific"]["cwe_ids"]:
            process_weakness_string(cwe)

    # POCs
    pocs_raw = []
    pocs_raw.extend(extract_github_pocs(poc_res))
    pocs_raw.extend(extract_tools_pocs(all_pocs_res, cve_id))
            
    if "references" in cve:
        for r in cve["references"]:
            if "Exploit" in r.get("tags", []):
                pocs_raw.append(r["url"])
                
    if cve_project_res and "containers" in cve_project_res and "cna" in cve_project_res["containers"]:
        for r in cve_project_res["containers"]["cna"].get("references", []):
            tags = r.get("tags", [])
            if "exploit" in tags or "Exploit" in tags:
                pocs_raw.append(r.get("url"))
                
    if cve_project_res and "containers" in cve_project_res and "adp" in cve_project_res["containers"]:
        for adp in cve_project_res["containers"]["adp"]:
            for r in adp.get("references", []):
                tags = r.get("tags", [])
                if "exploit" in tags or "Exploit" in tags:
                    pocs_raw.append(r.get("url"))
                    
    final_pocs = clean_poc_links(pocs_raw)
    
    # References
    all_refs = list(dict.fromkeys([r["url"] for r in cve.get("references", []) if "url" in r]))
    if rh_vex_res:
        rh_portal_url = f"https://access.redhat.com/security/cve/{cve_id.lower()}"
        if rh_portal_url not in all_refs:
            all_refs.append(rh_portal_url)
    if ghsa_res:
        ghsa_portal_url = f"https://github.com/advisories?query={cve_id.upper()}"
        if ghsa_portal_url not in all_refs:
            all_refs.append(ghsa_portal_url)
            
    clean_refs = [url for url in all_refs if url not in final_pocs]

    # EPSS
    epss_data = {"score": "N/A", "percentile": "N/A"}
    if epss_res:
        lines = epss_res.split('\n')
        for l in lines:
            if l.startswith('CVE'):
                parts = l.split(',')
                if len(parts) > 2:
                    try:
                        epss_data["score"] = float(parts[1])
                        epss_data["percentile"] = float(parts[2])
                    except ValueError:
                        pass
                elif len(parts) > 1:
                    try:
                        epss_data["score"] = float(parts[1])
                    except ValueError:
                        pass
                break
                
    # KEV
    kev_fields = extract_kev_fields(kev_cols)
    is_kev = kev_fields["in_cisa_kev"]
    kev_date = kev_fields["added_date"]
    kev_ransomware = kev_fields["ransomware_campaign_use"]

    # SSVC
    ssvc_vec = "N/A"
    ssvc_meta = {}
    
    ssvc_map = {
        "Exploitation": {"key": "E", "values": {"none": "N", "poc": "P", "active": "A"}},
        "Automatable": {"key": "A", "values": {"no": "N", "yes": "Y"}},
        "Technical Impact": {"key": "T", "values": {"partial": "P", "total": "T"}}
    }
    
    adp_target = None
    if cve_project_res and "containers" in cve_project_res and "adp" in cve_project_res["containers"]:
        for a in cve_project_res["containers"]["adp"]:
            if a.get("title") == "CISA ADP Vulnrichment" or any(m.get("other", {}).get("type") == "ssvc" for m in a.get("metrics", [])):
                adp_target = a
                break
                
    ssvc_data = None
    if adp_target:
        for m_adp in adp_target.get("metrics", []):
            if m_adp.get("other", {}).get("type") == "ssvc":
                ssvc_data = m_adp.get("other", {}).get("content")
                break
                
    if ssvc_data and "options" in ssvc_data:
        parts = []
        for o in ssvc_data["options"]:
            for l, val in o.items():
                current_val = val
                if l == "Exploitation":
                    current_exploit = current_val.lower()
                    if current_exploit == "none" and len(final_pocs) > 0:
                        current_val = "poc"
                    if is_kev and (current_val.lower() == "poc" or current_val.lower() == "none"):
                        current_val = "active"
                        
                ssvc_meta[l] = current_val.capitalize()
                if l in ssvc_map:
                    v_mapped = ssvc_map[l]["values"].get(current_val.lower(), current_val[0].upper())
                    parts.append(f"{ssvc_map[l]['key']}:{v_mapped}")
                    
        role = "CISA" if ssvc_data.get("role") == "CISA Coordinator" else ssvc_data.get("role", "-")
        version = ssvc_data.get("version", "-")
        if parts:
            ssvc_vec = f"{role}:{version}/" + "/".join(parts)
            
    elif data and data.get("vectorString") and data.get("vectorString") not in ("N/A", "Vector N/A"):
        exploitation = "N"
        automatable = "N"
        technical_impact = "P"
        
        if is_kev: exploitation = "A"
        elif len(final_pocs) > 0: exploitation = "P"
        else: exploitation = "N"
        
        av = (data.get("attackVector") or data.get("accessVector") or "").upper()
        pr = (data.get("privilegesRequired") or data.get("authentication") or "").upper()
        ui = (data.get("userInteraction") or "").upper()
        ac = (data.get("attackComplexity") or data.get("accessComplexity") or "").upper()
        
        if av == "NETWORK" and pr in ("NONE", "N") and ui in ("NONE", "") and ac == "LOW":
            automatable = "Y"
            
        ci = (data.get("confidentialityImpact") or "").upper()
        ii = (data.get("integrityImpact") or "").upper()
        if ci in ("HIGH", "COMPLETE") and ii in ("HIGH", "COMPLETE"):
            technical_impact = "T"
            
        exp_label = next((k for k, v in ssvc_map["Exploitation"]["values"].items() if v == exploitation), exploitation)
        auto_label = next((k for k, v in ssvc_map["Automatable"]["values"].items() if v == automatable), automatable)
        tech_label = "total" if technical_impact == "T" else "partial"
        
        ssvc_meta["exploitation"] = capitalize(exp_label)
        ssvc_meta["automatable"] = capitalize(auto_label)
        ssvc_meta["technical_impact"] = capitalize(tech_label)
        ssvc_vec = f"CISA:2.0.3/E:{exploitation}/A:{automatable}/T:{technical_impact}"

    # BOD SLA
    bod_sla_public = "N/A"
    bod_sla_internal = "N/A"
    bod_factors = {}
    
    if ssvc_vec != "N/A":
        auto_status = False
        tech_total = False
        parts = ssvc_vec.split('/')
        for p in parts:
            if p.startswith('A:'):
                auto_status = (p.split(':')[1] == 'Y')
            if p.startswith('T:'):
                tech_total = (p.split(':')[1] == 'T')
                
        def get_bod_sla(is_public, is_k, is_a, is_t):
            if is_k and is_t: return "3 Days + Forensic Triage"
            if is_public:
                if not is_k and is_a and is_t: return "3 Days"
                if not is_k and not is_a and not is_t: return "60 Days"
                return "14 Days"
            else:
                if (is_k and not is_t) or (not is_k and is_a and is_t): return "14 Days"
                if not is_k and not is_a and not is_t: return "Next Upgrade"
                return "60 Days"
                
        bod_sla_public = get_bod_sla(True, is_kev, auto_status, tech_total)
        bod_sla_internal = get_bod_sla(False, is_kev, auto_status, tech_total)
        bod_factors = {
            "in_cisa_kev": "Yes" if is_kev else "No",
            "automatable": "Yes" if auto_status else "No",
            "technical_impact": "Total" if tech_total else "Partial"
        }

    # Publication Date
    nvd_pub_date = "Unpublished"
    if "published" in cve:
        nvd_pub_date = cve["published"].split('T')[0]
        
    cvelist_pub_date = "Unpublished"
    if cve_project_res and "cveMetadata" in cve_project_res and "datePublished" in cve_project_res["cveMetadata"]:
        cvelist_pub_date = cve_project_res["cveMetadata"]["datePublished"].split('T')[0]

    vuln_status = cve_project_res.get("cveMetadata", {}).get("state", "N/A") if cve_project_res else "N/A"

    # News
    articles = extract_news(news_res)

    result = {
        "cve_id": cve_id,
        "status": vuln_status,
        "published_date": {
            "nvd": nvd_pub_date,
            "cveorg": cvelist_pub_date
        },
        "title": cve_title or "N/A",
        "description": description,
        "products": display_products,
        "affected": raw_affected,
        "cvss": all_cvss,
        "epss": epss_data,
        "cwe": cwe_list,
        "capec": capec_list,
        "ssvc": {
            "factors": ssvc_meta
        },
        "bod_sla": {
            "public": bod_sla_public,
            "internal": bod_sla_internal,
            "factors": bod_factors
        },
        "pocs": final_pocs,
        "references": clean_refs,
        "cisa_kev": {
            "in_cisa_kev": is_kev,
            "added_date": kev_date,
            "ransomware_campaign_use": kev_ransomware
        },
        "news": articles
    }
    
    return json.dumps(result)


def update_epss(cve_id: str, epss_score: str, percentile: str, parent_dir: str) -> None:
    """
    Reads the CVE JSON from the proper directory (YYYY/CVE-ID.json) 
    and updates the epss field.
    """
    # Extract the year from the CVE ID (e.g., "CVE-2026-1234" -> "2026")
    year = cve_id.split('-')[1]
    file_path = os.path.join(parent_dir, year, f"{cve_id}.json")
    
    if not os.path.exists(file_path):
        print(f"File not found, creating it: {file_path}")
        cve_json = process_cve(cve_id)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(cve_json)
        return
        
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    # Update the epss object exactly as structured in process_cve
    data["epss"] = {
        "score": float(epss_score),
        "percentile": float(percentile)
    }
    
    # Use the atomic write function already provided in api_builder.py
    if save_cve_data(data, file_path):
        print(f"Successfully updated EPSS for {cve_id}")
    else:
        print(f"Failed to save updated EPSS for {cve_id}")


def fetch_and_process_daily_epss(parent_dir: str) -> None:
    """
    Fetches current and previous day's EPSS data, extracts new entries,
    and processes them based on their existence in the local dataset.
    """
    current_url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    
    # 1. Fetch current EPSS data and capture the redirected URL
    req = urllib.request.Request(current_url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req) as response:
            final_url = response.geturl()
            current_gz = response.read()
    except Exception as e:
        print(f"Failed to fetch current EPSS data: {e}")
        return
        
    current_csv = gzip.decompress(current_gz).decode('utf-8')
    
    # Extract the YYYY-MM-DD date from the redirected URL
    match = re.search(r'epss_scores-(\d{4}-\d{2}-\d{2})\.csv\.gz', final_url)
    if not match:
        print(f"Could not extract date from redirected URL: {final_url}")
        return
        
    current_date_str = match.group(1)
    
    # 2. Calculate the previous date and fetch the previous day's EPSS data
    current_date = datetime.strptime(current_date_str, "%Y-%m-%d")
    prev_date = current_date - timedelta(days=1)
    prev_date_str = prev_date.strftime("%Y-%m-%d")
    
    prev_url = f"https://epss.empiricalsecurity.com/epss_scores-{prev_date_str}.csv.gz"
    
    try:
        req_prev = urllib.request.Request(prev_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req_prev) as response:
            prev_gz = response.read()
        prev_csv = gzip.decompress(prev_gz).decode('utf-8')
    except Exception as e:
        print(f"Failed to fetch previous EPSS data from {prev_url}: {e}")
        return

    # Helper function to parse CSV text into a dictionary, skipping comments
    def parse_epss_csv(csv_text: str) -> dict:
        lines = [line for line in csv_text.splitlines() if not line.startswith('#')]
        reader = csv.DictReader(lines)
        return {row['cve']: (row['epss'], row['percentile']) for row in reader}

    # 3. Un-gz both and parse the CSVs into dictionaries
    current_data = parse_epss_csv(current_csv)
    prev_data = parse_epss_csv(prev_csv)
    
    # 4. Find CVEs that are new or have updated scores/percentiles
    changed_cves = {
        cve: scores for cve, scores in current_data.items() 
        if cve not in prev_data or current_data[cve] != prev_data[cve]
    }
    
    print(f"Found {len(changed_cves)} updated CVEs in the latest EPSS data.")
    
    for cve_id, (epss_score, percentile) in changed_cves.items():
        update_epss(cve_id, epss_score, percentile, parent_dir)
