import base64
import os
import sys
import json
import time
import logging
import re
from typing import Any, Dict, List, Optional

import requests
import xml.etree.ElementTree as ET

import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, ConfigDict

# MCP SDK (Official)
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

# PDF text extraction
import io   
import pdfplumber

# =========================================================
# Logging
# =========================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mcp-qualys-defectdojo-apptracker")

# =========================================================
# ENV
# =========================================================
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")

# DefectDojo
DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "").rstrip("/")
DEFECTDOJO_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")

# Qualys
QUALYS_BASE_URL = os.getenv("QUALYS_BASE_URL", "").rstrip("/")
QUALYS_USER = os.getenv("QUALYS_USER", "")
QUALYS_PASS = os.getenv("QUALYS_PASS", "")
WAS_PROFILE_ID = str(os.getenv("WAS_PROFILE_ID", "")).strip()
QUALYS_VERIFY_TLS = os.getenv("QUALYS_VERIFY_TLS", "true").lower() in {"1", "true", "yes"}

# AppTracker
APPTRACKER_CLIENT_ID = os.getenv("APPTRACKER_CLIENT_ID", "")
APPTRACKER_CLIENT_SECRET = os.getenv("APPTRACKER_CLIENT_SECRET", "")
APPTRACKER_TOKEN_URL = os.getenv("APPTRACKER_TOKEN_URL", "")
APPTRACKER_API_BASE_URL = os.getenv("APPTRACKER_API_BASE_URL", "").rstrip("/") + "/"

# XML templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MCP_XML_DIR = os.getenv("MCP_XML_DIR", BASE_DIR)

# Qualys KB enrichment (QID -> CVE)
QUALYS_KB_ENRICH_CVES = os.getenv("QUALYS_KB_ENRICH_CVES", "false").lower() in {"1", "true", "yes"}
QUALYS_KB_PATH = os.getenv("QUALYS_KB_PATH", "/api/2.0/fo/knowledge_base/vuln/")  # classic API
QUALYS_KB_DETAILS = os.getenv("QUALYS_KB_DETAILS", "All")
QUALYS_KB_MAX_IDS_PER_CALL = int(os.getenv("QUALYS_KB_MAX_IDS_PER_CALL", "200"))

# =========================================================
# FastAPI app (ONLY ONCE)
# =========================================================
app = FastAPI(title="MCP Multi-Service (Qualys WAS + DefectDojo + AppTracker)")

@app.middleware("http")
async def require_token(request: Request, call_next):
    # allow health without auth
    if request.url.path in ("/health",):
        return await call_next(request)

    # if token not configured, DO NOT block (useful for local)
    if not MCP_AUTH_TOKEN:
        return await call_next(request)

    token = request.headers.get("x-mcp-token", "")
    if token != MCP_AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return await call_next(request)

@app.get("/health")
async def health_check():
    return {"ok": True, "service": "mcp", "time": int(time.time())}

# =========================================================
# Base model
# =========================================================
class BaseIgnorantModel(BaseModel):
    model_config = ConfigDict(extra="ignore")  # ignore n8n extra keys

# =========================================================
# XML helpers
# =========================================================
def load_xml(name: str) -> str:
    path = os.path.join(MCP_XML_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def render(tpl: str, **kwargs) -> str:
    for k, v in kwargs.items():
        tpl = tpl.replace(f"{{{{{k}}}}}", str(v))
    leftovers = re.findall(r"\{\{[A-Z0-9_]+\}\}", tpl)
    if leftovers:
        raise RuntimeError(f"Unreplaced placeholders: {leftovers}")
    return tpl

def parse_id(xml: bytes) -> str:
    root = ET.fromstring(xml)
    err = root.findtext(".//errorMessage")
    if err:
        raise RuntimeError(err)
    for el in root.findall(".//id"):
        if el.text and el.text.strip().isdigit():
            return el.text.strip()
    raise RuntimeError("No numeric <id> found")

# =========================================================
# Qualys HTTP helpers (blocking)
# =========================================================
def qualys_post(path: str, xml_payload: str) -> bytes:
    if not QUALYS_BASE_URL:
        raise RuntimeError("QUALYS_BASE_URL is missing")
    url = f"{QUALYS_BASE_URL}{path}"
    r = requests.post(
        url,
        data=xml_payload.encode("utf-8") if isinstance(xml_payload, str) else xml_payload,
        auth=(QUALYS_USER, QUALYS_PASS),
        headers={
            "X-Requested-With": "QualysAPI",
            "Content-Type": "application/xml",
            "Accept": "application/xml",
        },
        timeout=180,
        verify=QUALYS_VERIFY_TLS,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Qualys HTTP {r.status_code}: {r.text}")
    return r.content

def qualys_get(url: str) -> bytes:
    r = requests.get(
        url,
        auth=(QUALYS_USER, QUALYS_PASS),
        headers={"X-Requested-With": "QualysAPI"},
        timeout=300,
        verify=QUALYS_VERIFY_TLS,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Qualys HTTP {r.status_code}: {r.text}")
    return r.content

# =========================================================
# Qualys Download PDF report (blocking)
# =========================================================
def qualys_download_pdf_by_report_id(report_id: str) -> bytes:
    return qualys_get(
        f"{QUALYS_BASE_URL}/qps/rest/3.0/download/was/report/{report_id}"
    )

def qualys_download_pdf(scan_id: str, retries: int = 10, wait_sec: int = 15) -> bytes:
    tpl = load_xml("create_scan_report_pdf.xml")
    rep_xml = render(
        tpl,
        REPORT_NAME=f"REPORT-PDF-{scan_id}",
        SCAN_ID=scan_id,
    )

    report_id = parse_id(
        qualys_post("/qps/rest/3.0/create/was/report/", rep_xml)
    )

    for attempt in range(retries):
        try:
            pdf = qualys_get(
                f"{QUALYS_BASE_URL}/qps/rest/3.0/download/was/report/{report_id}"
            )
            return pdf
        except Exception as e:
            if "not yet complete" in str(e):
                logger.info(f"[Qualys] Report not ready, retry {attempt+1}/{retries}")
                time.sleep(wait_sec)
            else:
                raise

    raise RuntimeError("Qualys PDF report not ready after retries")

def qualys_find_webapp_id_by_url(url: str) -> Optional[str]:
    xml = qualys_post(
        "/qps/rest/3.0/search/was/webapp/",
        f"""
        <ServiceRequest>
          <filters>
            <Criteria field="url" operator="EQUALS">{url}</Criteria>
          </filters>
        </ServiceRequest>
        """
    )
    root = ET.fromstring(xml)
    for el in root.findall(".//WebApp/id"):
        if el.text and el.text.strip().isdigit():
            return el.text.strip()
    return None

# =========================================================
# Extract text from PDF (blocking)
# =========================================================
def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    text_parts: List[str] = []
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                text_parts.append(t)
    return "\n".join(text_parts)

def qualys_create_pdf_report(scan_id: str) -> str:
    tpl = load_xml("create_scan_report_pdf.xml")
    rep_xml = render(
        tpl,
        REPORT_NAME=f"REPORT-PDF-{scan_id}",
        SCAN_ID=scan_id,
    )

    report_id = parse_id(
        qualys_post("/qps/rest/3.0/create/was/report/", rep_xml)
    )
    return report_id

# =========================================================
# Qualys KB helpers
# =========================================================
def _chunk_list(items: List[str], size: int) -> List[List[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]

def qualys_kb_qid_to_cves(qids: List[str]) -> Dict[str, List[str]]:
    if not qids:
        return {}

    qids = sorted({q.strip() for q in qids if q and q.strip().isdigit()})
    if not qids:
        return {}

    mapping: Dict[str, List[str]] = {}

    for batch in _chunk_list(qids, max(1, QUALYS_KB_MAX_IDS_PER_CALL)):
        url = f"{QUALYS_BASE_URL}{QUALYS_KB_PATH}"
        params = {
            "action": "list",
            "ids": ",".join(batch),
            "details": QUALYS_KB_DETAILS,
        }

        r = requests.get(
            url,
            params=params,
            auth=(QUALYS_USER, QUALYS_PASS),
            headers={"X-Requested-With": "QualysAPI"},
            timeout=180,
            verify=QUALYS_VERIFY_TLS,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"Qualys KB HTTP {r.status_code}: {r.text}")

        root = ET.fromstring(r.content)

        for vuln in root.findall(".//VULN"):
            qid = (vuln.findtext("QID") or "").strip()
            if not qid:
                continue

            cves: List[str] = []
            for cve_el in vuln.findall(".//CVE_LIST/CVE"):
                if cve_el.text and cve_el.text.strip():
                    cves.append(cve_el.text.strip())

            if cves:
                mapping[qid] = sorted(set(cves))

    return mapping

def extract_qids_from_qualys_was_report(report_xml: bytes) -> List[str]:
    root = ET.fromstring(report_xml)
    qids = []
    for el in root.findall(".//QID"):
        if el.text and el.text.strip().isdigit():
            qids.append(el.text.strip())
    return sorted(set(qids))

def inject_cves_into_qualys_was_report(report_xml: bytes, qid_to_cves: Dict[str, List[str]]) -> bytes:
    root = ET.fromstring(report_xml)

    for parent in root.iter():
        qid_el = parent.find("QID")
        if qid_el is None or not qid_el.text:
            continue
        qid = qid_el.text.strip()
        cves = qid_to_cves.get(qid)
        if not cves:
            continue

        if parent.find("CVE_ID_LIST") is not None:
            continue

        cve_list_el = ET.SubElement(parent, "CVE_ID_LIST")
        for cve in cves:
            ET.SubElement(cve_list_el, "CVE_ID").text = cve

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
def scan_es_valido(report_xml: bytes) -> bool:
    root = ET.fromstring(report_xml)
    return not any(
        el.text == "150111"
        for el in root.findall(".//QID")
        if el.text
    )


# =========================================================
# DefectDojo helper (blocking)
# =========================================================
def dojo_import_scan(xml_bytes: bytes, product: str, engagement: str):
    if not DEFECTDOJO_URL:
        raise RuntimeError("DEFECTDOJO_URL is missing")
    url = f"{DEFECTDOJO_URL}/api/v2/import-scan/"
    r = requests.post(
        url,
        headers={"Authorization": f"Token {DEFECTDOJO_API_KEY}"},
        files={"file": ("scan.xml", xml_bytes)},
        data={
            "scan_type": "Qualys Webapp Scan",
            "product_type_name": "Web Applications",
            "product_name": product,
            "engagement_name": engagement,
            "auto_create_context": "true",
            "environment": "Production",
            "active": "true",
        },
        timeout=300,
    )
    r.raise_for_status()
    return r.json()

# =========================================================
# EPSS + tagging helpers (blocking)
# =========================================================
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

def epss_lookup(cves: List[str]) -> Dict[str, Dict[str, float]]:
    cves = sorted({c.strip().upper() for c in cves if c and _CVE_RE.match(c.strip().upper())})
    if not cves:
        return {}

    url = "https://api.first.org/data/v1/epss"
    out: Dict[str, Dict[str, float]] = {}

    chunk: List[str] = []
    total_len = 0
    for c in cves:
        add_len = len(c) + (1 if chunk else 0)
        if total_len + add_len > 1800:
            r = requests.get(url, params={"cve": ",".join(chunk)}, timeout=60)
            r.raise_for_status()
            data = r.json().get("data", [])
            for row in data:
                k = (row.get("cve") or "").upper()
                if k:
                    out[k] = {"epss": float(row.get("epss", 0.0)), "percentile": float(row.get("percentile", 0.0))}
            chunk, total_len = [], 0
        chunk.append(c)
        total_len += add_len

    if chunk:
        r = requests.get(url, params={"cve": ",".join(chunk)}, timeout=60)
        r.raise_for_status()
        data = r.json().get("data", [])
        for row in data:
            k = (row.get("cve") or "").upper()
            if k:
                out[k] = {"epss": float(row.get("epss", 0.0)), "percentile": float(row.get("percentile", 0.0))}

    return out

def dojo_list_findings_by_test(test_id: int) -> List[Dict[str, Any]]:
    url = f"{DEFECTDOJO_URL}/api/v2/findings/"
    headers = {"Authorization": f"Token {DEFECTDOJO_API_KEY}"}
    findings: List[Dict[str, Any]] = []
    params = {"test": test_id, "limit": 200, "offset": 0}

    while True:
        r = requests.get(url, headers=headers, params=params, timeout=120)
        r.raise_for_status()
        payload = r.json()
        results = payload.get("results", payload if isinstance(payload, list) else [])
        if not results:
            break
        findings.extend(results)
        if not payload.get("next"):
            break
        params["offset"] += params["limit"]

    return findings

def dojo_patch_finding_tags(finding_id: int, new_tags: List[str]) -> None:
    url = f"{DEFECTDOJO_URL}/api/v2/findings/{finding_id}/"
    headers = {"Authorization": f"Token {DEFECTDOJO_API_KEY}"}
    r = requests.patch(url, headers=headers, json={"tags": new_tags}, timeout=60)
    r.raise_for_status()

def epss_band(epss_score: float) -> str:
    if epss_score >= 0.5:
        return "high"
    if epss_score >= 0.1:
        return "medium"
    return "low"

#========================================================
#PDF HELPER
class CreateReportPdfRequest(BaseIgnorantModel):
    scan_id: str

# =========================================================
# AppTracker Client (blocking)
# =========================================================

class AppTrackerAPIClient:
    def __init__(self):
        self.access_token: Optional[str] = None

    def _require_creds(self):
        if not APPTRACKER_CLIENT_ID or not APPTRACKER_CLIENT_SECRET or not APPTRACKER_TOKEN_URL or not APPTRACKER_API_BASE_URL:
            raise RuntimeError("AppTracker env vars missing (CLIENT_ID/SECRET/TOKEN_URL/API_BASE_URL).")

    def obtener_token_acceso(self) -> str:
        self._require_creds()
        r = requests.post(
            APPTRACKER_TOKEN_URL,
            data={"grant_type": "client_credentials"},
            auth=(APPTRACKER_CLIENT_ID, APPTRACKER_CLIENT_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=60,
        )
        if r.status_code != 200:
            raise RuntimeError(f"Error getting token: {r.status_code} - {r.text}")
        token = r.json().get("access_token")
        if not token:
            raise RuntimeError("Token response missing access_token")
        self.access_token = token
        return token

    def get_token(self) -> str:
        return self.access_token or self.obtener_token_acceso()

    def llamar_api(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        token = self.get_token()
        url = f"{APPTRACKER_API_BASE_URL}{endpoint.lstrip('/')}"
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=60)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 401:
            self.access_token = None
            token = self.get_token()
            r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=60)
            if r.status_code == 200:
                return r.json()
        raise RuntimeError(f"API error: {r.status_code} - {r.text}")

    def get_all_apis(self) -> List[Dict[str, Any]]:
        apis_response = self.llamar_api("Api")
        if isinstance(apis_response, dict):
            apis = apis_response.get("data", [apis_response])
        elif isinstance(apis_response, list):
            apis = apis_response
        else:
            apis = []
        return [
            {"apiId": a.get("apiId"), "apiName": a.get("apiName"), "basePath": a.get("basePath"), "description": a.get("description")}
            for a in apis
        ]

    def get_api_by_id(self, api_id: int) -> Any:
        return self.llamar_api(f"Api/GetFullApi/{api_id}")

    def get_api_variables_by_api_id(self, api_id: int) -> List[Dict[str, Any]]:
        resp = self.llamar_api(f"ApiVariable/api/{api_id}")
        if isinstance(resp, dict):
            return resp.get("data", [resp])
        if isinstance(resp, list):
            return resp
        return []

    def get_all_api_variables(self) -> List[Dict[str, Any]]:
        variables_response = self.llamar_api("ApiVariable")
        if isinstance(variables_response, dict):
            return variables_response.get("data", [variables_response])
        if isinstance(variables_response, list):
            return variables_response
        return []

    def get_apis_with_variables(self) -> List[Dict[str, Any]]:
        apis = self.get_all_apis()
        all_vars = self.get_all_api_variables()
        api_vars_map: Dict[Any, List[Dict[str, Any]]] = {}
        for var in all_vars:
            a_id = var.get("apiId")
            if a_id is None:
                continue
            api_vars_map.setdefault(a_id, []).append(var)

        results = []
        for api in apis:
            a_id = api.get("apiId")
            merged = dict(api)
            merged["variables"] = api_vars_map.get(a_id, [])
            merged["hasVariables"] = len(merged["variables"]) > 0
            results.append(merged)
        return results

    def search_apis_by_name(self, search_term: str) -> List[Dict[str, Any]]:
        term = search_term.lower().strip()
        return [
            a for a in self.get_all_apis()
            if term in (a.get("apiName") or "").lower() or term in (a.get("description") or "").lower()
        ]

apptracker_client = AppTrackerAPIClient()

# =========================================================
# MCP request models
# =========================================================
class LaunchScanRequest(BaseIgnorantModel):
    url: str
    webapp_name: str = ""
    scan_name: str = ""
    profile_id: str = ""

class DojoEpssEnrichTestRequest(BaseIgnorantModel):
    test_id: int

class DownloadReportPdfRequest(BaseIgnorantModel):
    report_id: str

class PdfExtractTextRequest(BaseIgnorantModel):
    pdf_base64: str

class CheckStatusRequest(BaseIgnorantModel):
    scan_id: str

class FinalizeScanRequest(BaseIgnorantModel):
    scan_id: str
    product_name: str
    engagement_name: str
    delete_scan: bool = True

class AppTrackerGetAllApisRequest(BaseIgnorantModel):
    limit: Optional[int] = None

class AppTrackerGetApiDetailsRequest(BaseIgnorantModel):
    api_id: int

class AppTrackerGetApiVariablesRequest(BaseIgnorantModel):
    api_id: int

class AppTrackerGetApisWithVariablesRequest(BaseIgnorantModel):
    only_with_variables: bool = False
    limit: Optional[int] = None

class AppTrackerSearchApisRequest(BaseIgnorantModel):
    search_term: str
    limit: Optional[int] = None

# =========================================================
# MCP server
# =========================================================
mcp = Server("mcp-multi-service")

@mcp.list_tools()
async def list_tools() -> List[types.Tool]:
    return [
        # -------- QUALYS --------
        types.Tool(name="qualys_was_launch_scan", description="(Qualys) Launch WAS scan", inputSchema=LaunchScanRequest.model_json_schema()),
        types.Tool(name="qualys_was_check_status", description="(Qualys) Check scan status", inputSchema=CheckStatusRequest.model_json_schema()),
        types.Tool(name="qualys_was_finalize_scan", description="(Qualys+Dojo) Download XML report + upload to Dojo", inputSchema=FinalizeScanRequest.model_json_schema()),
        types.Tool(name="qualys_was_download_report_pdf", description="(Qualys) Generate and download WAS PDF report", inputSchema=DownloadReportPdfRequest.model_json_schema()),
        types.Tool(name="pdf_extract_text", description="Extract plain text from a PDF (base64)", inputSchema=PdfExtractTextRequest.model_json_schema()),
        types.Tool(
    name="qualys_was_create_report_pdf",
    description="(Qualys) Create WAS PDF report and return report_id",
    inputSchema=CreateReportPdfRequest.model_json_schema()
),

        # -------- APPTRACKER --------
        types.Tool(name="apptracker_get_all_apis", description="(AppTracker) List APIs", inputSchema=AppTrackerGetAllApisRequest.model_json_schema()),
        types.Tool(name="apptracker_get_api_details", description="(AppTracker) API details", inputSchema=AppTrackerGetApiDetailsRequest.model_json_schema()),
        types.Tool(name="apptracker_get_api_variables", description="(AppTracker) API variables", inputSchema=AppTrackerGetApiVariablesRequest.model_json_schema()),
        types.Tool(name="apptracker_search_apis", description="(AppTracker) Search APIs", inputSchema=AppTrackerSearchApisRequest.model_json_schema()),
        types.Tool(name="apptracker_get_apis_with_variables", description="(AppTracker) List APIs with variables", inputSchema=AppTrackerGetApisWithVariablesRequest.model_json_schema()),
        types.Tool(name="defectdojo_epss_enrich_test", description="(Dojo+EPSS) For a given test_id: fetch findings, lookup EPSS for CVEs, and tag findings with epss_score/percentile/band", inputSchema=DojoEpssEnrichTestRequest.model_json_schema()),
    ]

@mcp.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]):
    arguments = arguments or {}
    if not isinstance(arguments, dict):
        arguments = dict(arguments)

    # =========================
    # PDF
    # =========================
    if name == "pdf_extract_text":
        args = PdfExtractTextRequest(**arguments)

        def _run():
            pdf_bytes = base64.b64decode(args.pdf_base64)
            text = extract_text_from_pdf(pdf_bytes)
            return {"text": text}

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]
    if name == "qualys_was_create_report_pdf":
        args = CreateReportPdfRequest(**arguments)

        def _run():
            report_id = qualys_create_pdf_report(args.scan_id)
            return {"report_id": report_id}

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]
    if name == "qualys_was_download_report_pdf":
        args = DownloadReportPdfRequest(**arguments)

        def _run():
            pdf_bytes = qualys_download_pdf_by_report_id(args.report_id)
            return {
                "filename": f"qualys_report_{args.report_id}.pdf",
                "pdf_base64": base64.b64encode(pdf_bytes).decode()
            }

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]
    # =========================
    # QUALYS
    # =========================
    if name == "qualys_was_download_report_pdf":
        args = DownloadReportPdfRequest(**arguments)

        def _run():
            pdf_bytes = qualys_download_pdf(args.scan_id)
            return {
                "filename": f"qualys_report_{args.scan_id}.pdf",
                "pdf_base64": base64.b64encode(pdf_bytes).decode()
            }

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]

    if name == "qualys_was_launch_scan":
        args = LaunchScanRequest(**arguments)

        def _run():
        # 1️⃣ Create WebApp
            tpl = load_xml("create_webapp.xml")
            webapp_name = f"{args.webapp_name}-{int(time.time())}"


            webapp_xml = render(
                tpl,
                WEBAPP_NAME=webapp_name,
                WEBAPP_URL=args.url
            )

            webapp_id = qualys_find_webapp_id_by_url(args.url)
            if not webapp_id:
                webapp_id = parse_id(qualys_post("/qps/rest/3.0/create/was/webapp/", webapp_xml))


            # 2️⃣ Launch Scan
            tpl2 = load_xml("launch_scan.xml")

            profile_id = args.profile_id.strip() if args.profile_id and args.profile_id.strip() else None

            profile_xml = (
                f"<profile><id>{profile_id}</id></profile>"
                if profile_id else ""
            )

            scan_xml = render(
                tpl2,
                SCAN_NAME=args.scan_name or f"SCAN-{int(time.time())}",
                WEBAPP_ID=webapp_id,
                PROFILE_XML=profile_xml
            )

            scan_id = parse_id(
                qualys_post("/qps/rest/3.0/launch/was/wasscan/", scan_xml)
            )

            return {
                "webapp_id": webapp_id,
                "scan_id": scan_id,
                "scan_name": args.scan_name,
                "webapp_name": webapp_name
            }

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]


    if name == "qualys_was_check_status":
        args = CheckStatusRequest(**arguments)

        def _run():
            xml = qualys_get(f"{QUALYS_BASE_URL}/qps/rest/3.0/status/was/wasscan/{args.scan_id}")
            root = ET.fromstring(xml)
            status = (root.findtext(".//status") or "").upper()
            return {"scan_id": args.scan_id, "status": status}

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]

    if name == "qualys_was_finalize_scan":
        args = FinalizeScanRequest(**arguments)

        def _run():
            tpl = load_xml("create_scan_report_xml.xml")
            rep_xml = render(tpl, REPORT_NAME=f"REPORT-{args.scan_id}", SCAN_ID=args.scan_id)
            report_id = parse_id(qualys_post("/qps/rest/3.0/create/was/report/", rep_xml))

            report_xml = qualys_get(f"{QUALYS_BASE_URL}/qps/rest/3.0/download/was/report/{report_id}")
            if not scan_es_valido(report_xml):
                raise RuntimeError("Scan FINISHED pero fallido: No Web Service (QID 150111)")


            if QUALYS_KB_ENRICH_CVES:
                qids = extract_qids_from_qualys_was_report(report_xml)
                logger.info(f"[Qualys KB] Extracted {len(qids)} QIDs from WAS report")
                if qids:
                    qid_to_cves = qualys_kb_qid_to_cves(qids)
                    logger.info(f"[Qualys KB] Retrieved CVEs for {len(qid_to_cves)} QIDs from KnowledgeBase")
                    report_xml = inject_cves_into_qualys_was_report(report_xml, qid_to_cves)
                    logger.info(f"[Qualys KB] Injected CVEs into WAS report")

            dojo_resp = dojo_import_scan(report_xml, args.product_name, args.engagement_name)

            delete_warning = None
            if args.delete_scan:
                try:
                    qualys_post(f"/qps/rest/3.0/delete/was/wasscan/{args.scan_id}", "")
                except Exception as e:
                    delete_warning = str(e)

            out = {"status": "COMPLETED", "defectdojo": dojo_resp}
            if delete_warning:
                out["warning"] = f"Delete scan failed: {delete_warning}"
            return out

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]

    # =========================
    # APPTRACKER
    # =========================
    if name == "apptracker_get_all_apis":
        args = AppTrackerGetAllApisRequest(**arguments)

        def _run():
            apis = apptracker_client.get_all_apis()
            if args.limit:
                apis = apis[: args.limit]
            return {"count": len(apis), "apis": apis}

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]

    if name == "apptracker_get_api_details":
        args = AppTrackerGetApiDetailsRequest(**arguments)
        out = await run_in_threadpool(lambda: apptracker_client.get_api_by_id(args.api_id))
        return [types.TextContent(type="text", text=json.dumps(out))]

    if name == "apptracker_get_api_variables":
        args = AppTrackerGetApiVariablesRequest(**arguments)
        out = await run_in_threadpool(lambda: {"api_id": args.api_id, "variables": apptracker_client.get_api_variables_by_api_id(args.api_id)})
        return [types.TextContent(type="text", text=json.dumps(out))]

    if name == "apptracker_get_apis_with_variables":
        args = AppTrackerGetApisWithVariablesRequest(**arguments)

        def _run():
            apis = apptracker_client.get_apis_with_variables()
            if args.only_with_variables:
                apis = [a for a in apis if a.get("hasVariables")]
            if args.limit:
                apis = apis[: args.limit]
            return {"count": len(apis), "apis": apis}

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out, indent=2))]

    if name == "apptracker_search_apis":
        args = AppTrackerSearchApisRequest(**arguments)

        def _run():
            res = apptracker_client.search_apis_by_name(args.search_term)
            if args.limit:
                res = res[: args.limit]
            return {"count": len(res), "results": res}

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]

    # =========================
    # DEFECTDOJO EPSS ENRICH
    # =========================
    if name == "defectdojo_epss_enrich_test":
        args = DojoEpssEnrichTestRequest(**arguments)

        def _run():
            findings = dojo_list_findings_by_test(args.test_id)

            finding_cves: Dict[int, List[str]] = {}
            all_cves: List[str] = []

            for f in findings:
                fid = f.get("id")
                if not fid:
                    continue

                blob = " ".join([
                    json.dumps(f.get("vulnerability_ids", "")),
                    str(f.get("cve", "")),
                    str(f.get("title", "")),
                    str(f.get("description", "")),
                    str(f.get("mitigation", "")),
                ])
                cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(blob)})
                if cves:
                    finding_cves[int(fid)] = cves
                    all_cves.extend(cves)

            epss_map = epss_lookup(all_cves)

            updated = 0
            skipped = 0

            for fid, cves in finding_cves.items():
                scores = [epss_map.get(c, {}).get("epss", 0.0) for c in cves]
                pcts = [epss_map.get(c, {}).get("percentile", 0.0) for c in cves]
                if not scores:
                    skipped += 1
                    continue

                max_score = float(max(scores))
                max_pct = float(max(pcts)) if pcts else 0.0

                tags = [
                    f"epss_score:{max_score:.4f}",
                    f"epss_pct:{max_pct:.4f}",
                    f"epss_band:{epss_band(max_score)}",
                ]

                dojo_patch_finding_tags(fid, tags)
                updated += 1

            return {
                "test_id": args.test_id,
                "findings_total": len(findings),
                "findings_with_cves": len(finding_cves),
                "updated": updated,
                "skipped": skipped,
            }

        out = await run_in_threadpool(_run)
        return [types.TextContent(type="text", text=json.dumps(out))]

    raise ValueError(f"Unknown tool: {name}")

# =========================================================
# MCP SSE transport
# =========================================================
transport = SseServerTransport("/messages")

@app.get("/sse")
async def sse(request: Request):
    async with transport.connect_sse(request.scope, request.receive, request._send) as (r, w):
        await mcp.run(r, w, mcp.create_initialization_options())

@app.post("/messages")
async def messages(request: Request):
    await transport.handle_post_message(request.scope, request.receive, request._send)

# =========================================================
# Main
# =========================================================
if __name__ == "__main__":
    needed = ["create_webapp.xml", "launch_scan.xml", "create_scan_report_xml.xml", "create_scan_report_pdf.xml"]
    missing = [f for f in needed if not os.path.exists(os.path.join(MCP_XML_DIR, f))]
    if missing:
        logger.error(f"Missing XML templates: {missing}")
        sys.exit(1)

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
