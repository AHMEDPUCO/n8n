import os
import sys
import json
import logging
import requests
from typing import Any, Dict, List, Optional  # ✅ we'll use Optional for fields that can be null

import uvicorn
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field, ConfigDict

# Official MCP SDK
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("defectdojo_mcp")

# --- Env ---
DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "https://dojo.usfq.edu.ec")
DEFECTDOJO_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")

# --- 1) Pydantic models that IGNORE extra fields from n8n (sessionId, toolCallId, etc.) ---
class BaseIgnorantModel(BaseModel):
    model_config = ConfigDict(extra="ignore")  # ✅ critical: ignore unknown keys (sessionId, action, etc.)

class ProductVulnRequest(BaseIgnorantModel):
    # ✅ Optional so n8n can send null; we normalize later
    product_id: Optional[Any] = Field(default="", description="The ID of the product")
    product_name: Optional[Any] = Field(default="", description="The name of the product")

class ListEngagementsRequest(BaseIgnorantModel):
    # ✅ Optional so n8n can send null; we normalize later
    product_id: Optional[Any] = Field(default="", description="Filter by product ID")
    status: Optional[Any] = Field(default="", description="Filter by status")

    # ✅ IMPORTANT FIX:
    # n8n often sends limit=null when user doesn't fill it.
    # If we keep limit: str, Pydantic rejects None with: "None is not of type 'string'"
    limit: Optional[Any] = Field(default="50", description="Limit results (string/number/null allowed)")

class ListProductsRequest(BaseIgnorantModel):
    # ✅ IMPORTANT FIX for same reason as above
    limit: Optional[Any] = Field(default="50", description="Limit results (string/number/null allowed)")
    name_contains: Optional[Any] = Field(default="", description="Filter by name containment")

class ProductInfoRequest(BaseIgnorantModel):
    product_id: Optional[Any] = Field(default="", description="The ID of the product")
    product_name: Optional[Any] = Field(default="", description="The name of the product")

# --- 2) MCP Server ---
mcp_server = Server("defectdojo-server")

# --- DefectDojo API helpers ---
def get_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Token {DEFECTDOJO_API_KEY}",
        "Content-Type": "application/json",
    }

def make_api_request(endpoint: str, params: str = "") -> Dict[str, Any]:
    try:
        url = f"{DEFECTDOJO_URL}/api/v2/{endpoint}/{params}"
        logger.info(f"Making request to: {url}")
        r = requests.get(url, headers=get_headers(), timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error(f"API request failed: {str(e)}")
        return {"error": str(e)}

# ✅ Helper to normalize "null" / numbers / empty values into a safe string
def _norm_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    s = str(value).strip()
    return s if s else default

# --- 3) Tools registration ---
@mcp_server.list_tools()
async def list_tools() -> List[types.Tool]:
    return [
        types.Tool(
            name="get_product_vulnerabilities",
            description="Get vulnerability count for a specific product by ID or name",
            inputSchema=ProductVulnRequest.model_json_schema(),
        ),
        types.Tool(
            name="list_engagements",
            description="List engagements with optional filters",
            inputSchema=ListEngagementsRequest.model_json_schema(),
        ),
        types.Tool(
            name="list_products",
            description="List all products with optional name filter",
            inputSchema=ListProductsRequest.model_json_schema(),
        ),
        types.Tool(
            name="get_product_info",
            description="Get detailed information about a specific product including metrics",
            inputSchema=ProductInfoRequest.model_json_schema(),
        ),
    ]

@mcp_server.call_tool()
async def call_tool(name: str, arguments: Any) -> List[types.TextContent]:
    """
    ✅ IMPORTANT:
    n8n injects extra fields (sessionId, toolCallId, action, chatInput, etc.).
    BaseIgnorantModel ignores them safely.
    """
    try:
        if not isinstance(arguments, dict):
            arguments = {} if arguments is None else dict(arguments)

        if name == "get_product_vulnerabilities":
            args = ProductVulnRequest(**arguments)
            result = _logic_get_product_vulnerabilities(args)

        elif name == "list_engagements":
            args = ListEngagementsRequest(**arguments)
            result = _logic_list_engagements(args)

        elif name == "list_products":
            args = ListProductsRequest(**arguments)
            result = _logic_list_products(args)

        elif name == "get_product_info":
            args = ProductInfoRequest(**arguments)
            result = _logic_get_product_info(args)

        else:
            raise ValueError(f"Unknown tool: {name}")

        return [types.TextContent(type="text", text=result)]

    except Exception as e:
        logger.exception(f"Error executing tool {name}")
        return [types.TextContent(type="text", text=f"Error: {str(e)}")]

# --- 4) Business logic ---
def _logic_get_product_vulnerabilities(args: ProductVulnRequest) -> str:
    p_id = _norm_str(args.product_id, "")
    p_name = _norm_str(args.product_name, "")

    if not p_id and not p_name:
        return "Error: Please provide either product_id or product_name"

    if not p_id:
        prods = make_api_request("products", f"?name={p_name}")
        if prods.get("count", 0) == 0:
            return f"No product found with name: {p_name}"
        p_id = str(prods["results"][0]["id"])

    findings_resp = make_api_request("findings", f"?product={p_id}&limit=1000")
    if "error" in findings_resp:
        return f"Error: {findings_resp['error']}"

    findings = findings_resp.get("results", [])
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    active, verified = 0, 0

    for f in findings:
        sev = f.get("severity", "")
        if sev in severity_counts:
            severity_counts[sev] += 1
        if f.get("active"):
            active += 1
        if f.get("verified"):
            verified += 1

    return (
        f"Product ID: {p_id}\n"
        f"Total Findings: {findings_resp.get('count', 0)}\n"
        f"Active: {active}\n"
        f"Verified: {verified}\n\n"
        f"Severity Breakdown:\n{json.dumps(severity_counts, indent=2)}"
    )

def _logic_list_engagements(args: ListEngagementsRequest) -> str:
    # ✅ IMPORTANT FIX: normalize limit when n8n sends null
    limit = _norm_str(args.limit, "50")

    product_id = _norm_str(args.product_id, "")
    status = _norm_str(args.status, "")

    params = f"?limit={limit}"
    if product_id:
        params += f"&product={product_id}"
    if status:
        params += f"&status={status}"

    resp = make_api_request("engagements", params)
    if "error" in resp:
        return f"Error: {resp['error']}"

    res = f"Total Engagements: {resp.get('count', 0)}\n\n"
    for e in resp.get("results", []):
        res += f"ID: {e.get('id')} | Name: {e.get('name')} | Status: {e.get('status')}\n"
    return res

def _logic_list_products(args: ListProductsRequest) -> str:
    # ✅ IMPORTANT FIX: normalize limit when n8n sends null
    limit = _norm_str(args.limit, "50")
    name_contains = _norm_str(args.name_contains, "")

    params = f"?limit={limit}"
    if name_contains:
        params += f"&name__icontains={name_contains}"

    resp = make_api_request("products", params)
    if "error" in resp:
        return f"Error: {resp['error']}"

    res = f"Total Products: {resp.get('count', 0)}\n\n"
    for p in resp.get("results", []):
        res += f"ID: {p.get('id')} | Name: {p.get('name')} | Type: {p.get('prod_type')}\n"
    return res

def _logic_get_product_info(args: ProductInfoRequest) -> str:
    p_id = _norm_str(args.product_id, "")
    p_name = _norm_str(args.product_name, "")

    if not p_id and not p_name:
        return "Error: Please provide either product_id or product_name"

    if not p_id:
        prods = make_api_request("products", f"?name={p_name}")
        if prods.get("count", 0) == 0:
            return f"No product found: {p_name}"
        p_id = str(prods["results"][0]["id"])

    prod = make_api_request("products", p_id)
    if "error" in prod:
        return f"Error: {prod['error']}"

    engs = make_api_request("engagements", f"?product={p_id}")
    finds = make_api_request("findings", f"?product={p_id}&limit=1000")

    return (
        f"ID: {prod.get('id')}\n"
        f"Name: {prod.get('name')}\n"
        f"Description: {prod.get('description', 'N/A')}\n\n"
        f"Total Engagements: {engs.get('count', 0)}\n"
        f"Total Findings: {finds.get('count', 0)}"
    )

# --- 5) FastAPI + SSE transport ---
app = FastAPI(title="DefectDojo MCP Server (Official SDK + SSE)")

transport = SseServerTransport("/messages")

@app.get("/sse")
async def sse_endpoint(request: Request):
    async with transport.connect_sse(request.scope, request.receive, request._send) as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options(),
        )

@app.post("/messages")
async def messages_endpoint(request: Request):
    await transport.handle_post_message(request.scope, request.receive, request._send)

# --- Main ---
if __name__ == "__main__":
    if not DEFECTDOJO_API_KEY:
        logger.error("DEFECTDOJO_API_KEY environment variable not set")
        sys.exit(1)

    port = int(os.getenv("PORT", "8000"))
    logger.info(f"Starting DefectDojo MCP Server on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
