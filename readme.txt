MCP MULTI-SERVICE SERVER
Qualys WAS · DefectDojo · AppTracker
==================================================

OVERVIEW
--------------------------------------------------
This project implements an MCP (Model Context Protocol) server that exposes
tools for multiple security services:

- Qualys Web Application Scanning (WAS)
- DefectDojo scan import
- AppTracker API inventory and variables
- FastAPI + SSE transport for MCP-compatible clients (LLMs, n8n)

The server allows automation and LLM-driven workflows to:
- Launch and track Qualys WAS scans
- Download Qualys reports and import them into DefectDojo
- Query APIs and variables from AppTracker
- Use a single MCP endpoint for multiple services


ARCHITECTURE
--------------------------------------------------
MCP Client (LLM / n8n)
        |
        |  SSE (MCP)
        v
MCP Multi-Service Server (FastAPI)
        |
        +--> Qualys WAS (XML / REST)
        +--> DefectDojo (REST API)
        +--> AppTracker (OAuth2 / REST)


FEATURES
--------------------------------------------------
Qualys WAS
- Create web applications
- Launch WAS scans
- Check scan status
- Generate XML reports
- Optionally delete scans after completion

DefectDojo
- Import Qualys WAS XML reports
- Auto-create products and engagements

AppTracker
- OAuth2 client-credentials authentication
- List all APIs
- Get API details by ID
- Get API variables
- Search APIs by name or description
- Merge APIs with their variables
- Test API connectivity

MCP
- Tools grouped by prefix:
  * qualys_*
  * dojo_*
  * apptracker_*
- Defensive request parsing (ignores extra fields)
- SSE transport for streaming MCP messages


REQUIREMENTS
--------------------------------------------------
- Python 3.10+
- Qualys WAS account
- DefectDojo instance + API token
- AppTracker credentials (optional)


INSTALLATION
--------------------------------------------------
git clone <repository>
cd mcp-multi-service
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt


ENVIRONMENT VARIABLES
--------------------------------------------------

DefectDojo
DEFECTDOJO_URL=https://defectdojo.example.com
DEFECTDOJO_API_KEY=xxxxxxxxxxxxxxxx

Qualys WAS
QUALYS_BASE_URL=https://qualysapi.qualys.com
QUALYS_USER=your_username
QUALYS_PASS=your_password
WAS_PROFILE_ID=123456
QUALYS_VERIFY_TLS=true   (true | false)

AppTracker (optional)
APPTRACKER_CLIENT_ID=xxxxxxxx
APPTRACKER_CLIENT_SECRET=xxxxxxxx
APPTRACKER_TOKEN_URL=https://apptracker.example.com/oauth/token
APPTRACKER_API_BASE_URL=https://apptracker.example.com/api/

General
PORT=8000
MCP_XML_DIR=/path/to/xml/templates


REQUIRED QUALYS XML TEMPLATES
--------------------------------------------------
The following files MUST exist in MCP_XML_DIR:

- create_webapp.xml
- launch_scan.xml
- create_scan_report_xml.xml
- create_scan_report_pdf.xml

If any are missing, the server will fail at startup.


RUNNING THE SERVER
--------------------------------------------------
python main.py

or

uvicorn main:app --host 0.0.0.0 --port 8000


MCP ENDPOINTS
--------------------------------------------------
SSE Endpoint:
GET  /sse

MCP Message Endpoint:
POST /messages


AVAILABLE MCP TOOLS
--------------------------------------------------

Qualys WAS Tools
- qualys_was_launch_scan
- qualys_was_check_status
- qualys_was_finalize_scan

AppTracker Tools
- apptracker_get_all_apis
- apptracker_get_api_details
- apptracker_get_api_variables
- apptracker_search_apis
- apptracker_get_apis_with_variables
- apptracker_test_connection


EXAMPLE WORKFLOW (QUALYS → DEFECTDOJO)
--------------------------------------------------
1. Launch scan using qualys_was_launch_scan
2. Poll status using qualys_was_check_status
3. Finalize scan using qualys_was_finalize_scan
   - Report is downloaded
   - Findings are imported into DefectDojo
   - Scan may be deleted from Qualys


ERROR HANDLING NOTES
--------------------------------------------------
- AppTracker credentials are optional at startup
- AppTracker tools will fail until credentials are configured
- OAuth token refresh is automatic on 401 responses
- Qualys scan deletion failures return warnings, not fatal errors
- Unknown MCP fields are ignored (n8n compatibility)


SECURITY NOTES
--------------------------------------------------
- Do NOT hardcode secrets
- Use environment variables or a secret manager
- Run behind HTTPS / reverse proxy in production
- Disable TLS verification only for testing


LICENSE
--------------------------------------------------
Internal / Proprietary
(Adjust as required)
