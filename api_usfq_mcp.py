import asyncio
from typing import Any, Dict, List, Optional
import json
import requests
from mcp.server import NotificationOptions, Server
from mcp.server.models import TextContent
import mcp.server.stdio
import mcp.types as types

# Configuración de credenciales
CLIENT_ID = "inventarioapisseguridad_s79ieiu@!lsaopir873rii734s"
CLIENT_SECRET = "owpe883mdooe928mcn55-p4oo0982nnde21-p98i34mcnb4378s-dfg-elkmncv6738iet"

# URLs
TOKEN_URL = "https://wsidentity.usfq.edu.ec/ApiAuthentication/connect/token"
API_BASE_URL = "https://api-app-tracker-devl.usfq.edu.ec/api/"

class AppTrackerAPIClient:
    """Client for interacting with the AppTracker API."""
    
    def __init__(self):
        self.access_token = None
        self.token_expiry = None
    
    def obtener_token_acceso(self):
        """
        Solicita un token de acceso usando el flujo client_credentials de OAuth 2.0.
        """
        data = {
            'grant_type': 'client_credentials'
        }

        response = requests.post(
            TOKEN_URL,
            data=data,
            auth=(CLIENT_ID, CLIENT_SECRET),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        if response.status_code == 200:
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            return self.access_token
        else:
            raise Exception(f"Error al obtener el token: {response.status_code} - {response.text}")
    
    def get_token(self):
        """Get or refresh access token."""
        if not self.access_token:
            return self.obtener_token_acceso()
        return self.access_token
    
    def llamar_api(self, endpoint, params=None):
        """
        Realiza una llamada GET a un endpoint específico de la API protegida.
        """
        token = self.get_token()
        url = f"{API_BASE_URL}{endpoint.lstrip('/')}"
        headers = {
            'Authorization': f'Bearer {token}'
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            # Token might be expired, try to get a new one
            self.access_token = None
            token = self.get_token()
            headers['Authorization'] = f'Bearer {token}'
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"Error en la llamada a la API: {response.status_code} - {response.text}")
        else:
            raise Exception(f"Error en la llamada a la API: {response.status_code} - {response.text}")
    
    def get_all_apis(self):
        """
        Get all APIs from the system.
        Returns list of APIs with id, name, base path, and description.
        """
        try:
            apis_response = self.llamar_api("Api")
            
            # Handle different response formats
            if isinstance(apis_response, dict):
                if 'data' in apis_response:
                    apis = apis_response['data']
                else:
                    apis = [apis_response]
            elif isinstance(apis_response, list):
                apis = apis_response
            else:
                apis = []
            
            # Extract the required fields
            api_list = []
            for api in apis:
                api_info = {
                    "apiId": api.get('apiId'),
                    "apiName": api.get('apiName'),
                    "basePath": api.get('basePath'),
                    "description": api.get('description')
                }
                api_list.append(api_info)
            
            return api_list
            
        except Exception as e:
            raise Exception(f"Error getting APIs: {e}")
    
    def get_api_by_id(self, api_id):
        """
        Get detailed information about a specific API by ID.
        """
        try:
            # Try to get full API details
            api_response = self.llamar_api(f"Api/GetFullApi/{api_id}")
            return api_response
        except Exception as e:
            # Fall back to basic API info
            try:
                apis = self.get_all_apis()
                for api in apis:
                    if api.get('apiId') == api_id:
                        return {"api": api}
            except:
                pass
            raise Exception(f"Error getting API {api_id}: {e}")
    
    def get_all_api_variables(self):
        """
        Get all API variables from the system.
        """
        try:
            variables_response = self.llamar_api("ApiVariable")
            
            # Handle different response formats
            if isinstance(variables_response, dict):
                if 'data' in variables_response:
                    variables = variables_response['data']
                else:
                    variables = [variables_response]
            elif isinstance(variables_response, list):
                variables = variables_response
            else:
                variables = []
            
            return variables
            
        except Exception as e:
            raise Exception(f"Error getting API variables: {e}")
    
    def get_api_variables_by_api_id(self, api_id):
        """
        Get API variables for a specific API ID.
        """
        try:
            variables_response = self.llamar_api(f"ApiVariable/api/{api_id}")
            
            # Handle different response formats
            if isinstance(variables_response, dict):
                if 'data' in variables_response:
                    variables = variables_response['data']
                else:
                    variables = [variables_response]
            elif isinstance(variables_response, list):
                variables = variables_response
            else:
                variables = []
            
            return variables
            
        except Exception as e:
            raise Exception(f"Error getting API variables for API {api_id}: {e}")
    
    def search_apis_by_name(self, search_term):
        """
        Search APIs by name.
        """
        try:
            apis = self.get_all_apis()
            results = []
            search_term_lower = search_term.lower()
            
            for api in apis:
                api_name = api.get('apiName', '').lower()
                description = api.get('description', '').lower()
                
                if (search_term_lower in api_name or 
                    search_term_lower in description):
                    results.append(api)
            
            return results
            
        except Exception as e:
            raise Exception(f"Error searching APIs: {e}")
    
    def get_apis_with_variables(self):
        """
        Get all APIs with their associated variables.
        """
        try:
            # Get all APIs
            apis = self.get_all_apis()
            
            # Get all API variables
            all_variables = self.get_all_api_variables()
            
            # Create mapping of API IDs to variables
            api_variables_map = {}
            for var in all_variables:
                api_id = var.get('apiId')
                if api_id:
                    if api_id not in api_variables_map:
                        api_variables_map[api_id] = []
                    api_variables_map[api_id].append(var)
            
            # Combine API info with variables
            results = []
            for api in apis:
                api_id = api.get('apiId')
                api_with_vars = api.copy()
                api_with_vars['variables'] = api_variables_map.get(api_id, [])
                api_with_vars['hasVariables'] = len(api_with_vars['variables']) > 0
                results.append(api_with_vars)
            
            return results
            
        except Exception as e:
            raise Exception(f"Error getting APIs with variables: {e}")

class AppTrackerMCPServer:
    """MCP Server for AppTracker API."""
    
    def __init__(self):
        self.api_client = AppTrackerAPIClient()
        self.server = Server("app-tracker-mcp")
        
        # Register tools
        self.server.list_tools().callback(self.handle_list_tools)
        self.server.call_tool().callback(self.handle_call_tool)
        
        # Register resources
        self.server.list_resources().callback(self.handle_list_resources)
        self.server.read_resource().callback(self.handle_read_resource)
    
    async def handle_list_tools(self) -> List[types.Tool]:
        """List available tools."""
        return [
            types.Tool(
                name="get_all_apis",
                description="Get all APIs from the system with their basic information",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of APIs to return (default: all)"
                        }
                    }
                }
            ),
            types.Tool(
                name="get_api_details",
                description="Get detailed information about a specific API by ID",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "api_id": {
                            "type": "integer",
                            "description": "The ID of the API to retrieve"
                        }
                    },
                    "required": ["api_id"]
                }
            ),
            types.Tool(
                name="get_api_variables",
                description="Get variables associated with an API",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "api_id": {
                            "type": "integer",
                            "description": "The ID of the API"
                        }
                    },
                    "required": ["api_id"]
                }
            ),
            types.Tool(
                name="search_apis",
                description="Search APIs by name or description",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "search_term": {
                            "type": "string",
                            "description": "Term to search for in API names and descriptions"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results to return"
                        }
                    },
                    "required": ["search_term"]
                }
            ),
            types.Tool(
                name="get_apis_with_variables",
                description="Get all APIs with their associated variables",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of APIs to return"
                        },
                        "only_with_variables": {
                            "type": "boolean",
                            "description": "Only return APIs that have variables"
                        }
                    }
                }
            ),
            types.Tool(
                name="test_connection",
                description="Test the connection to the AppTracker API",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]
    
    async def handle_call_tool(self, name: str, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
        """Handle tool calls."""
        try:
            if name == "get_all_apis":
                return await self.handle_get_all_apis(arguments)
            elif name == "get_api_details":
                return await self.handle_get_api_details(arguments)
            elif name == "get_api_variables":
                return await self.handle_get_api_variables(arguments)
            elif name == "search_apis":
                return await self.handle_search_apis(arguments)
            elif name == "get_apis_with_variables":
                return await self.handle_get_apis_with_variables(arguments)
            elif name == "test_connection":
                return await self.handle_test_connection(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]
    
    async def handle_get_all_apis(self, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
        """Handle get_all_apis tool call."""
        try:
            apis = self.api_client.get_all_apis()
            
            limit = arguments.get('limit') if arguments else None
            if limit:
                apis = apis[:limit]
            
            # Format the response
            if not apis:
                return [types.TextContent(
                    type="text",
                    text="No APIs found."
                )]
            
            result_text = f"Found {len(apis)} APIs:\n\n"
            
            for i, api in enumerate(apis, 1):
                result_text += f"API #{i}:\n"
                result_text += f"  ID: {api.get('apiId')}\n"
                result_text += f"  Name: {api.get('apiName')}\n"
                result_text += f"  Base Path: {api.get('basePath')}\n"
                result_text += f"  Description: {api.get('description') or 'No description'}\n"
                result_text += "\n"
            
            return [types.TextContent(
                type="text",
                text=result_text
            )]
            
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error getting APIs: {str(e)}"
            )]
    
    async def handle_get_api_details(self, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
        """Handle get_api_details tool call."""
        if not arguments or 'api_id' not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: api_id is required"
            )]
        
        try:
            api_id = arguments['api_id']
            api_details = self.api_client.get_api_by_id(api_id)
            
            # Format the response
            result_text = f"API Details (ID: {api_id}):\n\n"
            
            if isinstance(api_details, dict) and 'api' in api_details:
                api = api_details['api']
                result_text += f"Name: {api.get('apiName')}\n"
                result_text += f"Base Path: {api.get('basePath')}\n"
                result_text += f"Description: {api.get('description') or 'No description'}\n"
                result_text += f"Project ID: {api.get('projectId')}\n"
                result_text += f"Version: {api.get('apiVersion') or 'No version'}\n"
                
                # Check for project details
                if 'projectApi' in api_details and api_details['projectApi']:
                    project = api_details['projectApi']
                    result_text += f"\nProject Details:\n"
                    result_text += f"  Name: {project.get('projectName')}\n"
                    result_text += f"  Description: {project.get('description') or 'No description'}\n"
                    result_text += f"  Status: {project.get('status', {}).get('statusName', 'Unknown')}\n"
                    result_text += f"  Environment: {project.get('environment', {}).get('name', 'Unknown')}\n"
            else:
                # Basic API info
                result_text += f"Name: {api_details.get('apiName')}\n"
                result_text += f"Base Path: {api_details.get('basePath')}\n"
                result_text += f"Description: {api_details.get('description') or 'No description'}\n"
            
            return [types.TextContent(
                type="text",
                text=result_text
            )]
            
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error getting API details: {str(e)}"
            )]
    
    async def handle_get_api_variables(self, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
        """Handle get_api_variables tool call."""
        if not arguments or 'api_id' not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: api_id is required"
            )]
        
        try:
            api_id = arguments['api_id']
            variables = self.api_client.get_api_variables_by_api_id(api_id)
            
            # Format the response
            if not variables:
                return [types.TextContent(
                    type="text",
                    text=f"No variables found for API ID {api_id}."
                )]
            
            result_text = f"Found {len(variables)} variables for API ID {api_id}:\n\n"
            
            for i, var in enumerate(variables, 1):
                result_text += f"Variable #{i}:\n"
                result_text += f"  Name: {var.get('variableName', 'Unknown')}\n"
                result_text += f"  Value: {var.get('value', 'N/A')}\n"
                result_text += f"  Variable ID: {var.get('variableId', 'N/A')}\n"
                if var.get('description'):
                    result_text += f"  Description: {var.get('description')}\n"
                result_text += "\n"
            
            return [types.TextContent(
                type="text",
                text=result_text
            )]
            
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error getting API variables: {str(e)}"
            )]
    
    async def handle_search_apis(self, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
        """Handle search_apis tool call."""
        if not arguments or 'search_term' not in arguments:
            return [types.TextContent(
                type="text",
                text="Error: search_term is required"
            )]
        
        try:
            search_term = arguments['search_term']
            results = self.api_client.search_apis_by_name(search_term)
            
            limit = arguments.get('limit')
            if limit:
                results = results[:limit]
            
            # Format the response
            if not results:
                return [types.TextContent(
                    type="text",
                    text=f"No APIs found matching '{search_term}'."
                )]
            
            result_text = f"Found {len(results)} APIs matching '{search_term}':\n\n"
            
            for i, api in enumerate(results, 1):
                result_text += f"API #{i}:\n"
                result_text += f"  ID: {api.get('apiId')}\n"
                result_text += f"  Name: {api.get('apiName')}\n"
                result_text += f"  Base Path: {api.get('basePath')}\n"
                result_text += f"  Description: {api.get('description') or 'No description'}\n"
                result_text += "\n"
            
            return [types.TextContent(
                type="text",
                text=result_text
            )]
            
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error searching APIs: {str(e)}"
            )]
    
    async def handle_get_apis_with_variables(self, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
        """Handle get_apis_with_variables tool call."""
        try:
            apis_with_vars = self.api_client.get_apis_with_variables()
            
            # Apply filters
            only_with_variables = arguments.get('only_with_variables') if arguments else False
            limit = arguments.get('limit') if arguments else None
            
            if only_with_variables:
                apis_with_vars = [api for api in apis_with_vars if api['hasVariables']]
            
            if limit:
                apis_with_vars = apis_with_vars[:limit]
            
            # Format the response
            if not apis_with_vars:
                return [types.TextContent(
                    type="text",
                    text="No APIs found."
                )]
            
            result_text = f"Found {len(apis_with_vars)} APIs:\n\n"
            
            for i, api in enumerate(apis_with_vars, 1):
                result_text += f"API #{i}:\n"
                result_text += f"  ID: {api.get('apiId')}\n"
                result_text += f"  Name: {api.get('apiName')}\n"
                result_text += f"  Base Path: {api.get('basePath')}\n"
                result_text += f"  Has Variables: {'Yes' if api['hasVariables'] else 'No'}\n"
                
                if api['hasVariables']:
                    result_text += f"  Variable Count: {len(api['variables'])}\n"
                    # Show first 2 variables
                    for j, var in enumerate(api['variables'][:2], 1):
                        result_text += f"    Variable {j}: {var.get('variableName', 'Unknown')} = {var.get('value', 'N/A')}\n"
                    if len(api['variables']) > 2:
                        result_text += f"    ... and {len(api['variables']) - 2} more\n"
                
                result_text += "\n"
            
            # Add summary
            total_apis = len(apis_with_vars)
            apis_with_vars_count = sum(1 for api in apis_with_vars if api['hasVariables'])
            
            result_text += f"\nSummary:\n"
            result_text += f"  Total APIs: {total_apis}\n"
            result_text += f"  APIs with variables: {apis_with_vars_count} ({apis_with_vars_count/total_apis*100:.1f}%)\n"
            result_text += f"  APIs without variables: {total_apis - apis_with_vars_count} ({(total_apis - apis_with_vars_count)/total_apis*100:.1f}%)\n"
            
            return [types.TextContent(
                type="text",
                text=result_text
            )]
            
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"Error getting APIs with variables: {str(e)}"
            )]
    
    async def handle_test_connection(self, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
        """Handle test_connection tool call."""
        try:
            # Test by getting a token and making a simple API call
            token = self.api_client.obtener_token_acceso()
            
            # Try to get API count
            apis = self.api_client.get_all_apis()
            
            return [types.TextContent(
                type="text",
                text=f"✅ Connection successful!\n"
                     f"   • Token obtained: Yes\n"
                     f"   • APIs accessible: {len(apis)} found\n"
                     f"   • API Base URL: {API_BASE_URL}"
            )]
            
        except Exception as e:
            return [types.TextContent(
                type="text",
                text=f"❌ Connection failed: {str(e)}"
            )]
    
    async def handle_list_resources(self) -> List[types.Resource]:
        """List available resources."""
        return [
            types.Resource(
                uri="apptracker://apis/summary",
                name="AppTracker APIs Summary",
                description="Summary of all APIs in the AppTracker system",
                mimeType="text/plain"
            ),
            types.Resource(
                uri="apptracker://docs",
                name="AppTracker API Documentation",
                description="Documentation for the AppTracker MCP server",
                mimeType="text/markdown"
            )
        ]
    
    async def handle_read_resource(self, uri: str) -> types.ReadResourceResult:
        """Read a resource."""
        if uri == "apptracker://apis/summary":
            try:
                apis = self.api_client.get_all_apis()
                apis_with_vars = self.api_client.get_apis_with_variables()
                
                apis_with_vars_count = sum(1 for api in apis_with_vars if api['hasVariables'])
                
                content = f"AppTracker APIs Summary\n"
                content += "=" * 50 + "\n\n"
                content += f"Total APIs: {len(apis)}\n"
                content += f"APIs with variables: {apis_with_vars_count}\n"
                content += f"APIs without variables: {len(apis) - apis_with_vars_count}\n\n"
                content += "Sample APIs (first 3):\n"
                content += "-" * 30 + "\n\n"
                
                for i, api in enumerate(apis[:3], 1):
                    content += f"{i}. {api.get('apiName')} (ID: {api.get('apiId')})\n"
                    content += f"   Base Path: {api.get('basePath')}\n"
                    content += f"   Description: {api.get('description') or 'No description'}\n\n"
                
                return types.ReadResourceResult(
                    contents=[types.TextContent(type="text", text=content)]
                )
                
            except Exception as e:
                return types.ReadResourceResult(
                    contents=[types.TextContent(
                        type="text", 
                        text=f"Error generating summary: {str(e)}"
                    )]
                )
        
        elif uri == "apptracker://docs":
            content = """# AppTracker MCP Server Documentation

## Available Tools

### 1. get_all_apis
Get all APIs from the system with their basic information.

**Parameters:**
- `limit` (optional): Maximum number of APIs to return

### 2. get_api_details
Get detailed information about a specific API by ID.

**Parameters:**
- `api_id` (required): The ID of the API to retrieve

### 3. get_api_variables
Get variables associated with an API.

**Parameters:**
- `api_id` (required): The ID of the API

### 4. search_apis
Search APIs by name or description.

**Parameters:**
- `search_term` (required): Term to search for
- `limit` (optional): Maximum number of results

### 5. get_apis_with_variables
Get all APIs with their associated variables.

**Parameters:**
- `limit` (optional): Maximum number of APIs to return
- `only_with_variables` (optional): Only return APIs that have variables

### 6. test_connection
Test the connection to the AppTracker API.

## Available Resources

1. **APIs Summary** (`apptracker://apis/summary`): Overview of all APIs
2. **Documentation** (`apptracker://docs`): This documentation

## Authentication
The server uses OAuth 2.0 client credentials flow to authenticate with the AppTracker API.
"""
            
            return types.ReadResourceResult(
                contents=[types.TextContent(type="text", text=content)]
            )
        
        else:
            raise ValueError(f"Unknown resource URI: {uri}")
    
    async def run(self):
        """Run the MCP server."""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                NotificationOptions(),
            )

async def main():
    """Main entry point."""
    server = AppTrackerMCPServer()
    await server.run()

if __name__ == "__main__":
    asyncio.run(main())