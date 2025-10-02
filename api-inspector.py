from fastapi import FastAPI, Request, HTTPException, Depends, Query
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Dict, Optional, List
import json
import logging
from datetime import datetime, timedelta
import uuid
from pydantic import BaseModel
from collections import defaultdict
import asyncio
import re
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_captures.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Advanced API Call Capture Utility",
    description="A versatile endpoint to capture, analyze, and log any API calls or webhooks with detailed header analysis",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for captured requests (use Redis/DB for production)
captured_requests = []
request_stats = defaultdict(int)
header_stats = defaultdict(int)

class HeaderAnalysis(BaseModel):
    total_headers: int
    standard_headers: Dict[str, str]
    custom_headers: Dict[str, str]
    webhook_headers: Dict[str, str]
    security_headers: Dict[str, str]
    browser_headers: Dict[str, str]
    content_headers: Dict[str, str]
    forwarding_headers: Dict[str, str]

class CapturedRequest(BaseModel):
    id: str
    timestamp: datetime
    method: str
    url: str
    path: str
    query_params: Dict[str, Any]
    headers: Dict[str, str]
    header_analysis: HeaderAnalysis
    body: Optional[Any] = None
    body_size: int
    content_type: str
    client_ip: str
    user_agent: str
    is_webhook: bool
    webhook_type: Optional[str] = None

def analyze_headers(headers: Dict[str, str]) -> HeaderAnalysis:
    """Analyze and categorize headers"""
    
    standard_headers = {}
    custom_headers = {}
    webhook_headers = {}
    security_headers = {}
    browser_headers = {}
    content_headers = {}
    forwarding_headers = {}
    
    # Define header categories
    standard_http_headers = {
        'accept', 'accept-charset', 'accept-encoding', 'accept-language',
        'cache-control', 'connection', 'content-length', 'content-type',
        'date', 'expect', 'from', 'host', 'if-match', 'if-modified-since',
        'if-none-match', 'if-range', 'if-unmodified-since', 'max-forwards',
        'pragma', 'proxy-authorization', 'range', 'referer', 'te', 'upgrade',
        'user-agent', 'via', 'warning'
    }
    
    security_related = {
        'authorization', 'x-api-key', 'x-auth-token', 'x-access-token',
        'x-hub-signature', 'x-hub-signature-256', 'x-webhook-signature',
        'x-stripe-signature', 'x-paypal-transmission-sig'
    }
    
    webhook_patterns = [
        r'^x-github-.*', r'^x-stripe-.*', r'^x-paypal-.*', r'^x-slack-.*',
        r'^x-webhook-.*', r'^webhook-.*', r'^x-.*-event$', r'^x-.*-delivery$'
    ]
    
    browser_related = {
        'user-agent', 'accept', 'accept-language', 'accept-encoding',
        'accept-charset', 'dnt', 'sec-fetch-dest', 'sec-fetch-mode',
        'sec-fetch-site', 'sec-fetch-user', 'upgrade-insecure-requests'
    }
    
    content_related = {
        'content-type', 'content-length', 'content-encoding', 'content-language',
        'content-location', 'content-md5', 'content-range', 'content-disposition'
    }
    
    forwarding_related = {
        'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
        'x-real-ip', 'x-original-forwarded-for', 'x-client-ip',
        'cf-connecting-ip', 'true-client-ip'
    }
    
    for key, value in headers.items():
        key_lower = key.lower()
        
        # Truncate long values for security headers
        display_value = value
        if key_lower in security_related and len(value) > 50:
            display_value = value[:20] + "..." + value[-10:]
        
        # Categorize headers
        if key_lower in security_related:
            security_headers[key] = display_value
        elif key_lower in content_related:
            content_headers[key] = value
        elif key_lower in forwarding_related:
            forwarding_headers[key] = value
        elif key_lower in browser_related:
            browser_headers[key] = value
        elif any(re.match(pattern, key_lower) for pattern in webhook_patterns):
            webhook_headers[key] = value
        elif key_lower.startswith('x-') or key_lower.startswith('custom-'):
            custom_headers[key] = value
        elif key_lower in standard_http_headers:
            standard_headers[key] = value
        else:
            # Default to custom if not recognized
            custom_headers[key] = value
    
    return HeaderAnalysis(
        total_headers=len(headers),
        standard_headers=standard_headers,
        custom_headers=custom_headers,
        webhook_headers=webhook_headers,
        security_headers=security_headers,
        browser_headers=browser_headers,
        content_headers=content_headers,
        forwarding_headers=forwarding_headers
    )

def detect_webhook_type(headers: Dict[str, str], path: str) -> Optional[str]:
    """Detect the type of webhook based on headers and path"""
    
    headers_lower = {k.lower(): v for k, v in headers.items()}
    path_lower = path.lower()
    
    # GitHub
    if 'x-github-event' in headers_lower or 'github' in path_lower:
        return 'GitHub'
    
    # Stripe
    if 'x-stripe-signature' in headers_lower or 'stripe' in path_lower:
        return 'Stripe'
    
    # PayPal
    if any(k.startswith('x-paypal-') for k in headers_lower) or 'paypal' in path_lower:
        return 'PayPal'
    
    # Slack
    if 'x-slack-signature' in headers_lower or 'slack' in path_lower:
        return 'Slack'
    
    # Generic webhook indicators
    if ('x-webhook-signature' in headers_lower or 
        'webhook-signature' in headers_lower or
        'webhook' in path_lower or
        any(k.endswith('-event') for k in headers_lower)):
        return 'Generic Webhook'
    
    return None

async def log_request_details(request: Request, body: bytes = b"") -> CapturedRequest:
    """Extract and log all request details with enhanced header analysis"""
    
    # Parse body based on content type
    parsed_body = None
    body_size = len(body)
    
    if body:
        content_type = request.headers.get("content-type", "").lower()
        try:
            if "application/json" in content_type:
                parsed_body = json.loads(body.decode())
            elif "application/x-www-form-urlencoded" in content_type:
                from urllib.parse import parse_qs
                parsed_body = parse_qs(body.decode())
            elif "multipart/form-data" in content_type:
                parsed_body = f"Multipart form data ({body_size} bytes)"
            elif "text/" in content_type:
                parsed_body = body.decode()
            elif body_size > 1024:  # Large binary data
                parsed_body = f"Binary data ({body_size} bytes) - First 100 bytes: {body[:100].hex()}"
            else:
                parsed_body = body.hex()  # Small binary data as hex
        except Exception as e:
            parsed_body = f"Error parsing body: {str(e)} - Raw (first 200 chars): {body.decode(errors='ignore')[:200]}"
    
    # Analyze headers
    headers_dict = dict(request.headers)
    header_analysis = analyze_headers(headers_dict)
    
    # Detect if this is a webhook
    webhook_type = detect_webhook_type(headers_dict, request.url.path)
    is_webhook = webhook_type is not None
    
    # Create captured request object
    captured_req = CapturedRequest(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(),
        method=request.method,
        url=str(request.url),
        path=request.url.path,
        query_params=dict(request.query_params),
        headers=headers_dict,
        header_analysis=header_analysis,
        body=parsed_body,
        body_size=body_size,
        content_type=request.headers.get("content-type", "not-specified"),
        client_ip=request.client.host if request.client else "unknown",
        user_agent=request.headers.get("user-agent", "unknown"),
        is_webhook=is_webhook,
        webhook_type=webhook_type
    )
    
    # Store in memory (limit to last 500 requests)
    captured_requests.append(captured_req)
    if len(captured_requests) > 500:
        captured_requests.pop(0)
    
    # Update stats
    request_stats[request.method] += 1
    request_stats["total"] += 1
    if is_webhook:
        request_stats["webhooks"] += 1
        if webhook_type:
            request_stats[f"webhook_{webhook_type}"] += 1
    
    # Update header stats
    for header_name in headers_dict.keys():
        header_stats[header_name.lower()] += 1
    
    # Enhanced logging
    logger.info(f"CAPTURED REQUEST: {captured_req.method} {captured_req.path}")
    if captured_req.query_params:
        logger.info(f"Query Parameters: {json.dumps(captured_req.query_params, indent=2)}")
    logger.info(f"Content-Type: {captured_req.content_type}")
    logger.info(f"Body Size: {body_size} bytes")
    logger.info(f"Client IP: {captured_req.client_ip}")
    logger.info(f"User Agent: {captured_req.user_agent}")
    
    if is_webhook:
        logger.info(f"WEBHOOK DETECTED: {webhook_type}")
        logger.info(f"Webhook Headers: {json.dumps(header_analysis.webhook_headers, indent=2)}")
    
    if header_analysis.security_headers:
        logger.info(f"Security Headers: {json.dumps(header_analysis.security_headers, indent=2)}")
    
    logger.info(f"All Headers ({header_analysis.total_headers}): {json.dumps(headers_dict, indent=2)}")
    
    if parsed_body and body_size < 2048:  # Only log small bodies in full
        logger.info(f"Body: {json.dumps(parsed_body, indent=2) if isinstance(parsed_body, (dict, list)) else parsed_body}")
    elif body_size > 0:
        logger.info(f"Body: {body_size} bytes (too large for full logging)")
    
    return captured_req

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with interactive dashboard"""

    recent_requests = captured_requests[-50:] if captured_requests else []

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>API Inspector</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg-primary: #ffffff;
                --bg-secondary: #f8fafc;
                --bg-tertiary: #f1f5f9;
                --bg-hover: #e2e8f0;
                --text-primary: #0f172a;
                --text-secondary: #475569;
                --text-tertiary: #64748b;
                --border-color: #e2e8f0;
                --accent-primary: #3b82f6;
                --accent-secondary: #60a5fa;
                --accent-success: #10b981;
                --accent-warning: #f59e0b;
                --accent-error: #ef4444;
                --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
                --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
                --card-bg: #ffffff;
                --code-bg: #1e293b;
                --code-text: #e2e8f0;
            }}

            [data-theme="dark"] {{
                --bg-primary: #0f172a;
                --bg-secondary: #1e293b;
                --bg-tertiary: #334155;
                --bg-hover: #475569;
                --text-primary: #f1f5f9;
                --text-secondary: #cbd5e1;
                --text-tertiary: #94a3b8;
                --border-color: #334155;
                --card-bg: #1e293b;
                --code-bg: #0f172a;
                --code-text: #e2e8f0;
            }}

            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: var(--bg-secondary);
                color: var(--text-primary);
                line-height: 1.6;
                transition: background-color 0.3s ease, color 0.3s ease;
            }}

            .header {{
                background: var(--card-bg);
                border-bottom: 1px solid var(--border-color);
                padding: 1rem 2rem;
                position: sticky;
                top: 0;
                z-index: 100;
                box-shadow: var(--shadow-sm);
            }}

            .header-content {{
                max-width: 1600px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}

            .logo {{
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }}

            .logo-icon {{
                width: 32px;
                height: 32px;
                background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: bold;
                color: white;
            }}

            .logo-text {{
                font-size: 1.25rem;
                font-weight: 700;
                color: var(--text-primary);
            }}

            .theme-toggle {{
                background: var(--bg-tertiary);
                border: 1px solid var(--border-color);
                padding: 0.5rem 1rem;
                border-radius: 8px;
                cursor: pointer;
                font-size: 0.875rem;
                font-weight: 500;
                color: var(--text-primary);
                transition: all 0.2s ease;
            }}

            .theme-toggle:hover {{
                background: var(--bg-hover);
                transform: translateY(-1px);
            }}

            .container {{
                max-width: 1600px;
                margin: 0 auto;
                padding: 2rem;
            }}

            .card {{
                background: var(--card-bg);
                padding: 1.5rem;
                margin: 1rem 0;
                border-radius: 12px;
                border: 1px solid var(--border-color);
                box-shadow: var(--shadow-sm);
                transition: all 0.3s ease;
            }}

            .card:hover {{
                box-shadow: var(--shadow-md);
            }}

            .card h2 {{
                font-size: 1.125rem;
                font-weight: 600;
                color: var(--text-primary);
                margin-bottom: 1rem;
            }}

            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 1rem;
            }}

            .stat-item {{
                text-align: center;
                padding: 1.5rem;
                background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
                border-radius: 12px;
                color: white;
                box-shadow: var(--shadow-md);
                transition: transform 0.2s ease;
            }}

            .stat-item:hover {{
                transform: translateY(-2px);
            }}

            .stat-item h3 {{
                font-size: 2rem;
                font-weight: 700;
                margin-bottom: 0.25rem;
            }}

            .stat-item p {{
                font-size: 0.875rem;
                opacity: 0.9;
            }}

            .request-list {{
                max-height: 650px;
                overflow-y: auto;
                padding-right: 0.5rem;
            }}

            .request-list::-webkit-scrollbar {{
                width: 8px;
            }}

            .request-list::-webkit-scrollbar-track {{
                background: var(--bg-tertiary);
                border-radius: 4px;
            }}

            .request-list::-webkit-scrollbar-thumb {{
                background: var(--border-color);
                border-radius: 4px;
            }}

            .request-list::-webkit-scrollbar-thumb:hover {{
                background: var(--text-tertiary);
            }}

            .request-item {{
                border-left: 4px solid var(--accent-primary);
                padding: 1rem;
                margin: 0.5rem 0;
                background: var(--bg-tertiary);
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.2s ease;
            }}

            .request-item:hover {{
                background: var(--bg-hover);
                transform: translateX(4px);
            }}

            .request-item.selected {{
                background: var(--accent-primary);
                color: white;
                box-shadow: var(--shadow-md);
            }}

            .request-item.selected small {{
                color: rgba(255, 255, 255, 0.9) !important;
            }}

            .request-item small {{
                color: var(--text-secondary);
                font-size: 0.8125rem;
            }}

            .request-item .timestamp {{
                color: var(--text-tertiary);
                font-size: 0.75rem;
            }}

            .request-item.selected .timestamp {{
                color: rgba(255, 255, 255, 0.8) !important;
            }}

            .webhook {{
                border-left-color: var(--accent-success);
            }}

            .main-content {{
                display: grid;
                grid-template-columns: 1fr 1.5fr;
                gap: 1.5rem;
            }}

            @media (max-width: 1024px) {{
                .main-content {{
                    grid-template-columns: 1fr;
                }}
            }}

            .detail-panel {{
                background: var(--card-bg);
                padding: 1.5rem;
                border-radius: 12px;
                border: 1px solid var(--border-color);
                box-shadow: var(--shadow-sm);
                position: sticky;
                top: 100px;
                max-height: calc(100vh - 120px);
                overflow-y: auto;
            }}

            .detail-panel::-webkit-scrollbar {{
                width: 8px;
            }}

            .detail-panel::-webkit-scrollbar-track {{
                background: var(--bg-tertiary);
                border-radius: 4px;
            }}

            .detail-panel::-webkit-scrollbar-thumb {{
                background: var(--border-color);
                border-radius: 4px;
            }}

            .detail-section {{
                margin-bottom: 1.5rem;
            }}

            .detail-section h3 {{
                font-size: 1rem;
                font-weight: 600;
                color: var(--text-primary);
                margin-bottom: 1rem;
                padding-bottom: 0.5rem;
                border-bottom: 2px solid var(--accent-primary);
            }}

            .detail-grid {{
                display: grid;
                grid-template-columns: auto 1fr;
                gap: 0.75rem 1rem;
                font-size: 0.875rem;
            }}

            .detail-label {{
                font-weight: 600;
                color: var(--text-secondary);
            }}

            .detail-value {{
                color: var(--text-primary);
                word-break: break-all;
            }}

            .badge {{
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 6px;
                font-size: 0.75rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}

            .badge-method {{
                background: var(--accent-primary);
                color: white;
            }}

            .badge-webhook {{
                background: var(--accent-success);
                color: white;
            }}

            .badge-auth {{
                background: var(--accent-warning);
                color: white;
            }}

            .headers-table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 0.875rem;
                margin-top: 1rem;
            }}

            .headers-table th {{
                background: var(--bg-tertiary);
                padding: 0.75rem;
                text-align: left;
                font-weight: 600;
                color: var(--text-primary);
                border-bottom: 2px solid var(--border-color);
            }}

            .headers-table td {{
                padding: 0.75rem;
                border-bottom: 1px solid var(--border-color);
                vertical-align: top;
                color: var(--text-secondary);
            }}

            .headers-table tr:hover {{
                background: var(--bg-tertiary);
            }}

            .header-category {{
                font-size: 0.75rem;
                color: var(--text-tertiary);
                font-style: italic;
                font-weight: 500;
            }}

            pre {{
                background: var(--code-bg);
                color: var(--code-text);
                padding: 1rem;
                border-radius: 8px;
                overflow-x: auto;
                max-height: 400px;
                font-size: 0.875rem;
                font-family: 'JetBrains Mono', 'Courier New', monospace;
                margin: 0.5rem 0;
                border: 1px solid var(--border-color);
            }}

            .no-selection {{
                text-align: center;
                color: var(--text-tertiary);
                padding: 3rem;
            }}

            .method-badge {{
                display: inline-block;
                padding: 0.125rem 0.5rem;
                border-radius: 4px;
                font-size: 0.75rem;
                font-weight: 600;
                margin-right: 0.5rem;
                font-family: 'JetBrains Mono', monospace;
            }}

            .GET {{ background: var(--accent-success); color: white; }}
            .POST {{ background: var(--accent-primary); color: white; }}
            .PUT {{ background: var(--accent-warning); color: white; }}
            .DELETE {{ background: var(--accent-error); color: white; }}
            .PATCH {{ background: #9c27b0; color: white; }}

            .tabs {{
                display: flex;
                gap: 0.5rem;
                border-bottom: 2px solid var(--border-color);
                margin-bottom: 1.5rem;
                padding: 0 0.5rem;
            }}

            .tab {{
                padding: 0.75rem 1.5rem;
                cursor: pointer;
                background: transparent;
                border: none;
                border-bottom: 3px solid transparent;
                font-size: 0.875rem;
                font-weight: 600;
                color: var(--text-secondary);
                transition: all 0.2s ease;
                position: relative;
                bottom: -2px;
            }}

            .tab:hover {{
                color: var(--text-primary);
                background: var(--bg-tertiary);
                border-radius: 8px 8px 0 0;
            }}

            .tab.active {{
                color: var(--accent-primary);
                border-bottom-color: var(--accent-primary);
            }}

            .tab-content {{
                display: none;
            }}

            .tab-content.active {{
                display: block;
                animation: fadeIn 0.3s ease-in;
            }}

            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(10px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}

            .endpoint-card {{
                background: var(--bg-tertiary);
                padding: 1.25rem;
                margin: 1rem 0;
                border-radius: 8px;
                border-left: 4px solid var(--accent-primary);
                transition: all 0.2s ease;
            }}

            .endpoint-card:hover {{
                border-left-width: 6px;
                box-shadow: var(--shadow-sm);
            }}

            .endpoint-title {{
                font-weight: 600;
                color: var(--accent-primary);
                margin-bottom: 0.5rem;
                font-size: 1rem;
            }}

            .endpoint-description {{
                color: var(--text-secondary);
                font-size: 0.875rem;
                margin-bottom: 0.75rem;
            }}

            .code-example {{
                background: var(--code-bg);
                color: var(--code-text);
                padding: 1rem;
                border-radius: 8px;
                font-family: 'JetBrains Mono', 'Courier New', monospace;
                font-size: 0.8125rem;
                overflow-x: auto;
                margin: 0.75rem 0;
                white-space: pre;
                border: 1px solid var(--border-color);
            }}

            pre.code-example {{
                margin-top: 0.75rem;
            }}

            .method-tag {{
                font-family: 'JetBrains Mono', monospace;
            }}

            .endpoint-path {{
                font-family: 'JetBrains Mono', monospace;
                color: var(--text-primary);
                font-size: 0.875rem;
                background: var(--bg-tertiary);
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
            }}

            .help-section {{
                margin-bottom: 2rem;
            }}

            .help-section h3 {{
                color: var(--text-primary);
                border-bottom: 2px solid var(--accent-primary);
                padding-bottom: 0.5rem;
                margin-bottom: 1rem;
                font-weight: 600;
            }}

            .help-section ul {{
                margin-left: 1.5rem;
                color: var(--text-secondary);
            }}

            .help-section li {{
                margin: 0.5rem 0;
            }}

            table.endpoint-table {{
                width: 100%;
                border-collapse: collapse;
                margin: 1rem 0;
                border-radius: 8px;
                overflow: hidden;
            }}

            table.endpoint-table th {{
                background: var(--accent-primary);
                color: white;
                padding: 0.75rem;
                text-align: left;
                font-weight: 600;
                font-size: 0.875rem;
            }}

            table.endpoint-table td {{
                padding: 0.75rem;
                border-bottom: 1px solid var(--border-color);
                color: var(--text-secondary);
                font-size: 0.875rem;
            }}

            table.endpoint-table tr:hover {{
                background: var(--bg-tertiary);
            }}

            table.endpoint-table code {{
                background: var(--bg-tertiary);
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.8125rem;
                color: var(--accent-primary);
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="header-content">
                <div class="logo">
                    <div class="logo-icon">AI</div>
                    <span class="logo-text">API Inspector</span>
                </div>
                <button class="theme-toggle" onclick="toggleTheme()">
                    <span id="theme-icon">🌙</span> Toggle Theme
                </button>
            </div>
        </div>

        <div class="container">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('dashboard')">Dashboard</button>
                <button class="tab" onclick="switchTab('help')">Documentation</button>
            </div>

            <div id="dashboard-tab" class="tab-content active">
            <div class="card">
                <h2>Statistics</h2>
                <div class="stats">
                    <div class="stat-item">
                        <h3>{request_stats.get('total', 0)}</h3>
                        <p>Total Requests</p>
                    </div>
                    <div class="stat-item">
                        <h3>{request_stats.get('webhooks', 0)}</h3>
                        <p>Webhooks</p>
                    </div>
                    <div class="stat-item">
                        <h3>{len(captured_requests)}</h3>
                        <p>Stored Requests</p>
                    </div>
                    <div class="stat-item">
                        <h3>{len(header_stats)}</h3>
                        <p>Unique Headers</p>
                    </div>
                </div>
            </div>

            <div class="main-content">
                <div class="card">
                    <h2>Recent Requests ({len(recent_requests)})</h2>
                    <div class="request-list" id="requestList">
                        {"".join([f'''
                        <div class="request-item {'webhook' if req.is_webhook else ''}" onclick="showDetails('{req.id}')" data-id="{req.id}">
                            <span class="method-badge {req.method}">{req.method}</span>
                            <strong>{req.path}</strong>
                            <span class="timestamp">({req.timestamp.strftime('%H:%M:%S')})</span>
                            {f'<span class="badge badge-webhook">{req.webhook_type}</span>' if req.is_webhook else ''}
                            <br>
                            <small>
                                Headers: {req.header_analysis.total_headers} |
                                Body: {req.body_size} bytes |
                                IP: {req.client_ip}
                            </small>
                        </div>
                        ''' for req in reversed(recent_requests)])}
                    </div>
                </div>

                <div class="detail-panel" id="detailPanel">
                    <div class="no-selection">
                        <p>Select a request from the list to view details</p>
                    </div>
                </div>
            </div>
            </div>

            <div id="help-tab" class="tab-content">
                <div class="card">
                    <h2>Documentation & Examples</h2>

                    <div class="help-section">
                        <h3>Quick Start</h3>
                        <p>API Inspector captures and analyzes HTTP requests and webhooks. Point any API client or webhook provider to the capture endpoints below.</p>
                    </div>

                    <div class="help-section">
                        <h3>Capture Endpoints</h3>
                        <table class="endpoint-table">
                            <thead>
                                <tr>
                                    <th>Endpoint</th>
                                    <th>Methods</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><code>/capture/{{path:path}}</code></td>
                                    <td><span class="method-tag GET">ALL</span></td>
                                    <td>Main capture endpoint - accepts any HTTP method and path</td>
                                </tr>
                                <tr>
                                    <td><code>/webhook</code> or <code>/webhook/{{path:path}}</code></td>
                                    <td><span class="method-tag GET">ALL</span></td>
                                    <td>Dedicated webhook capture with enhanced detection</td>
                                </tr>
                            </tbody>
                        </table>

                        <div class="endpoint-card">
                            <div class="endpoint-title">Example: Basic API Call Capture</div>
                            <div class="endpoint-description">Capture a simple GET request with custom headers</div>
                            <pre class="code-example">curl "http://localhost:8000/capture/test-endpoint?param=value" \\
  -H "Authorization: Bearer my-token" \\
  -H "X-Custom-Header: test-value"</pre>
                        </div>

                        <div class="endpoint-card">
                            <div class="endpoint-title">Example: POST with JSON Body</div>
                            <div class="endpoint-description">Capture a POST request with JSON payload</div>
                            <pre class="code-example">curl -X POST "http://localhost:8000/capture/api/endpoint" \\
  -H "Content-Type: application/json" \\
  -d '{{"key": "value", "test": true}}'</pre>
                        </div>

                        <div class="endpoint-card">
                            <div class="endpoint-title">Example: GitHub Webhook Simulation</div>
                            <div class="endpoint-description">Simulate a GitHub webhook event</div>
                            <pre class="code-example">curl -X POST "http://localhost:8000/webhook/github" \\
  -H "X-GitHub-Event: push" \\
  -H "X-GitHub-Delivery: 12345-67890" \\
  -H "X-Hub-Signature-256: sha256=abc123..." \\
  -H "Content-Type: application/json" \\
  -d '{{"ref": "refs/heads/main", "repository": {{"name": "test-repo"}}}}'</pre>
                        </div>
                    </div>

                    <div class="help-section">
                        <h3>Admin & Monitoring Endpoints</h3>
                        <table class="endpoint-table">
                            <thead>
                                <tr>
                                    <th>Endpoint</th>
                                    <th>Method</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><code>/</code></td>
                                    <td><span class="method-tag GET">GET</span></td>
                                    <td>Interactive web dashboard (this page)</td>
                                </tr>
                                <tr>
                                    <td><code>/health</code></td>
                                    <td><span class="method-tag GET">GET</span></td>
                                    <td>Health check with system information</td>
                                </tr>
                                <tr>
                                    <td><code>/admin/monitor</code></td>
                                    <td><span class="method-tag GET">GET</span></td>
                                    <td>Real-time monitoring with live stats</td>
                                </tr>
                                <tr>
                                    <td><code>/admin/captured</code></td>
                                    <td><span class="method-tag GET">GET</span></td>
                                    <td>View all captured requests with filtering</td>
                                </tr>
                                <tr>
                                    <td><code>/admin/stats</code></td>
                                    <td><span class="method-tag GET">GET</span></td>
                                    <td>Comprehensive statistics and analytics</td>
                                </tr>
                                <tr>
                                    <td><code>/admin/headers/{{request_id}}</code></td>
                                    <td><span class="method-tag GET">GET</span></td>
                                    <td>Detailed header analysis for specific request</td>
                                </tr>
                                <tr>
                                    <td><code>/admin/search?q={{term}}</code></td>
                                    <td><span class="method-tag GET">GET</span></td>
                                    <td>Search through captured requests</td>
                                </tr>
                                <tr>
                                    <td><code>/admin/export?format={{json|csv}}</code></td>
                                    <td><span class="method-tag GET">GET</span></td>
                                    <td>Export captured data</td>
                                </tr>
                                <tr>
                                    <td><code>/admin/clear</code></td>
                                    <td><span class="method-tag DELETE">DELETE</span></td>
                                    <td>Clear all captured requests</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="help-section">
                        <h3>Usage Examples</h3>

                        <div class="endpoint-card">
                            <div class="endpoint-title">View Captured Requests</div>
                            <pre class="code-example"># Get all captured requests (default limit: 50)
curl http://localhost:8000/admin/captured

# Filter by HTTP method
curl "http://localhost:8000/admin/captured?method=POST&limit=10"

# Show only webhooks from the last hour
curl "http://localhost:8000/admin/captured?webhook_only=true&since_minutes=60"</pre>
                        </div>

                        <div class="endpoint-card">
                            <div class="endpoint-title">Search Captured Requests</div>
                            <pre class="code-example"># Search for specific content in headers
curl "http://localhost:8000/admin/search?q=github&field=headers"

# Search in request body
curl "http://localhost:8000/admin/search?q=payment&field=body"

# Search everywhere
curl "http://localhost:8000/admin/search?q=api-key&field=all"</pre>
                        </div>

                        <div class="endpoint-card">
                            <div class="endpoint-title">Export Data</div>
                            <pre class="code-example"># Export as JSON
curl "http://localhost:8000/admin/export?format=json" > captures.json

# Export as CSV without request bodies
curl "http://localhost:8000/admin/export?format=csv&include_bodies=false" > captures.csv</pre>
                        </div>

                        <div class="endpoint-card">
                            <div class="endpoint-title">Replay Captured Request</div>
                            <pre class="code-example"># Replay a captured request to your actual API
curl -X POST "http://localhost:8000/admin/replay/{{request_id}}" \\
  -H "Content-Type: application/json" \\
  -d '{{"target_url": "https://api.example.com/endpoint"}}'</pre>
                        </div>
                    </div>

                    <div class="help-section">
                        <h3>Webhook Detection</h3>
                        <p>API Inspector automatically detects and identifies webhooks from popular services:</p>
                        <ul>
                            <li><strong>GitHub</strong> - Identifies via <code>X-GitHub-Event</code> header</li>
                            <li><strong>Stripe</strong> - Identifies via <code>X-Stripe-Signature</code> header</li>
                            <li><strong>PayPal</strong> - Identifies via <code>X-PayPal-*</code> headers</li>
                            <li><strong>Slack</strong> - Identifies via <code>X-Slack-Signature</code> header</li>
                            <li><strong>Generic Webhooks</strong> - Identifies via common webhook patterns</li>
                        </ul>
                    </div>

                    <div class="help-section">
                        <h3>Header Analysis</h3>
                        <p>Headers are automatically categorized into:</p>
                        <ul>
                            <li><strong>Standard HTTP Headers</strong> - Content-Type, Accept, User-Agent, etc.</li>
                            <li><strong>Security Headers</strong> - Authorization, X-API-Key, X-Hub-Signature, etc.</li>
                            <li><strong>Webhook Headers</strong> - X-GitHub-Event, X-Stripe-Signature, etc.</li>
                            <li><strong>Custom Headers</strong> - X-* and Custom-* prefixed headers</li>
                            <li><strong>Browser Headers</strong> - Accept-Language, DNT, Sec-Fetch-* headers</li>
                            <li><strong>Content Headers</strong> - Content-Type, Content-Length, Content-Encoding, etc.</li>
                            <li><strong>Forwarding Headers</strong> - X-Forwarded-For, X-Real-IP, CF-Connecting-IP, etc.</li>
                        </ul>
                    </div>

                    <div class="help-section">
                        <h3>Configuration</h3>
                        <p>Current system configuration:</p>
                        <ul>
                            <li><strong>Max Stored Requests:</strong> 500 (automatically rotates oldest)</li>
                            <li><strong>Log File:</strong> api_captures.log</li>
                            <li><strong>Max Body Log Size:</strong> 2048 bytes (larger bodies truncated in logs)</li>
                            <li><strong>Host:</strong> 0.0.0.0 (all interfaces)</li>
                            <li><strong>Port:</strong> 8000</li>
                        </ul>
                    </div>

                    <div class="help-section">
                        <h3>API Documentation</h3>
                        <p>For complete interactive API documentation, visit:</p>
                        <ul>
                            <li><a href="/docs" target="_blank">Swagger UI - /docs</a></li>
                            <li><a href="/redoc" target="_blank">ReDoc - /redoc</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <script>
            // Theme toggle functionality
            function toggleTheme() {{
                const html = document.documentElement;
                const currentTheme = html.getAttribute('data-theme');
                const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
                const icon = document.getElementById('theme-icon');

                html.setAttribute('data-theme', newTheme);
                localStorage.setItem('theme', newTheme);

                icon.textContent = newTheme === 'dark' ? '☀️' : '🌙';
            }}

            // Load saved theme on page load
            document.addEventListener('DOMContentLoaded', () => {{
                const savedTheme = localStorage.getItem('theme') || 'light';
                const icon = document.getElementById('theme-icon');
                document.documentElement.setAttribute('data-theme', savedTheme);
                icon.textContent = savedTheme === 'dark' ? '☀️' : '🌙';
            }});

            function switchTab(tabName) {{
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(content => {{
                    content.classList.remove('active');
                }});
                document.querySelectorAll('.tab').forEach(tab => {{
                    tab.classList.remove('active');
                }});

                // Show selected tab
                document.getElementById(tabName + '-tab').classList.add('active');
                event.target.classList.add('active');
            }}
        </script>

        <script>
            let selectedRequestId = null;

            async function showDetails(requestId) {{
                // Update selected state
                document.querySelectorAll('.request-item').forEach(item => {{
                    item.classList.remove('selected');
                }});
                document.querySelector(`[data-id="${{requestId}}"]`).classList.add('selected');

                selectedRequestId = requestId;

                // Fetch details
                const response = await fetch(`/admin/headers/${{requestId}}`);
                const data = await response.json();

                // Render details
                renderDetails(data);
            }}

            function renderDetails(data) {{
                const panel = document.getElementById('detailPanel');

                const webhookBadge = data.is_webhook ?
                    `<span class="badge badge-webhook">${{data.webhook_type}}</span>` : '';

                const authBadge = data.header_analysis.security_headers &&
                    Object.keys(data.header_analysis.security_headers).length > 0 ?
                    '<span class="badge badge-auth">Has Auth</span>' : '';

                // Build headers table by category
                let headersHtml = '';
                const categories = [
                    {{ key: 'security_headers', label: 'Security', color: '#ff9800' }},
                    {{ key: 'webhook_headers', label: 'Webhook', color: '#4caf50' }},
                    {{ key: 'content_headers', label: 'Content', color: '#2196f3' }},
                    {{ key: 'forwarding_headers', label: 'Forwarding', color: '#9c27b0' }},
                    {{ key: 'browser_headers', label: 'Browser', color: '#607d8b' }},
                    {{ key: 'standard_headers', label: 'Standard', color: '#795548' }},
                    {{ key: 'custom_headers', label: 'Custom', color: '#f44336' }}
                ];

                categories.forEach(cat => {{
                    const headers = data.header_analysis[cat.key];
                    if (headers && Object.keys(headers).length > 0) {{
                        Object.entries(headers).forEach(([key, value]) => {{
                            headersHtml += `
                                <tr>
                                    <td><strong>${{key}}</strong><br><span class="header-category" style="color: ${{cat.color}}">${{cat.label}}</span></td>
                                    <td style="word-break: break-all;">${{value}}</td>
                                </tr>
                            `;
                        }});
                    }}
                }});

                // Format body
                let bodyHtml = '';
                if (data.insights && data.insights.content_type) {{
                    const contentType = data.insights.content_type;
                    // Get body from raw_headers endpoint
                    fetch(`/admin/captured?limit=1`).then(r => r.json()).then(capturedData => {{
                        // Find the matching request
                        const matchingReq = capturedData.requests.find(r => r.id === data.request_id);
                        if (matchingReq && matchingReq.body) {{
                            let bodyContent = matchingReq.body;
                            if (typeof bodyContent === 'object') {{
                                bodyContent = JSON.stringify(bodyContent, null, 2);
                            }}
                            document.getElementById('bodyContent').innerHTML = `<pre>${{bodyContent}}</pre>`;
                        }}
                    }});
                }}

                // Format query parameters
                let queryParamsHtml = '';
                if (data.query_params && Object.keys(data.query_params).length > 0) {{
                    queryParamsHtml = '<pre>' + JSON.stringify(data.query_params, null, 2) + '</pre>';
                }} else {{
                    queryParamsHtml = '<em style="color: var(--text-tertiary);">No query parameters</em>';
                }}

                panel.innerHTML = `
                    <div class="detail-section">
                        <h3>Request Details</h3>
                        <div class="detail-grid">
                            <span class="detail-label">Method:</span>
                            <span class="detail-value">
                                <span class="badge badge-method">${{data.method}}</span>
                                ${{webhookBadge}}
                                ${{authBadge}}
                            </span>

                            <span class="detail-label">Path:</span>
                            <span class="detail-value">${{data.path}}</span>

                            <span class="detail-label">Timestamp:</span>
                            <span class="detail-value">${{new Date(data.timestamp).toLocaleString()}}</span>

                            <span class="detail-label">Content-Type:</span>
                            <span class="detail-value">${{data.insights.content_type || 'Not specified'}}</span>

                            <span class="detail-label">Client IP:</span>
                            <span class="detail-value">${{data.raw_headers.host || 'Unknown'}}</span>
                        </div>
                    </div>

                    <div class="detail-section">
                        <h3>Query Parameters</h3>
                        ${{queryParamsHtml}}
                    </div>

                    <div class="detail-section">
                        <h3>Headers (${{data.header_analysis.total_headers}} total)</h3>
                        <table class="headers-table">
                            <thead>
                                <tr>
                                    <th>Header Name</th>
                                    <th>Value</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${{headersHtml}}
                            </tbody>
                        </table>
                    </div>

                    <div class="detail-section">
                        <h3>Request Body</h3>
                        <div id="bodyContent">
                            <em style="color: #999;">Loading body...</em>
                        </div>
                    </div>

                    <div class="detail-section">
                        <h3>Insights</h3>
                        <div class="detail-grid">
                            <span class="detail-label">Has Authentication:</span>
                            <span class="detail-value">${{data.insights.has_authentication ? 'Yes' : 'No'}}</span>

                            <span class="detail-label">Custom Headers:</span>
                            <span class="detail-value">${{data.insights.has_custom_headers ? 'Yes' : 'No'}}</span>

                            <span class="detail-label">Forwarded Request:</span>
                            <span class="detail-value">${{data.insights.forwarded_request ? 'Yes' : 'No'}}</span>

                            <span class="detail-label">Likely Browser:</span>
                            <span class="detail-value">${{data.insights.likely_browser ? 'Yes' : 'No'}}</span>
                        </div>
                    </div>
                `;

                // Fetch and display body
                fetch(`/admin/captured?limit=500`).then(r => r.json()).then(capturedData => {{
                    const matchingReq = capturedData.requests.find(r => r.id === data.request_id);
                    if (matchingReq && matchingReq.body) {{
                        let bodyContent = matchingReq.body;
                        if (typeof bodyContent === 'object') {{
                            bodyContent = JSON.stringify(bodyContent, null, 2);
                        }}
                        document.getElementById('bodyContent').innerHTML = `<pre>${{bodyContent}}</pre>`;
                    }} else {{
                        document.getElementById('bodyContent').innerHTML = '<em style="color: #999;">No body content</em>';
                    }}
                }});
            }}

            // Auto-refresh request list every 30 seconds (but preserve selection)
            setInterval(() => {{
                const currentSelected = selectedRequestId;
                fetch('/admin/captured?limit=50').then(r => r.json()).then(data => {{
                    // Update list without full page reload
                    // For now, just reload if no selection
                    if (!currentSelected) {{
                        location.reload();
                    }}
                }});
            }}, 30000);
        </script>
    </body>
    </html>
    """
    return html_content

# Catch-all endpoint for capturing any request
@app.api_route("/capture/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"])
async def capture_request(request: Request, path: str):
    """Capture any HTTP request sent to /capture/* paths"""
    
    # Read request body
    body = await request.body()
    
    # Log the request
    captured_req = await log_request_details(request, body)
    
    # Return a detailed response
    response_data = {
        "status": "captured",
        "request_id": captured_req.id,
        "timestamp": captured_req.timestamp.isoformat(),
        "message": f"Successfully captured {request.method} request to {path}",
        "analysis": {
            "is_webhook": captured_req.is_webhook,
            "webhook_type": captured_req.webhook_type,
            "body_size": captured_req.body_size,
            "header_count": captured_req.header_analysis.total_headers,
            "has_auth": bool(captured_req.header_analysis.security_headers),
            "client_ip": captured_req.client_ip
        },
        "echo": {
            "method": captured_req.method,
            "path": path,
            "query_params": captured_req.query_params,
            "headers": captured_req.headers,
            "body": captured_req.body if captured_req.body_size < 1024 else f"Body too large ({captured_req.body_size} bytes)"
        }
    }
    
    return JSONResponse(content=response_data, status_code=200)

# Alternative webhook endpoint
@app.api_route("/webhook", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.api_route("/webhook/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def webhook_capture(request: Request, path: str = ""):
    """Dedicated webhook capture endpoint"""
    body = await request.body()
    captured_req = await log_request_details(request, body)
    
    return {
        "webhook_received": True,
        "request_id": captured_req.id,
        "timestamp": captured_req.timestamp.isoformat(),
        "webhook_type": captured_req.webhook_type,
        "path": path or "root",
        "analysis": {
            "detected_type": captured_req.webhook_type,
            "security_headers": list(captured_req.header_analysis.security_headers.keys()),
            "webhook_headers": list(captured_req.header_analysis.webhook_headers.keys()),
            "body_size": captured_req.body_size
        }
    }

# Admin endpoints for viewing captured data
@app.get("/admin/captured")
async def get_captured_requests(
    limit: int = Query(50, description="Number of requests to return"),
    method: Optional[str] = Query(None, description="Filter by HTTP method"),
    webhook_only: bool = Query(False, description="Show only webhooks"),
    since_minutes: Optional[int] = Query(None, description="Show requests from last N minutes")
):
    """View captured requests with advanced filtering"""
    
    requests_to_show = captured_requests.copy()
    
    # Apply time filter
    if since_minutes:
        cutoff_time = datetime.now() - timedelta(minutes=since_minutes)
        requests_to_show = [req for req in requests_to_show if req.timestamp >= cutoff_time]
    
    # Apply method filter
    if method:
        requests_to_show = [req for req in requests_to_show if req.method.upper() == method.upper()]
    
    # Apply webhook filter
    if webhook_only:
        requests_to_show = [req for req in requests_to_show if req.is_webhook]
    
    # Apply limit
    requests_to_show = requests_to_show[-limit:]
    
    return {
        "total_captured": len(captured_requests),
        "filtered_total": len(requests_to_show),
        "filters_applied": {
            "method": method,
            "webhook_only": webhook_only,
            "since_minutes": since_minutes,
            "limit": limit
        },
        "requests": [req.dict() for req in requests_to_show]
    }

@app.get("/admin/stats")
async def get_detailed_stats():
    """Get comprehensive statistics"""
    
    # Calculate time-based stats
    now = datetime.now()
    last_hour = [req for req in captured_requests if (now - req.timestamp).seconds < 3600]
    last_day = [req for req in captured_requests if (now - req.timestamp).days < 1]
    
    # Most common headers
    top_headers = dict(sorted(header_stats.items(), key=lambda x: x[1], reverse=True)[:10])
    
    # Webhook breakdown
    webhook_types = {}
    for req in captured_requests:
        if req.is_webhook and req.webhook_type:
            webhook_types[req.webhook_type] = webhook_types.get(req.webhook_type, 0) + 1
    
    return {
        "overview": {
            "total_requests": len(captured_requests),
            "last_hour": len(last_hour),
            "last_24_hours": len(last_day),
            "webhooks": len([req for req in captured_requests if req.is_webhook]),
            "unique_paths": len(set(req.path for req in captured_requests)),
            "unique_ips": len(set(req.client_ip for req in captured_requests))
        },
        "methods": dict(request_stats),
        "top_headers": top_headers,
        "webhook_types": webhook_types,
        "avg_body_size": sum(req.body_size for req in captured_requests) // max(len(captured_requests), 1),
        "last_request": captured_requests[-1].dict() if captured_requests else None
    }

@app.get("/admin/headers/{request_id}")
async def analyze_request_headers(request_id: str):
    """Detailed header analysis for a specific request"""
    
    for req in captured_requests:
        if req.id == request_id:
            return {
                "request_id": request_id,
                "timestamp": req.timestamp.isoformat(),
                "method": req.method,
                "path": req.path,
                "query_params": req.query_params,
                "is_webhook": req.is_webhook,
                "webhook_type": req.webhook_type,
                "header_analysis": req.header_analysis.dict(),
                "raw_headers": req.headers,
                "insights": {
                    "has_authentication": bool(req.header_analysis.security_headers),
                    "has_custom_headers": bool(req.header_analysis.custom_headers),
                    "forwarded_request": bool(req.header_analysis.forwarding_headers),
                    "content_type": req.content_type,
                    "likely_browser": "mozilla" in req.user_agent.lower() or "chrome" in req.user_agent.lower()
                }
            }
    
    raise HTTPException(status_code=404, detail="Request not found")

@app.get("/admin/search")
async def search_requests(
    q: str = Query(..., description="Search term"),
    field: str = Query("all", description="Field to search in: all, path, headers, body")
):
    """Search through captured requests"""
    
    results = []
    search_term = q.lower()
    
    for req in captured_requests:
        match = False
        
        if field == "all" or field == "path":
            if search_term in req.path.lower():
                match = True
        
        if field == "all" or field == "headers":
            for key, value in req.headers.items():
                if search_term in key.lower() or search_term in str(value).lower():
                    match = True
                    break
        
        if field == "all" or field == "body":
            if req.body and search_term in str(req.body).lower():
                match = True
        
        if match:
            results.append(req)
    
    return {
        "search_term": q,
        "search_field": field,
        "results_count": len(results),
        "results": [req.dict() for req in results[-50:]]  # Limit to last 50 matches
    }

@app.get("/admin/export")
async def export_captured_requests(
    format: str = Query("json", description="Export format: json, csv"),
    include_bodies: bool = Query(True, description="Include request bodies in export")
):
    """Export captured requests"""
    
    if format == "json":
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "total_requests": len(captured_requests),
            "requests": []
        }
        
        for req in captured_requests:
            req_data = req.dict()
            if not include_bodies:
                req_data.pop('body', None)
            export_data["requests"].append(req_data)
        
        return JSONResponse(
            content=export_data,
            headers={"Content-Disposition": f"attachment; filename=api_captures_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
        )
    
    elif format == "csv":
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = ['timestamp', 'method', 'path', 'client_ip', 'user_agent', 'content_type', 
                  'body_size', 'is_webhook', 'webhook_type', 'header_count']
        if include_bodies:
            headers.append('body')
        writer.writerow(headers)
        
        # Write data
        for req in captured_requests:
            row = [
                req.timestamp.isoformat(),
                req.method,
                req.path,
                req.client_ip,
                req.user_agent,
                req.content_type,
                req.body_size,
                req.is_webhook,
                req.webhook_type or '',
                req.header_analysis.total_headers
            ]
            if include_bodies:
                row.append(str(req.body) if req.body else '')
            writer.writerow(row)
        
        output.seek(0)
        return JSONResponse(
            content={"csv_data": output.getvalue()},
            headers={"Content-Disposition": f"attachment; filename=api_captures_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'json' or 'csv'")

@app.get("/admin/header-stats")
async def get_header_statistics():
    """Get detailed header usage statistics"""
    
    header_categories = {
        "security": defaultdict(int),
        "webhook": defaultdict(int),
        "standard": defaultdict(int),
        "custom": defaultdict(int)
    }
    
    for req in captured_requests:
        for header_name in req.header_analysis.security_headers.keys():
            header_categories["security"][header_name.lower()] += 1
        for header_name in req.header_analysis.webhook_headers.keys():
            header_categories["webhook"][header_name.lower()] += 1
        for header_name in req.header_analysis.standard_headers.keys():
            header_categories["standard"][header_name.lower()] += 1
        for header_name in req.header_analysis.custom_headers.keys():
            header_categories["custom"][header_name.lower()] += 1
    
    return {
        "total_unique_headers": len(header_stats),
        "by_category": {
            category: dict(sorted(headers.items(), key=lambda x: x[1], reverse=True)[:20])
            for category, headers in header_categories.items()
        },
        "most_common_overall": dict(sorted(header_stats.items(), key=lambda x: x[1], reverse=True)[:30])
    }

@app.delete("/admin/clear")
async def clear_captured_requests():
    """Clear all captured requests and reset statistics"""
    global captured_requests, request_stats, header_stats
    
    count = len(captured_requests)
    captured_requests.clear()
    request_stats.clear()
    header_stats.clear()
    
    logger.info("Cleared all captured requests and statistics")
    return {
        "message": f"Cleared {count} captured requests and reset all statistics",
        "timestamp": datetime.now().isoformat()
    }

@app.delete("/admin/clear/{request_id}")
async def delete_single_request(request_id: str):
    """Delete a specific captured request"""
    global captured_requests
    
    for i, req in enumerate(captured_requests):
        if req.id == request_id:
            deleted_req = captured_requests.pop(i)
            logger.info(f"Deleted request {request_id}")
            return {
                "message": f"Deleted request {request_id}",
                "deleted_request": {
                    "method": deleted_req.method,
                    "path": deleted_req.path,
                    "timestamp": deleted_req.timestamp.isoformat()
                }
            }
    
    raise HTTPException(status_code=404, detail="Request not found")

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint with system information"""
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "captured_requests": len(captured_requests),
        "total_processed": request_stats.get("total", 0),
        "memory_usage": {
            "captured_requests": len(captured_requests),
            "max_capacity": 500,
            "usage_percentage": (len(captured_requests) / 500) * 100
        },
        "uptime_info": {
            "requests_per_minute": request_stats.get("total", 0) / max((datetime.now() - datetime.min).total_seconds() / 60, 1),
            "webhooks_detected": request_stats.get("webhooks", 0)
        }
    }

# Real-time monitoring endpoint
@app.get("/admin/monitor")
async def real_time_monitor():
    """Real-time monitoring endpoint for live stats"""
    
    recent_requests = captured_requests[-10:]
    
    return {
        "current_time": datetime.now().isoformat(),
        "active_monitoring": True,
        "recent_activity": [
            {
                "id": req.id,
                "timestamp": req.timestamp.isoformat(),
                "method": req.method,
                "path": req.path,
                "is_webhook": req.is_webhook,
                "webhook_type": req.webhook_type,
                "client_ip": req.client_ip,
                "body_size": req.body_size
            }
            for req in reversed(recent_requests)
        ],
        "live_stats": {
            "total_requests": len(captured_requests),
            "methods_distribution": dict(request_stats),
            "last_request_time": captured_requests[-1].timestamp.isoformat() if captured_requests else None
        }
    }

# Webhook validation helpers
@app.post("/admin/validate-webhook/{request_id}")
async def validate_webhook_signature(request_id: str, secret: str):
    """Validate webhook signature for supported webhook types"""
    
    for req in captured_requests:
        if req.id == request_id:
            if not req.is_webhook:
                raise HTTPException(status_code=400, detail="Request is not a webhook")
            
            validation_result = {
                "request_id": request_id,
                "webhook_type": req.webhook_type,
                "validation_attempted": True,
                "signatures_found": [],
                "validation_results": {}
            }
            
            # Check for various signature headers
            signature_headers = [
                'x-hub-signature-256', 'x-hub-signature', 'x-stripe-signature',
                'x-webhook-signature', 'x-slack-signature'
            ]
            
            for header_name in signature_headers:
                if header_name in req.headers:
                    validation_result["signatures_found"].append(header_name)
            
            # GitHub webhook validation
            if req.webhook_type == "GitHub" and req.body:
                import hmac
                import hashlib
                
                github_sig = req.headers.get('x-hub-signature-256')
                if github_sig:
                    try:
                        body_str = json.dumps(req.body) if isinstance(req.body, dict) else str(req.body)
                        expected_sig = 'sha256=' + hmac.new(
                            secret.encode(),
                            body_str.encode(),
                            hashlib.sha256
                        ).hexdigest()
                        
                        validation_result["validation_results"]["github"] = {
                            "provided_signature": github_sig,
                            "expected_signature": expected_sig,
                            "valid": hmac.compare_digest(github_sig, expected_sig)
                        }
                    except Exception as e:
                        validation_result["validation_results"]["github"] = {
                            "error": str(e)
                        }
            
            return validation_result
    
    raise HTTPException(status_code=404, detail="Request not found")

# Batch operations
@app.post("/admin/batch-delete")
async def batch_delete_requests(request_ids: List[str]):
    """Delete multiple requests by IDs"""
    
    global captured_requests
    
    deleted_count = 0
    not_found = []
    
    for req_id in request_ids:
        found = False
        for i, req in enumerate(captured_requests):
            if req.id == req_id:
                captured_requests.pop(i)
                deleted_count += 1
                found = True
                break
        
        if not found:
            not_found.append(req_id)
    
    return {
        "deleted_count": deleted_count,
        "not_found": not_found,
        "remaining_requests": len(captured_requests)
    }

# Custom response simulation
@app.post("/admin/simulate-response/{request_id}")
async def simulate_custom_response(
    request_id: str,
    status_code: int = 200,
    response_body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None
):
    """Simulate a custom response for testing purposes"""
    
    for req in captured_requests:
        if req.id == request_id:
            custom_response = {
                "simulated_response": True,
                "original_request": {
                    "id": req.id,
                    "method": req.method,
                    "path": req.path,
                    "timestamp": req.timestamp.isoformat()
                },
                "response_details": {
                    "status_code": status_code,
                    "body": response_body or {"message": "Custom simulated response"},
                    "headers": headers or {"Content-Type": "application/json"}
                }
            }
            
            return JSONResponse(
                content=custom_response,
                status_code=status_code,
                headers=headers or {}
            )
    
    raise HTTPException(status_code=404, detail="Request not found")

# Request replay functionality
@app.post("/admin/replay/{request_id}")
async def replay_request(request_id: str, target_url: str):
    """Replay a captured request to a different URL"""
    
    for req in captured_requests:
        if req.id == request_id:
            import httpx
            
            try:
                # Prepare the request
                headers = req.headers.copy()
                # Remove hop-by-hop headers
                hop_by_hop = ['connection', 'keep-alive', 'proxy-authenticate', 
                             'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade', 'host']
                for header in hop_by_hop:
                    headers.pop(header, None)
                
                # Make the request
                async with httpx.AsyncClient() as client:
                    if req.method.upper() == "GET":
                        response = await client.get(target_url, headers=headers, params=req.query_params)
                    else:
                        body_data = None
                        if req.body:
                            if isinstance(req.body, dict):
                                body_data = json.dumps(req.body)
                                headers['content-type'] = 'application/json'
                            else:
                                body_data = str(req.body)
                        
                        response = await client.request(
                            method=req.method,
                            url=target_url,
                            headers=headers,
                            content=body_data,
                            params=req.query_params
                        )
                
                return {
                    "replay_successful": True,
                    "original_request_id": request_id,
                    "target_url": target_url,
                    "response": {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": response.text[:1000] + "..." if len(response.text) > 1000 else response.text
                    }
                }
                
            except Exception as e:
                return {
                    "replay_successful": False,
                    "error": str(e),
                    "original_request_id": request_id,
                    "target_url": target_url
                }
    
    raise HTTPException(status_code=404, detail="Request not found")

# Configuration endpoint
@app.get("/admin/config")
async def get_configuration():
    """Get current configuration and system info"""
    
    return {
        "version": "2.0.0",
        "configuration": {
            "max_stored_requests": 500,
            "log_file": "api_captures.log",
            "auto_detect_webhooks": True,
            "truncate_long_headers": True,
            "max_body_log_size": 2048
        },
        "features": {
            "header_analysis": True,
            "webhook_detection": True,
            "signature_validation": True,
            "request_replay": True,
            "real_time_monitoring": True,
            "export_functionality": True,
            "search_capability": True
        },
        "supported_webhook_types": [
            "GitHub", "Stripe", "PayPal", "Slack", "Generic Webhook"
        ],
        "supported_content_types": [
            "application/json", "application/x-www-form-urlencoded",
            "text/plain", "multipart/form-data", "binary data"
        ]
    }

# Advanced filtering endpoint
@app.get("/admin/filter")
async def advanced_filter(
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    methods: Optional[List[str]] = Query(None, description="HTTP methods to include"),
    webhook_types: Optional[List[str]] = Query(None, description="Webhook types to include"),
    has_auth: Optional[bool] = Query(None, description="Filter by presence of auth headers"),
    min_body_size: Optional[int] = Query(None, description="Minimum body size"),
    max_body_size: Optional[int] = Query(None, description="Maximum body size"),
    client_ips: Optional[List[str]] = Query(None, description="Client IPs to include")
):
    """Advanced filtering of captured requests"""
    
    filtered_requests = captured_requests.copy()
    
    # Date filtering
    if start_date:
        start_dt = datetime.fromisoformat(start_date)
        filtered_requests = [req for req in filtered_requests if req.timestamp >= start_dt]
    
    if end_date:
        end_dt = datetime.fromisoformat(end_date + "T23:59:59")
        filtered_requests = [req for req in filtered_requests if req.timestamp <= end_dt]
    
    # Method filtering
    if methods:
        methods_upper = [m.upper() for m in methods]
        filtered_requests = [req for req in filtered_requests if req.method in methods_upper]
    
    # Webhook type filtering
    if webhook_types:
        filtered_requests = [req for req in filtered_requests if req.webhook_type in webhook_types]
    
    # Authentication filtering
    if has_auth is not None:
        if has_auth:
            filtered_requests = [req for req in filtered_requests if req.header_analysis.security_headers]
        else:
            filtered_requests = [req for req in filtered_requests if not req.header_analysis.security_headers]
    
    # Body size filtering
    if min_body_size is not None:
        filtered_requests = [req for req in filtered_requests if req.body_size >= min_body_size]
    
    if max_body_size is not None:
        filtered_requests = [req for req in filtered_requests if req.body_size <= max_body_size]
    
    # Client IP filtering
    if client_ips:
        filtered_requests = [req for req in filtered_requests if req.client_ip in client_ips]
    
    return {
        "total_requests": len(captured_requests),
        "filtered_count": len(filtered_requests),
        "filters_applied": {
            "start_date": start_date,
            "end_date": end_date,
            "methods": methods,
            "webhook_types": webhook_types,
            "has_auth": has_auth,
            "min_body_size": min_body_size,
            "max_body_size": max_body_size,
            "client_ips": client_ips
        },
        "requests": [req.dict() for req in filtered_requests[-100:]]  # Last 100 results
    }

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*60)
    print("🚀 ADVANCED API CALL CAPTURE UTILITY v2.0.0")
    print("="*60)
    print("📡 Starting comprehensive API capture server...")
    print("\n📍 Available endpoints:")
    print("   • Main Dashboard:     http://localhost:8000/")
    print("   • Capture Endpoint:   http://localhost:8000/capture/your-path")
    print("   • Webhook Endpoint:   http://localhost:8000/webhook/your-path")
    print("   • Admin Panel:        http://localhost:8000/admin/captured")
    print("   • API Documentation:  http://localhost:8000/docs")
    print("   • Health Check:       http://localhost:8000/health")
    print("   • Real-time Monitor:  http://localhost:8000/admin/monitor")
    print("\n🔧 Features enabled:")
    print("   ✅ Advanced header analysis")
    print("   ✅ Webhook type detection")
    print("   ✅ Request search & filtering")
    print("   ✅ Export functionality")
    print("   ✅ Signature validation")
    print("   ✅ Request replay")
    print("   ✅ Real-time monitoring")
    print("   ✅ Interactive dashboard")
    print("\n📝 Log file: api_captures.log")
    print("💾 Memory limit: 500 requests")
    print("="*60)
    print("Ready to capture API calls! 🎯")
    print("="*60 + "\n")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000, 
        log_level="info",
        access_log=True
    )                     