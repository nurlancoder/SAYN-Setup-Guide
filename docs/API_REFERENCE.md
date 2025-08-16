# SAYN Security Scanner - API Reference

## Overview

The SAYN Security Scanner provides a comprehensive REST API for managing security scans, retrieving results, and configuring the system. This document describes all available endpoints, request/response formats, and usage examples.

## Base URL

```
http://localhost:5000/api
```

## Authentication

Currently, the API does not require authentication for basic operations. For production deployments, consider implementing API key authentication or OAuth2.

## Response Format

All API responses follow a consistent JSON format:

```json
{
  "success": true,
  "data": {},
  "message": "Operation completed successfully",
  "error": null
}
```

## Error Responses

Error responses include detailed information:

```json
{
  "success": false,
  "data": null,
  "message": "Error description",
  "error": {
    "code": "ERROR_CODE",
    "details": "Additional error details"
  }
}
```

## Endpoints

### 1. Dashboard Statistics

#### GET /api/dashboard/stats

Retrieve dashboard statistics including scan counts, vulnerability statistics, and system health.

**Response:**
```json
{
  "success": true,
  "data": {
    "total_scans": 150,
    "completed_scans": 145,
    "failed_scans": 5,
    "total_vulnerabilities": 89,
    "high_risk_count": 12,
    "medium_risk_count": 34,
    "low_risk_count": 43,
    "success_rate": 96.7,
    "recent_activity": [
      {
        "id": 150,
        "target": "https://example.com",
        "scan_type": "web",
        "status": "completed",
        "created_at": "2024-01-15T10:30:00Z"
      }
    ]
  }
}
```

### 2. Scan Management

#### POST /api/scan

Start a new security scan.

**Request Body:**
```json
{
  "target": "https://example.com",
  "scan_name": "My Security Scan",
  "scan_type": "web",
  "scan_depth": "normal",
  "threads": 10,
  "timeout": 30,
  "modules": ["xss", "sqli", "csrf", "headers"]
}
```

**Parameters:**
- `target` (required): Target URL to scan
- `scan_name` (optional): Human-readable name for the scan
- `scan_type`: `web`, `api`, `network`, or `full`
- `scan_depth`: `quick`, `normal`, `deep`, or `aggressive`
- `threads` (1-50): Number of concurrent threads
- `timeout` (5-300): Request timeout in seconds
- `modules`: Array of module names to enable

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": 151,
    "status": "started",
    "message": "Scan started successfully"
  }
}
```

#### GET /api/scans

Retrieve list of scans with optional filtering.

**Query Parameters:**
- `limit` (optional): Number of scans to return (default: 50)
- `offset` (optional): Number of scans to skip (default: 0)
- `status` (optional): Filter by status (`running`, `completed`, `failed`)
- `scan_type` (optional): Filter by scan type
- `target` (optional): Filter by target URL

**Response:**
```json
{
  "success": true,
  "data": {
    "scans": [
      {
        "id": 151,
        "target": "https://example.com",
        "scan_name": "My Security Scan",
        "scan_type": "web",
        "status": "completed",
        "vulnerability_count": 5,
        "created_at": "2024-01-15T10:30:00Z",
        "completed_at": "2024-01-15T10:35:00Z",
        "duration": 300
      }
    ],
    "total": 150,
    "limit": 50,
    "offset": 0
  }
}
```

#### GET /api/scan/{scan_id}

Retrieve detailed information about a specific scan.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 151,
    "target": "https://example.com",
    "scan_name": "My Security Scan",
    "scan_type": "web",
    "status": "completed",
    "scan_depth": "normal",
    "threads_used": 10,
    "timeout_seconds": 30,
    "vulnerability_count": 5,
    "risk_score": 7.5,
    "created_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:35:00Z",
    "duration": 300,
    "modules_executed": ["xss_scanner", "sqli_scanner", "headers_scanner"],
    "metadata": {
      "user_agent": "SAYN-Scanner/2.1.0",
      "scan_version": "2.1.0"
    }
  }
}
```

#### GET /api/scan/{scan_id}/progress

Get real-time progress information for a running scan.

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": 151,
    "status": "running",
    "progress": 65,
    "current_module": "sqli_scanner",
    "modules": {
      "xss_scanner": "completed",
      "sqli_scanner": "running",
      "headers_scanner": "pending"
    },
    "results": {
      "total_vulnerabilities": 3,
      "high_risk": 1,
      "medium_risk": 2,
      "low_risk": 0
    },
    "estimated_completion": "2024-01-15T10:32:00Z"
  }
}
```

#### DELETE /api/scan/{scan_id}

Delete a scan and all associated data.

**Response:**
```json
{
  "success": true,
  "data": {
    "scan_id": 151,
    "message": "Scan deleted successfully"
  }
}
```

### 3. Vulnerability Management

#### GET /api/vulnerabilities

Retrieve list of vulnerabilities with optional filtering.

**Query Parameters:**
- `limit` (optional): Number of vulnerabilities to return (default: 50)
- `offset` (optional): Number of vulnerabilities to skip (default: 0)
- `severity` (optional): Filter by severity (`critical`, `high`, `medium`, `low`)
- `type` (optional): Filter by vulnerability type
- `scan_id` (optional): Filter by scan ID
- `target` (optional): Filter by target URL

**Response:**
```json
{
  "success": true,
  "data": {
    "vulnerabilities": [
      {
        "id": 1,
        "scan_id": 151,
        "type": "xss",
        "severity": "high",
        "title": "Cross-Site Scripting Vulnerability",
        "description": "XSS vulnerability found in search parameter",
        "location": "https://example.com/search?q=test",
        "recommendation": "Implement proper input validation and output encoding",
        "cvss_score": 7.2,
        "affected_component": "search functionality",
        "evidence": "<script>alert('XSS')</script>",
        "created_at": "2024-01-15T10:31:00Z"
      }
    ],
    "total": 89,
    "limit": 50,
    "offset": 0
  }
}
```

#### GET /api/vulnerability/{vulnerability_id}

Retrieve detailed information about a specific vulnerability.

**Response:**
```json
{
  "success": true,
  "data": {
    "id": 1,
    "scan_id": 151,
    "type": "xss",
    "severity": "high",
    "title": "Cross-Site Scripting Vulnerability",
    "description": "XSS vulnerability found in search parameter",
    "location": "https://example.com/search?q=test",
    "recommendation": "Implement proper input validation and output encoding",
    "cvss_score": 7.2,
    "affected_component": "search functionality",
    "evidence": "<script>alert('XSS')</script>",
    "payload": "<script>alert('XSS')</script>",
    "parameter": "q",
    "false_positive": false,
    "verified": false,
    "created_at": "2024-01-15T10:31:00Z"
  }
}
```

#### PUT /api/vulnerability/{vulnerability_id}

Update vulnerability information (e.g., mark as false positive).

**Request Body:**
```json
{
  "false_positive": true,
  "verified": true,
  "notes": "Marked as false positive after manual verification"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "vulnerability_id": 1,
    "message": "Vulnerability updated successfully"
  }
}
```

### 4. Report Generation

#### GET /api/scan/{scan_id}/report

Generate a comprehensive report for a completed scan.

**Query Parameters:**
- `format` (optional): Report format (`html`, `pdf`, `json`, `xml`, `csv`) (default: `html`)

**Response:**
```json
{
  "success": true,
  "data": {
    "report_url": "/reports/scan_151_report.html",
    "report_path": "/app/reports/scan_151_report.html",
    "format": "html",
    "generated_at": "2024-01-15T10:36:00Z"
  }
}
```

#### GET /api/reports

List all available reports.

**Response:**
```json
{
  "success": true,
  "data": {
    "reports": [
      {
        "filename": "scan_151_report.html",
        "scan_id": 151,
        "format": "html",
        "size": "245KB",
        "created_at": "2024-01-15T10:36:00Z",
        "download_url": "/api/reports/scan_151_report.html"
      }
    ]
  }
}
```

### 5. Configuration Management

#### GET /api/config

Retrieve current system configuration.

**Response:**
```json
{
  "success": true,
  "data": {
    "database": {
      "path": "/app/data/sayn.db",
      "backup_enabled": true
    },
    "scanning": {
      "default_threads": 10,
      "default_timeout": 30,
      "max_concurrent_scans": 5
    },
    "modules": {
      "web_security": {
        "enabled": true,
        "xss_scanner": {"enabled": true},
        "sqli_scanner": {"enabled": true},
        "csrf_scanner": {"enabled": true},
        "headers_scanner": {"enabled": true},
        "file_inclusion_scanner": {"enabled": true}
      },
      "api_security": {
        "enabled": true,
        "rest_scanner": {"enabled": true},
        "graphql_scanner": {"enabled": true}
      },
      "network_security": {
        "enabled": true,
        "port_scanner": {"enabled": true},
        "ssl_scanner": {"enabled": true}
      }
    },
    "web_interface": {
      "host": "0.0.0.0",
      "port": 5000,
      "debug": false
    }
  }
}
```

#### PUT /api/config

Update system configuration.

**Request Body:**
```json
{
  "scanning": {
    "default_threads": 15,
    "default_timeout": 45
  },
  "modules": {
    "web_security": {
      "xss_scanner": {"enabled": false}
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Configuration updated successfully",
    "restart_required": false
  }
}
```

### 6. System Health

#### GET /api/health

Check system health and status.

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "2.1.0",
    "uptime": 3600,
    "database": {
      "status": "connected",
      "size": "15.2MB"
    },
    "modules": {
      "web_security": "available",
      "api_security": "available",
      "network_security": "available"
    },
    "system": {
      "cpu_usage": 15.2,
      "memory_usage": 45.8,
      "disk_usage": 23.1
    }
  }
}
```

### 7. Statistics and Analytics

#### GET /api/stats/vulnerabilities

Get vulnerability statistics and trends.

**Query Parameters:**
- `period` (optional): Time period (`day`, `week`, `month`, `year`) (default: `month`)

**Response:**
```json
{
  "success": true,
  "data": {
    "period": "month",
    "total_vulnerabilities": 89,
    "by_severity": {
      "critical": 3,
      "high": 12,
      "medium": 34,
      "low": 40
    },
    "by_type": {
      "xss": 25,
      "sqli": 18,
      "csrf": 12,
      "headers": 15,
      "file_inclusion": 8,
      "other": 11
    },
    "trends": [
      {
        "date": "2024-01-01",
        "vulnerabilities": 5,
        "high_risk": 2
      }
    ]
  }
}
```

#### GET /api/stats/scans

Get scan statistics and performance metrics.

**Response:**
```json
{
  "success": true,
  "data": {
    "total_scans": 150,
    "success_rate": 96.7,
    "average_duration": 245,
    "by_type": {
      "web": 89,
      "api": 34,
      "network": 18,
      "full": 9
    },
    "performance": {
      "fastest_scan": 45,
      "slowest_scan": 890,
      "average_vulnerabilities_per_scan": 0.59
    }
  }
}
```

## WebSocket Events

The API also supports real-time updates via WebSocket connections.

### Connection

Connect to WebSocket endpoint:
```
ws://localhost:5000/ws
```

### Events

#### scan_progress
Emitted when scan progress updates:
```json
{
  "event": "scan_progress",
  "data": {
    "scan_id": 151,
    "progress": 65,
    "status": "running",
    "current_module": "sqli_scanner"
  }
}
```

#### scan_completed
Emitted when a scan completes:
```json
{
  "event": "scan_completed",
  "data": {
    "scan_id": 151,
    "status": "completed",
    "vulnerability_count": 5,
    "risk_score": 7.5
  }
}
```

#### vulnerability_found
Emitted when a new vulnerability is discovered:
```json
{
  "event": "vulnerability_found",
  "data": {
    "scan_id": 151,
    "vulnerability": {
      "type": "xss",
      "severity": "high",
      "title": "Cross-Site Scripting Vulnerability"
    }
  }
}
```

## Rate Limiting

API endpoints are rate-limited to prevent abuse:
- 100 requests per minute for authenticated users
- 20 requests per minute for anonymous users

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642243200
```

## Error Codes

Common error codes and their meanings:

- `400`: Bad Request - Invalid request parameters
- `401`: Unauthorized - Authentication required
- `403`: Forbidden - Insufficient permissions
- `404`: Not Found - Resource not found
- `429`: Too Many Requests - Rate limit exceeded
- `500`: Internal Server Error - Server error
- `503`: Service Unavailable - Service temporarily unavailable

## SDK Examples

### Python SDK

```python
import requests

class SAYNClient:
    def __init__(self, base_url="http://localhost:5000/api"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def start_scan(self, target, scan_type="web"):
        response = self.session.post(f"{self.base_url}/scan", json={
            "target": target,
            "scan_type": scan_type
        })
        return response.json()
    
    def get_scan_progress(self, scan_id):
        response = self.session.get(f"{self.base_url}/scan/{scan_id}/progress")
        return response.json()
    
    def get_vulnerabilities(self, scan_id):
        response = self.session.get(f"{self.base_url}/vulnerabilities?scan_id={scan_id}")
        return response.json()

# Usage
client = SAYNClient()
scan = client.start_scan("https://example.com")
print(f"Scan started with ID: {scan['data']['scan_id']}")
```

### JavaScript SDK

```javascript
class SAYNClient {
    constructor(baseUrl = 'http://localhost:5000/api') {
        this.baseUrl = baseUrl;
    }
    
    async startScan(target, scanType = 'web') {
        const response = await fetch(`${this.baseUrl}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                target,
                scan_type: scanType
            })
        });
        return response.json();
    }
    
    async getScanProgress(scanId) {
        const response = await fetch(`${this.baseUrl}/scan/${scanId}/progress`);
        return response.json();
    }
    
    async getVulnerabilities(scanId) {
        const response = await fetch(`${this.baseUrl}/vulnerabilities?scan_id=${scanId}`);
        return response.json();
    }
}

// Usage
const client = new SAYNClient();
client.startScan('https://example.com')
    .then(scan => console.log(`Scan started with ID: ${scan.data.scan_id}`));
```

## Support

For API support and questions:
- Documentation: https://github.com/sayn-scanner/docs
- Issues: https://github.com/sayn-scanner/issues
- Email: support@sayn-scanner.com
