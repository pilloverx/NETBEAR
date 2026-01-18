# nextcloud/nc_recon.py
"""
NextCloud Reconnaissance Module
Enumerates: users, shares, public links, system info
"""

import requests
import json
from typing import Dict, List, Any
from rich.console import Console
import config

console = Console()

class NCRecon:
    """NextCloud enumeration and reconnaissance"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.host = config.NEXTCLOUD_HOST.rstrip("/")
        self.findings = []

    def run(self) -> List[Dict[str, Any]]:
        """Execute all recon tests"""
        console.print("[cyan]Starting NextCloud reconnaissance...[/cyan]")
        
        # System info
        self.enumerate_system_info()
        
        # User enumeration
        self.enumerate_users()
        
        # Shares enumeration
        self.enumerate_shares()
        
        # Public links enumeration
        self.enumerate_public_links()
        
        console.print(f"[green]✓ Recon complete: {len(self.findings)} findings[/green]")
        return self.findings

    def enumerate_system_info(self):
        """Get NextCloud version and capabilities"""
        try:
            resp = self.session.get(
                f"{self.host}/status.php",
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            if resp.status_code == 200:
                data = resp.json()
                self.findings.append({
                    "type": "system_info",
                    "severity": "info",
                    "data": data,
                    "description": f"NextCloud version: {data.get('version')}",
                    "endpoint": "/status.php"
                })
                console.print(f"  [cyan]Version:[/cyan] {data.get('version')}")
        except Exception as e:
            console.print(f"  [yellow]System info failed: {str(e)}[/yellow]")

    def enumerate_users(self, limit=100):
        """Enumerate NextCloud users via OCS API"""
        try:
            # Try to get user list
            resp = self.session.get(
                f"{self.host}/ocs/v2.php/apps/provisioning_api/api/v1/users",
                headers={"OCS-APIRequest": "true"},
                params={"limit": limit},
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            if resp.status_code in [200, 400]:  # 400 = permission denied but user exists
                try:
                    data = resp.json()
                    users = data.get("ocs", {}).get("data", {}).get("users", [])
                    if users:
                        self.findings.append({
                            "type": "user_enumeration",
                            "severity": "high",
                            "count": len(users),
                            "users": users,
                            "description": f"Exposed {len(users)} user IDs",
                            "endpoint": "/ocs/v2.php/apps/provisioning_api/api/v1/users",
                            "impact": "User enumeration can aid in brute force or targeted attacks"
                        })
                        console.print(f"  [green]Found {len(users)} users[/green]")
                        for user in users[:10]:
                            console.print(f"    - {user}")
                        if len(users) > 10:
                            console.print(f"    ... and {len(users) - 10} more")
                except:
                    pass
        except Exception as e:
            console.print(f"  [yellow]User enumeration failed: {str(e)}[/yellow]")

    def enumerate_shares(self):
        """Enumerate shared files and folders"""
        try:
            resp = self.session.get(
                f"{self.host}/ocs/v2.php/apps/files_sharing/api/v1/shares",
                headers={"OCS-APIRequest": "true"},
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    shares = data.get("ocs", {}).get("data", [])
                    if isinstance(shares, dict):
                        shares = list(shares.values())
                    
                    if shares:
                        self.findings.append({
                            "type": "shares_enumeration",
                            "severity": "medium",
                            "count": len(shares),
                            "shares": shares[:20],  # Show first 20
                            "description": f"Enumerated {len(shares)} shares",
                            "endpoint": "/ocs/v2.php/apps/files_sharing/api/v1/shares",
                            "impact": "Can identify shared resources and potential IDOR vectors"
                        })
                        console.print(f"  [green]Found {len(shares)} shares[/green]")
                except:
                    pass
        except Exception as e:
            console.print(f"  [yellow]Share enumeration failed: {str(e)}[/yellow]")

    def enumerate_public_links(self):
        """Find public shares (tokens)"""
        try:
            resp = self.session.get(
                f"{self.host}/ocs/v2.php/apps/files_sharing/api/v1/shares?reshares=true&shared_with_me=false",
                headers={"OCS-APIRequest": "true"},
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    shares = data.get("ocs", {}).get("data", [])
                    if isinstance(shares, dict):
                        shares = list(shares.values())
                    
                    public_shares = [s for s in shares if s.get("share_type") == 3]  # Public link
                    
                    if public_shares:
                        self.findings.append({
                            "type": "public_links",
                            "severity": "medium",
                            "count": len(public_shares),
                            "shares": public_shares[:20],
                            "description": f"Found {len(public_shares)} public shares",
                            "endpoint": "/ocs/v2.php/apps/files_sharing/api/v1/shares",
                            "impact": "Public links may be leaked or enumerable"
                        })
                        console.print(f"  [green]Found {len(public_shares)} public links[/green]")
                except:
                    pass
        except Exception as e:
            console.print(f"  [yellow]Public link enumeration failed: {str(e)}[/yellow]")
