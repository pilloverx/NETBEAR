# nextcloud/nc_idor.py
"""
NextCloud IDOR Testing Module
Tests for ID enumeration in files, shares, users
"""

import requests
import time
from typing import Dict, List, Any
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
import config

console = Console()

class NCIDOR:
    """NextCloud IDOR vulnerability testing"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.host = config.NEXTCLOUD_HOST.rstrip("/")
        self.findings = []
        self.vulnerable_ids = []

    def run(self) -> List[Dict[str, Any]]:
        """Execute IDOR tests"""
        console.print("[cyan]Starting IDOR testing...[/cyan]")
        
        # Test file ID enumeration
        self.test_file_id_idor()
        
        # Test share ID enumeration
        self.test_share_id_idor()
        
        # Test user ID access
        self.test_user_id_idor()
        
        # Test direct file access
        self.test_direct_file_access()
        
        console.print(f"[green]✓ IDOR tests complete: {len(self.vulnerable_ids)} potential vulnerabilities[/green]")
        return self.findings

    def test_file_id_idor(self):
        """Test if file IDs can be enumerated or accessed by other users"""
        console.print("  [cyan]Testing file ID IDOR...[/cyan]")
        
        sample_ids = self._generate_id_samples(config.NEXTCLOUD_IDOR_SAMPLE_SIZE)
        vulnerable = []
        
        for file_id in sample_ids:
            try:
                # Try to access file info
                resp = self.session.get(
                    f"{self.host}/remote.php/dav/files/{config.NEXTCLOUD_USERNAME}/{file_id}",
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
                
                # 200 = file exists and accessible, 404 = not found
                if resp.status_code == 200:
                    vulnerable.append({
                        "type": "file_id_idor",
                        "file_id": file_id,
                        "status": resp.status_code,
                        "size": len(resp.content)
                    })
                    time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                    
            except Exception as e:
                pass
        
        if vulnerable:
            self.findings.append({
                "type": "file_id_idor",
                "severity": "high",
                "count": len(vulnerable),
                "endpoint": "/remote.php/dav/files/",
                "vulnerable_ids": vulnerable[:20],
                "description": "File IDs may be enumerable or accessible across users",
                "impact": "Direct file access without authorization"
            })
            self.vulnerable_ids.extend(vulnerable)
            console.print(f"    [red]Found {len(vulnerable)} accessible file IDs[/red]")

    def test_share_id_idor(self):
        """Test if share IDs can be accessed or modified"""
        console.print("  [cyan]Testing share ID IDOR...[/cyan]")
        
        sample_ids = self._generate_id_samples(config.NEXTCLOUD_IDOR_SAMPLE_SIZE)
        vulnerable = []
        
        for share_id in sample_ids:
            try:
                # Try to get share info
                resp = self.session.get(
                    f"{self.host}/ocs/v2.php/apps/files_sharing/api/v1/shares/{share_id}",
                    headers={"OCS-APIRequest": "true"},
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
                
                if resp.status_code == 200:
                    vulnerable.append({
                        "type": "share_id_idor",
                        "share_id": share_id,
                        "status": resp.status_code
                    })
                    time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                    
            except Exception as e:
                pass
        
        if vulnerable:
            self.findings.append({
                "type": "share_id_idor",
                "severity": "high",
                "count": len(vulnerable),
                "endpoint": "/ocs/v2.php/apps/files_sharing/api/v1/shares/",
                "vulnerable_ids": vulnerable[:20],
                "description": "Share IDs may be enumerable or have info disclosure",
                "impact": "Unauthorized access to share details and modification"
            })
            self.vulnerable_ids.extend(vulnerable)
            console.print(f"    [red]Found {len(vulnerable)} accessible share IDs[/red]")

    def test_user_id_idor(self):
        """Test if user IDs/profiles are accessible"""
        console.print("  [cyan]Testing user ID IDOR...[/cyan]")
        
        sample_ids = self._generate_id_samples(30)
        vulnerable = []
        
        for user_id in sample_ids:
            try:
                # Try to get user info
                resp = self.session.get(
                    f"{self.host}/ocs/v2.php/apps/provisioning_api/api/v1/users/{user_id}",
                    headers={"OCS-APIRequest": "true"},
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerable.append({
                        "type": "user_id_idor",
                        "user_id": user_id,
                        "user_data": data.get("ocs", {}).get("data", {})
                    })
                    time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                    
            except Exception as e:
                pass
        
        if vulnerable:
            self.findings.append({
                "type": "user_id_idor",
                "severity": "medium",
                "count": len(vulnerable),
                "endpoint": "/ocs/v2.php/apps/provisioning_api/api/v1/users/",
                "vulnerable_ids": vulnerable[:20],
                "description": "User profiles may be enumerable",
                "impact": "Information disclosure on user profiles"
            })
            self.vulnerable_ids.extend(vulnerable)
            console.print(f"    [red]Found {len(vulnerable)} accessible user profiles[/red]")

    def test_direct_file_access(self):
        """Test direct file access via webdav"""
        console.print("  [cyan]Testing direct file access...[/cyan]")
        
        common_paths = [
            "/README.md",
            "/Photos/",
            "/Documents/",
            "/test.txt",
            "/config.php",
            "/.htaccess"
        ]
        
        vulnerable = []
        for path in common_paths:
            try:
                resp = self.session.get(
                    f"{self.host}/remote.php/dav/files/{config.NEXTCLOUD_USERNAME}{path}",
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
                
                if resp.status_code == 200:
                    vulnerable.append({
                        "path": path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("content-type")
                    })
                    
            except Exception as e:
                pass
        
        if vulnerable:
            self.findings.append({
                "type": "direct_file_access",
                "severity": "medium",
                "count": len(vulnerable),
                "endpoint": "/remote.php/dav/files/",
                "accessible_paths": vulnerable,
                "description": "Files accessible via direct paths",
                "impact": "Potential unauthorized file disclosure"
            })
            console.print(f"    [red]Found {len(vulnerable)} accessible paths[/red]")

    def _generate_id_samples(self, count: int) -> List[int]:
        """Generate sample IDs for testing"""
        # Test a mix of sequential and random IDs
        ids = []
        # Sequential
        for i in range(1, min(count // 2, 50)):
            ids.append(i)
        # Random larger IDs
        import random
        for _ in range(count - len(ids)):
            ids.append(random.randint(100, 10000))
        return list(set(ids))[:count]
