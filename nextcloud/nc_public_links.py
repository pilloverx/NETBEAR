# nextcloud/nc_public_links.py
"""
NextCloud Public Link Testing Module
Tests for share token leaks, enumeration, and access control
"""

import requests
import string
import random
from typing import Dict, List, Any
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
import config
import time

console = Console()

class NCPublicLinks:
    """NextCloud public link vulnerability testing"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.host = config.NEXTCLOUD_HOST.rstrip("/")
        self.findings = []
        self.valid_tokens = []

    def run(self) -> List[Dict[str, Any]]:
        """Execute public link tests"""
        console.print("[cyan]Starting public link testing...[/cyan]")
        
        # Enumerate existing shares
        self.enumerate_public_shares()
        
        # Test token enumeration
        self.test_token_enumeration()
        
        # Test share access control
        self.test_share_access_control()
        
        # Test password bypass
        self.test_password_bypass()
        
        console.print(f"[green]✓ Public link tests complete: {len(self.valid_tokens)} tokens found[/green]")
        return self.findings

    def enumerate_public_shares(self):
        """Get existing public shares (if accessible)"""
        console.print("  [cyan]Enumerating public shares...[/cyan]")
        
        try:
            resp = self.session.get(
                f"{self.host}/ocs/v2.php/apps/files_sharing/api/v1/shares?public=true",
                headers={"OCS-APIRequest": "true"},
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            if resp.status_code == 200:
                data = resp.json()
                shares = data.get("ocs", {}).get("data", [])
                
                if isinstance(shares, dict):
                    shares = list(shares.values())
                
                public_shares = []
                for share in shares:
                    if share.get("share_type") == 3:  # Public link
                        public_shares.append(share)
                        if "token" in share:
                            self.valid_tokens.append(share["token"])
                
                if public_shares:
                    self.findings.append({
                        "type": "public_shares_enumeration",
                        "severity": "medium",
                        "count": len(public_shares),
                        "shares": public_shares[:20],
                        "description": f"Found {len(public_shares)} public shares",
                        "endpoint": "/ocs/v2.php/apps/files_sharing/api/v1/shares"
                    })
                    console.print(f"    [green]Found {len(public_shares)} public shares[/green]")
                    time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                    
        except Exception as e:
            console.print(f"    [yellow]Enumeration failed: {str(e)}[/yellow]")

    def test_token_enumeration(self):
        """Test if public share tokens can be enumerated"""
        console.print("  [cyan]Testing token enumeration...[/cyan]")
        
        # Generate token patterns
        tokens = self._generate_token_candidates(config.NEXTCLOUD_PUBLIC_LINK_MAX_ATTEMPTS)
        valid_tokens = []
        
        with ThreadPoolExecutor(max_workers=config.NEXTCLOUD_MAX_WORKERS) as executor:
            futures = []
            for token in tokens:
                futures.append(executor.submit(self._test_token, token))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    valid_tokens.append(result)
                    if len(valid_tokens) % 10 == 0:
                        console.print(f"    [green]Found {len(valid_tokens)} valid tokens so far...[/green]")
        
        if valid_tokens:
            self.findings.append({
                "type": "token_enumeration",
                "severity": "high",
                "count": len(valid_tokens),
                "tokens": valid_tokens[:20],
                "description": "Public share tokens can be enumerated",
                "endpoint": "/s/",
                "impact": "Unauthorized access to shared resources"
            })
            self.valid_tokens.extend(valid_tokens)
            console.print(f"    [red]Found {len(valid_tokens)} valid tokens[/red]")

    def test_share_access_control(self):
        """Test if share permissions are properly enforced"""
        console.print("  [cyan]Testing share access control...[/cyan]")
        
        issues = []
        
        for token in self.valid_tokens[:10]:  # Test first 10 tokens
            try:
                # Test direct access
                resp = self.session.get(
                    f"{self.host}/s/{token}",
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL,
                    allow_redirects=True
                )
                
                if resp.status_code == 200:
                    # Check if content is accessible without password
                    if "password" not in resp.text.lower():
                        issues.append({
                            "token": token,
                            "issue": "No password required",
                            "accessible": True
                        })
                        console.print(f"    [red]✗ Token {token[:10]}... accessible without password[/red]")
                
                # Test API access with token
                resp = self.session.get(
                    f"{self.host}/ocs/v2.php/apps/files_sharing/api/v1/shares",
                    headers={"OCS-APIRequest": "true", "X-Requested-With": token},
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
                
                if resp.status_code == 200:
                    issues.append({
                        "token": token,
                        "issue": "Token can be used for API access",
                        "endpoint": "/ocs/v2.php/apps/files_sharing/api/v1/shares"
                    })
                    console.print(f"    [red]✗ Token reusable for API access[/red]")
                    
                time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                
            except Exception as e:
                pass
        
        if issues:
            self.findings.append({
                "type": "share_access_control",
                "severity": "high",
                "count": len(issues),
                "issues": issues,
                "description": "Share access control bypass",
                "impact": "Unauthorized access to shared resources"
            })

    def test_password_bypass(self):
        """Test if password-protected shares can be bypassed"""
        console.print("  [cyan]Testing password bypass...[/cyan]")
        
        bypass_attempts = []
        
        for token in self.valid_tokens[:5]:
            try:
                # Try empty password
                resp = self.session.post(
                    f"{self.host}/s/{token}",
                    data={"password": ""},
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
                
                if resp.status_code == 200 and "password" not in resp.text.lower():
                    bypass_attempts.append({
                        "token": token,
                        "method": "empty_password",
                        "success": True
                    })
                    console.print(f"    [red]✗ Bypass via empty password[/red]")
                
                # Try common passwords
                common_passwords = ["123456", "password", "admin", "test", ""]
                for pwd in common_passwords:
                    resp = self.session.post(
                        f"{self.host}/s/{token}",
                        data={"password": pwd},
                        timeout=config.NEXTCLOUD_TIMEOUT,
                        verify=config.NEXTCLOUD_VERIFY_SSL
                    )
                    
                    if resp.status_code == 200 and "password" not in resp.text.lower():
                        bypass_attempts.append({
                            "token": token,
                            "method": f"weak_password_{pwd}",
                            "success": True
                        })
                        console.print(f"    [red]✗ Bypass via weak password: {pwd}[/red]")
                        break
                    
                    time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
                    
            except Exception as e:
                pass
        
        if bypass_attempts:
            self.findings.append({
                "type": "password_bypass",
                "severity": "high",
                "count": len(bypass_attempts),
                "attempts": bypass_attempts,
                "description": "Password-protected shares can be bypassed",
                "impact": "Unauthorized access to sensitive shared resources"
            })

    def _test_token(self, token: str) -> Dict[str, Any]:
        """Test if a token is valid"""
        try:
            resp = self.session.get(
                f"{self.host}/s/{token}",
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL,
                allow_redirects=False
            )
            
            if resp.status_code in [200, 302]:  # 200 = accessible, 302 = redirect (still valid)
                return {"token": token, "status": resp.status_code}
            
        except Exception as e:
            pass
        
        return {}

    def _generate_token_candidates(self, count: int) -> List[str]:
        """Generate possible public share tokens"""
        tokens = []
        
        # Common token patterns in NextCloud
        chars = string.ascii_letters + string.digits
        
        # Random tokens
        for _ in range(count):
            token = "".join(random.choice(chars) for _ in range(15))
            tokens.append(token)
        
        # Sequential patterns
        for i in range(100, min(100 + count, 1000)):
            tokens.append(f"share{i}")
        
        return tokens[:count]
