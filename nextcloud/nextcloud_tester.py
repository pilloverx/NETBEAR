# nextcloud_tester.py
"""
NextCloud Vulnerability Assessment Orchestrator
Coordinates all NextCloud-specific vulnerability tests
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Any
from rich.console import Console
from requests.auth import HTTPBasicAuth
import config

# Import NextCloud test modules
from nextcloud.nc_recon import NCRecon
from nextcloud.nc_idor import NCIDOR
from nextcloud.nc_upload import NCUpload
from nextcloud.nc_auth import NCAuth
from nextcloud.nc_public_links import NCPublicLinks

console = Console()

class NextCloudTester:
    """Main orchestrator for NextCloud vulnerability assessment"""
    
    def __init__(self):
        self.host = config.NEXTCLOUD_HOST.rstrip("/")
        self.username = config.NEXTCLOUD_USERNAME
        self.password = config.NEXTCLOUD_PASSWORD
        self.session = None
        self.findings = []
        self.test_modules = {
            "recon": NCRecon,
            "idor": NCIDOR,
             "upload": NCUpload,
            "auth": NCAuth,
            "public_links": NCPublicLinks,
        }

    def setup_session(self) -> bool:
        """Create authenticated session"""
        try:
            self.session = requests.Session()
            # Test connection
            resp = self.session.get(
                f"{self.host}/status.php",
                auth=HTTPBasicAuth(self.username, self.password),
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            
            if resp.status_code == 200:
                console.print("[green]✓ Connected to NextCloud instance[/green]")
                return True
            else:
                console.print(f"[red]✗ Connection failed: HTTP {resp.status_code}[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]✗ Connection error: {str(e)}[/red]")
            return False

    def run_tests(self, test_types: List[str], session_id: str) -> List[Dict[str, Any]]:
        """Execute selected vulnerability tests"""
        
        if not self.setup_session():
            return []

        all_findings = []
        
        for test_type in test_types:
            if test_type not in self.test_modules:
                console.print(f"[yellow]⚠️ Unknown test type: {test_type}[/yellow]")
                continue
            
            try:
                console.print(f"\n[bold cyan]Running {test_type} tests...[/bold cyan]")
                module_class = self.test_modules[test_type]
                tester = module_class(self.session)
                findings = tester.run()
                all_findings.extend(findings)
                
            except Exception as e:
                console.print(f"[red]Error in {test_type}: {str(e)}[/red]")
        
        return all_findings

def test_nextcloud_connection() -> bool:
    """Test NextCloud connectivity (for CLI)"""
    try:
        session = requests.Session()
        resp = session.get(
            f"{config.NEXTCLOUD_HOST.rstrip('/')}/status.php",
            auth=HTTPBasicAuth(config.NEXTCLOUD_USERNAME, config.NEXTCLOUD_PASSWORD),
            timeout=config.NEXTCLOUD_TIMEOUT,
            verify=config.NEXTCLOUD_VERIFY_SSL
        )
        
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"[green]✓ NextCloud {data.get('version')} connected[/green]")
            return True
        else:
            console.print(f"[red]✗ HTTP {resp.status_code}[/red]")
            return False
            
    except Exception as e:
        console.print(f"[red]✗ {str(e)}[/red]")
        return False
