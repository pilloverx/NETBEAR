# demo_workflow.py
"""
NextCloud Assessment - Demo Workflow
Shows how to use the framework programmatically (non-interactive)
"""

import json
import os
from datetime import datetime

# Configure NextCloud target
import config
config.NEXTCLOUD_HOST = "https://your-nextcloud.example.com"
config.NEXTCLOUD_USERNAME = "testuser"
config.NEXTCLOUD_PASSWORD = "testpass"
config.NEXTCLOUD_VERIFY_SSL = True

# Optional: Customize test parameters
config.NEXTCLOUD_IDOR_SAMPLE_SIZE = 50
config.NEXTCLOUD_MAX_WORKERS = 5
config.NEXTCLOUD_RATE_LIMIT_SEC = 0.5

from nextcloud_tester import NextCloudTester
from rich.console import Console

console = Console()

def demo_nextcloud_assessment():
    """Run a programmatic NextCloud assessment"""
    
    console.print("""
    [bold cyan]NextCloud Vulnerability Assessment - Programmatic Demo[/bold cyan]
    
    This script demonstrates how to use the framework
    without the interactive CLI.
    """)
    
    # Initialize tester
    tester = NextCloudTester()
    
    # Select which tests to run
    tests_to_run = [
        "recon",           # Enumeration
        "idor",            # ID testing
        # "upload",        # File upload (use with caution!)
        "auth",            # Auth escalation
        "public_links",    # Public link testing
    ]
    
    console.print(f"[cyan]Tests to run:[/cyan] {', '.join(tests_to_run)}\n")
    
    # Run assessment
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    findings = tester.run_tests(tests_to_run, session_id)
    
    # Display summary
    console.print(f"\n[bold green]Assessment Complete[/bold green]")
    console.print(f"[cyan]Findings:[/cyan] {len(findings)}")
    
    # Categorize findings
    severity_counts = {}
    for finding in findings:
        severity = finding.get("severity", "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    console.print("\n[cyan]Breakdown:[/cyan]")
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            console.print(f"  {severity.upper()}: {count}")
    
    # Save results
    results = {
        "session_id": session_id,
        "mode": "nextcloud",
        "timestamp": datetime.now().isoformat(),
        "tests_run": tests_to_run,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts
        }
    }
    
    # Create output directory
    report_dir = os.path.join(config.REPORTS_DIR, session_id)
    os.makedirs(report_dir, exist_ok=True)
    
    # Save JSON report
    report_path = os.path.join(report_dir, "nextcloud_demo_report.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    
    console.print(f"\n[green]✓ Report saved:[/green] {report_path}")
    
    # Print top findings
    console.print("\n[bold cyan]Top Findings:[/bold cyan]")
    critical_high = [f for f in findings if f.get("severity") in ["critical", "high"]]
    for i, finding in enumerate(critical_high[:5], 1):
        console.print(f"\n  {i}. {finding['type'].upper()}")
        console.print(f"     Severity: [red]{finding.get('severity')}[/red]")
        console.print(f"     {finding.get('description', 'N/A')}")
        if "count" in finding:
            console.print(f"     Count: {finding['count']}")


def demo_custom_workflow():
    """Example of custom assessment workflow"""
    
    console.print("""
    [bold cyan]Custom Assessment Workflow[/bold cyan]
    
    This demonstrates how to build custom workflows
    for specific assessment scenarios.
    """)
    
    from nextcloud.nc_recon import NCRecon
    from nextcloud.nc_idor import NCIDOR
    from requests.auth import HTTPBasicAuth
    import requests

    # Create a session
    session = requests.Session()

    # Correctly assign authentication using HTTPBasicAuth
    username = "your_username"
    password = "your_password"
    session.auth = HTTPBasicAuth(username, password)

    # Now you can use the session for authenticated requests
    response = session.get("https://example.com/protected-resource")
    print(response.status_code)
    try:
        # Test connection
        resp = session.get(
            f"{config.NEXTCLOUD_HOST}/status.php",
            timeout=10,
            verify=config.NEXTCLOUD_VERIFY_SSL
        )
        
        if resp.status_code == 200:
            console.print("[green]✓ Connected to NextCloud[/green]")
            
            # Run specific tests
            console.print("\n[cyan]Running recon...[/cyan]")
            recon = NCRecon(session)
            recon_findings = recon.run()
            console.print(f"[green]Found {len(recon_findings)} recon findings[/green]")
            
            console.print("\n[cyan]Running IDOR tests...[/cyan]")
            idor = NCIDOR(session)
            idor_findings = idor.run()
            console.print(f"[green]Found {len(idor_findings)} IDOR findings[/green]")
            
            # Combine results
            all_findings = recon_findings + idor_findings
            return all_findings
        else:
            console.print(f"[red]Connection failed: HTTP {resp.status_code}[/red]")
            return []
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        return []


def show_finding_examples():
    """Display example findings structure"""
    
    console.print("""
    [bold cyan]Example Finding Structures[/bold cyan]
    """)
    
    examples = [
        {
            "type": "user_enumeration",
            "severity": "high",
            "description": "Exposed 42 user IDs via OCS API",
            "endpoint": "/ocs/v2.php/apps/provisioning_api/api/v1/users",
            "impact": "Attackers can enumerate valid user accounts",
            "users_sample": ["user1", "user2", "admin"],
            "recommendation": "Restrict OCS API access or require authentication"
        },
        {
            "type": "file_id_idor",
            "severity": "critical",
            "description": "15 file IDs accessible via WebDAV",
            "endpoint": "/remote.php/dav/files/",
            "impact": "Users can access files belonging to other users",
            "vulnerable_ids": [1, 3, 5, 7, 9],
            "recommendation": "Implement proper authorization checks in file access"
        },
        {
            "type": "file_type_bypass",
            "severity": "critical",
            "description": "PHP files executable via upload",
            "endpoint": "/remote.php/webdav/",
            "impact": "Remote Code Execution - attacker can execute arbitrary code",
            "bypassed_checks": ["double extension", "case variation"],
            "recommendation": "Use whitelist approach, disable script execution in upload dir"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        console.print(f"\n[bold]Example {i}: {example['type']}[/bold]")
        for key, value in example.items():
            if key != "type":
                console.print(f"  {key}: {value}")


def main():
    """Main demo entry point"""
    
    console.print("""
    ╔════════════════════════════════════════════════════════════╗
    ║     NextCloud Assessment Framework - Demo Script           ║
    ║                                                            ║
    ║  Usage:                                                    ║
    ║    1. Update config at top of file with your NC instance  ║
    ║    2. Run: python demo_workflow.py                         ║
    ║    3. Choose demo option                                   ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    console.print("\n[cyan]Demo Options:[/cyan]\n")
    console.print("  [1] Full NextCloud Assessment")
    console.print("  [2] Custom Workflow Example")
    console.print("  [3] Show Example Findings")
    console.print("  [4] Exit")
    
    choice = input("\nSelect option (1-4): ").strip()
    
    if choice == "1":
        console.print("\n⚠️  [yellow]Make sure to update config at top of file[/yellow]")
        demo_nextcloud_assessment()
    elif choice == "2":
        console.print("\n⚠️  [yellow]Make sure to update config at top of file[/yellow]")
        demo_custom_workflow()
    elif choice == "3":
        show_finding_examples()
    elif choice == "4":
        console.print("[yellow]Exiting[/yellow]")
    else:
        console.print("[red]Invalid option[/red]")


if __name__ == "__main__":
    main()
