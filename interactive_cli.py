# interactive_cli.py
"""
Interactive CLI menu system for unified security testing framework
Supports: NetBear (web crawling), NextCloud (vulnerability assessment)
"""

import os
import sys
import json
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# Import modules
import config

class InteractiveCLI:
    def __init__(self):
        self.selected_mode = None
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            "session_id": self.session_id,
            "mode": None,
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "summary": {}
        }

    def main_menu(self):
        """Display main menu and route user"""
        console.print(Panel.fit(
            "[bold blue]🔒 NetBear Security Framework[/bold blue]\n"
            "[cyan]Modular vulnerability assessment & reconnaissance[/cyan]",
            box=box.ROUNDED
        ))

        menu_options = [
            ("1", "NetBear - Web Crawling & Reconnaissance"),
            ("2", "NextCloud - Vulnerability Assessment"),
            ("3", "Doctolib - Healthcare Platform Recon"),
            ("4", "Exit")
        ]

        console.print("\n[bold]Select Mode:[/bold]\n")
        for key, desc in menu_options:
            console.print(f"  [{key}] {desc}")

        choice = Prompt.ask("\nChoose", choices=["1", "2", "3", "4"])

        if choice == "1":
            self.netbear_menu()
        elif choice == "2":
            self.nextcloud_menu()
        elif choice == "3":
            self.doctolib_menu()
        else:
            console.print("[yellow]Exiting...[/yellow]")
            sys.exit(0)

    def netbear_menu(self):
        """NetBear-specific menu"""
        self.selected_mode = "netbear"
        self.results["mode"] = "netbear"
        
        console.print(Panel.fit(
            "[bold cyan]🕷️  NetBear - Web Crawling[/bold cyan]\n"
            "Depth-based reconnaissance with scope validation",
            box=box.SQUARE
        ))

        console.print("\n[cyan]Configuration:[/cyan]")
        
        # Show current targets
        if os.path.exists(config.TARGETS_FILE):
            with open(config.TARGETS_FILE, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            console.print(f"  Targets: [green]{len(targets)}[/green] loaded from {config.TARGETS_FILE}")
        else:
            console.print(f"  [yellow]⚠️ No {config.TARGETS_FILE} found[/yellow]")

        # Prompt for modifications
        modify = Confirm.ask("Modify settings", default=False)
        if modify:
            self.netbear_settings_menu()

        # Start crawl
        confirm = Confirm.ask("Start NetBear crawl", default=True)
        if confirm:
            self.run_netbear()
        else:
            self.main_menu()

    def netbear_settings_menu(self):
        """Configure NetBear parameters"""
        console.print("\n[bold]NetBear Settings:[/bold]")
        
        max_depth = Prompt.ask("Max crawl depth", default=str(config.NETBEAR_MAX_DEPTH))
        config.NETBEAR_MAX_DEPTH = int(max_depth)
        
        max_pages = Prompt.ask("Max pages per domain", default=str(config.NETBEAR_MAX_PAGES_PER_DOMAIN))
        config.NETBEAR_MAX_PAGES_PER_DOMAIN = int(max_pages)
        
        rate_limit = Prompt.ask("Rate limit (sec)", default=str(config.NETBEAR_RATE_LIMIT_SEC))
        config.NETBEAR_RATE_LIMIT_SEC = float(rate_limit)

    def netbear_wrapper(self):
        """Import and run NetBear"""
        from netbear_crawler import main as netbear_main
        try:
            netbear_main()
            console.print("[green]✓ NetBear crawl completed[/green]")
        except Exception as e:
            console.print(f"[red]✗ NetBear error: {str(e)}[/red]")
            self.results["summary"]["error"] = str(e)

    def nextcloud_menu(self):
        """NextCloud-specific menu"""
        self.selected_mode = "nextcloud"
        self.results["mode"] = "nextcloud"
        
        console.print(Panel.fit(
            "[bold magenta]☁️  NextCloud - Vulnerability Assessment[/bold magenta]\n"
            "IDOR, Upload Abuse, Auth Escalation, Public Links",
            box=box.SQUARE
        ))

        # Get NextCloud credentials
        console.print("\n[bold cyan]Target Configuration:[/bold cyan]")
        host = Prompt.ask("NextCloud Host", default=config.NEXTCLOUD_HOST)
        username = Prompt.ask("Username", default=config.NEXTCLOUD_USERNAME)
        password = Prompt.ask("Password", password=True)

        config.NEXTCLOUD_HOST = host
        config.NEXTCLOUD_USERNAME = username
        config.NEXTCLOUD_PASSWORD = password

        # Test connection
        console.print("\n[cyan]Testing connection...[/cyan]")
        from nextcloud_tester import test_nextcloud_connection
        is_valid = test_nextcloud_connection()
        
        if not is_valid:
            console.print("[red]✗ Connection failed[/red]")
            return self.main_menu()

        # Select tests
        console.print("\n[bold cyan]Available Tests:[/bold cyan]\n")
        tests = self.nextcloud_test_selection_menu()
        
        if not tests:
            return self.nextcloud_menu()

        # Configure test params
        console.print("\n[bold cyan]Test Parameters:[/bold cyan]")
        self.nextcloud_settings_menu()

        # Start tests
        confirm = Confirm.ask("Start tests", default=True)
        if confirm:
            self.run_nextcloud(tests)
        else:
            self.nextcloud_menu()

    def nextcloud_test_selection_menu(self):
        """Select which NextCloud tests to run"""
        test_options = [
            ("1", "Recon - Enumerate users, shares, public links"),
            ("2", "IDOR - Test ID enumeration in files/shares"),
            ("3", "Upload Abuse - Test file type bypass & RCE/XSS"),
            ("4", "Auth Escalation - Test privilege elevation"),
            ("5", "Public Links - Enumerate & analyze shared resources"),
            ("6", "All Tests"),
            ("7", "Back to Main Menu")
        ]

        for key, desc in test_options:
            console.print(f"  [{key}] {desc}")

        choice = Prompt.ask("Select tests (comma-separated)", default="6")
        
        if choice == "7":
            return None
        
        selected_tests = []
        if choice == "6":
            selected_tests = ["recon", "idor", "upload", "auth", "public_links"]
        else:
            test_map = {
                "1": "recon",
                "2": "idor",
                "3": "upload",
                "4": "auth",
                "5": "public_links"
            }
            for c in choice.split(","):
                c = c.strip()
                if c in test_map:
                    selected_tests.append(test_map[c])

        return selected_tests

    def nextcloud_settings_menu(self):
        """Configure NextCloud test parameters"""
        console.print("  IDOR sample size:", end=" ")
        config.NEXTCLOUD_IDOR_SAMPLE_SIZE = int(Prompt.ask(
            "default", default=str(config.NEXTCLOUD_IDOR_SAMPLE_SIZE)
        ))

        console.print("  Concurrent workers:", end=" ")
        config.NEXTCLOUD_MAX_WORKERS = int(Prompt.ask(
            "default", default=str(config.NEXTCLOUD_MAX_WORKERS)
        ))

        console.print("  Rate limit (sec):", end=" ")
        config.NEXTCLOUD_RATE_LIMIT_SEC = float(Prompt.ask(
            "default", default=str(config.NEXTCLOUD_RATE_LIMIT_SEC)
        ))

    def run_netbear(self):
        """Execute NetBear with user settings"""
        console.print(Panel.fit(
            "[bold]🕷️  Running NetBear...[/bold]",
            box=box.ROUNDED
        ))
        self.netbear_wrapper()
        self.show_results_menu()

    def run_nextcloud(self, tests):
        """Execute NextCloud tests with user settings"""
        console.print(Panel.fit(
            f"[bold]☁️  Running NextCloud Tests...[/bold]\n{', '.join(tests)}",
            box=box.ROUNDED
        ))

        from nextcloud_tester import NextCloudTester
        tester = NextCloudTester()
        findings = tester.run_tests(tests, self.session_id)
        
        self.results["findings"] = findings
        self.results["summary"] = {
            "total_tests": len(tests),
            "findings_count": len(findings),
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"])
        }

        self.show_results_menu()

    def doctolib_menu(self):
        """Doctolib-specific menu"""
        self.selected_mode = "doctolib"
        self.results["mode"] = "doctolib"
        
        console.print(Panel.fit(
            "[bold cyan]🏥 Doctolib - Healthcare Platform Recon[/bold cyan]\n"
            "Specialized reconnaissance with dynamic content analysis",
            box=box.SQUARE
        ))
        
        console.print("\n[cyan]Doctolib Recon Options:[/cyan]")
        console.print("  [1] Full automated recon (all modes)")
        console.print("  [2] Public search & doctor profiles")
        console.print("  [3] Appointment flow analysis")
        console.print("  [4] Static page analysis")
        console.print("  [5] Authenticated crawl (requires credentials)")
        console.print("  [6] Custom selection")
        
        choice = Prompt.ask("Select", choices=["1", "2", "3", "4", "5", "6"])
        
        # Launch doctolib recon runner
        import subprocess
        result = subprocess.run([sys.executable, "run_doctolib_recon.py"], cwd=os.path.dirname(__file__))
        
        if Confirm.ask("Return to main menu", default=True):
            self.main_menu()

    def show_results_menu(self):

        """Display results and save options"""
        console.print(Panel.fit(
            "[bold green]✓ Testing Complete[/bold green]",
            box=box.ROUNDED
        ))

        # Show summary
        summary = self.results.get("summary", {})
        console.print(f"\n[cyan]Summary:[/cyan]")
        for key, val in summary.items():
            console.print(f"  {key}: {val}")

        # Save results
        confirm = Confirm.ask("Save results as JSON", default=True)
        if confirm:
            self.save_results()

        # Back to menu
        if Confirm.ask("Return to main menu", default=True):
            self.main_menu()

    def save_results(self):
        """Save results to JSON file"""
        import os
        report_dir = os.path.join(config.REPORTS_DIR, self.session_id)
        os.makedirs(report_dir, exist_ok=True)

        report_path = os.path.join(report_dir, f"{self.selected_mode}_report.json")
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)

        console.print(f"[green]✓ Report saved:[/green] {report_path}")

def main():
    """Entry point"""
    try:
        cli = InteractiveCLI()
        cli.main_menu()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Fatal error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
