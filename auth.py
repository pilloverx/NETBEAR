# auth.py
"""
Authentication handler for Juice Shop, Doctolib, and other login-required sites.
Supports multiple login patterns and credential management.
"""

from playwright.sync_api import Page
from typing import Optional
import time

class LoginHandler:
    """Generic login handler for common web app patterns."""
    
    @staticmethod
    def login_juice_shop(page: Page, email="demo@juice.sh", password="demo"):
        """
        Juice Shop specific login.
        Default demo credentials work on all Juice Shop instances.
        """
        try:
            page.goto("https://juice-shop.herokuapp.com/#/login", wait_until="networkidle")
            time.sleep(1)
            
            # Fill email
            page.fill('#email', email)
            time.sleep(0.5)
            
            # Fill password
            page.fill('#password', password)
            time.sleep(0.5)
            
            # Click login button
            page.click('button[type="submit"]')
            
            # Wait for redirect (scoreboard or dashboard visible)
            try:
                page.wait_for_selector('.ribbon', timeout=5000)
                print(f"[Auth] ✅ Juice Shop login successful for {email}")
                return True
            except:
                print(f"[Auth] ⚠️ Juice Shop login may have failed - no ribbon detected")
                return False
                
        except Exception as e:
            print(f"[Auth] ❌ Juice Shop login error: {e}")
            return False
    
    @staticmethod
    def login_doctolib(page: Page, email="test@example.com", password="test123"):
        """
        Generic Doctolib login pattern.
        Requires valid test credentials - replace with bounty program creds.
        """
        try:
            page.goto("https://www.doctolib.fr/login", wait_until="networkidle")
            time.sleep(1)
            
            # Fill email
            email_input = page.locator('input[type="email"]')
            email_input.fill(email)
            time.sleep(0.5)
            
            # Fill password
            password_input = page.locator('input[type="password"]')
            password_input.fill(password)
            time.sleep(0.5)
            
            # Click login button
            page.click('button[type="submit"]')
            
            # Wait for authenticated state
            try:
                page.wait_for_url("**/profile**", timeout=5000)
                print(f"[Auth] ✅ Doctolib login successful")
                return True
            except:
                print(f"[Auth] ⚠️ Doctolib login may have failed")
                return False
                
        except Exception as e:
            print(f"[Auth] ❌ Doctolib login error: {e}")
            return False
    
    @staticmethod
    def login_generic(page: Page, email_field: str, password_field: str, 
                     submit_button: str, email: str, password: str, 
                     wait_selector: Optional[str] = None, url: Optional[str] = None):
        """
        Generic login handler for custom sites.
        
        Args:
            page: Playwright page object
            email_field: CSS selector for email input
            password_field: CSS selector for password input
            submit_button: CSS selector for submit button
            email: Email/username to use
            password: Password to use
            wait_selector: Optional selector to wait for after login (indicates success)
            url: Optional URL to navigate to before login
        """
        try:
            if url:
                page.goto(url, wait_until="networkidle")
            
            time.sleep(1)
            
            # Fill credentials
            page.fill(email_field, email)
            time.sleep(0.3)
            page.fill(password_field, password)
            time.sleep(0.3)
            
            # Submit form
            page.click(submit_button)
            
            # Wait for success indicator if provided
            if wait_selector:
                try:
                    page.wait_for_selector(wait_selector, timeout=5000)
                    print(f"[Auth] ✅ Generic login successful")
                    return True
                except:
                    print(f"[Auth] ⚠️ Login completed but success indicator not found")
                    return False
            else:
                time.sleep(2)  # Simple wait
                print(f"[Auth] ✅ Generic login completed")
                return True
                
        except Exception as e:
            print(f"[Auth] ❌ Generic login error: {e}")
            return False
    
    @staticmethod
    def preserve_auth_context(page: Page):
        """
        Capture and preserve authentication state (cookies, storage).
        Returns dict with auth context for later restoration.
        """
        try:
            cookies = page.context.cookies()
            local_storage = page.evaluate("() => JSON.stringify(localStorage)")
            session_storage = page.evaluate("() => JSON.stringify(sessionStorage)")
            
            auth_context = {
                "cookies": cookies,
                "local_storage": local_storage,
                "session_storage": session_storage
            }
            print(f"[Auth] ✅ Captured auth context ({len(cookies)} cookies)")
            return auth_context
        except Exception as e:
            print(f"[Auth] ⚠️ Could not preserve auth context: {e}")
            return {}
    
    @staticmethod
    def restore_auth_context(page: Page, auth_context: dict):
        """
        Restore previously captured authentication state.
        """
        try:
            if "cookies" in auth_context:
                page.context.add_cookies(auth_context["cookies"])
            
            if "local_storage" in auth_context:
                page.evaluate(
                    f"(data) => Object.entries(data).forEach(([k, v]) => localStorage.setItem(k, v))",
                    {"data": eval(auth_context["local_storage"])}
                )
            
            print(f"[Auth] ✅ Restored auth context")
            return True
        except Exception as e:
            print(f"[Auth] ⚠️ Could not restore auth context: {e}")
            return False
