import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import dns.resolver
import whois
import socket
import ssl
import json
from datetime import datetime
import threading
import queue
from typing import Dict, Any
import logging
from geopy.geocoders import Nominatim
import re
import subprocess
import sublist3r
import requests

class DNSAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Analysis Toolkit -d3 ")
        # Set minimum window size
        self.root.minsize(800, 600)

        # Initialize DNS resolver
        self.resolver = dns.resolver.Resolver()

        # Initialize settings
        self.settings = {
            'timeout': 10,
            'logging_level': logging.INFO
        }

        # Setup logging
        self.setup_logging()

        # Initialize dark mode
        self.dark_mode = tk.BooleanVar(value=False)
        self.dark_mode.trace_add("write", self.toggle_dark_mode)

        # Create main frames
        self.create_frames()

        # Create input section
        self.create_input_section()

        # Create analysis options
        self.create_analysis_options()

        # Create output section
        self.create_output_section()

        # Create status bar
        self.create_status_bar()

        # Initialize queue for thread-safe GUI updates
        self.queue = queue.Queue()

        # Start queue processing
        self.process_queue()

    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=self.settings['logging_level'],
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("dns_analyzer.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def create_frames(self):
        """Create main application frames"""
        # Input frame (top)
        self.input_frame = ttk.LabelFrame(self.root, text="Domain Input", padding="10")
        self.input_frame.pack(fill=tk.X, padx=10, pady=5)

        # Options frame (middle)
        self.options_frame = ttk.LabelFrame(self.root, text="Analysis Options", padding="10")
        self.options_frame.pack(fill=tk.X, padx=10, pady=5)

        # Output frame (bottom)
        self.output_frame = ttk.LabelFrame(self.root, text="Analysis Results", padding="10")
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def create_input_section(self):
        """Create domain input section"""
        # Domain entry
        ttk.Label(self.input_frame, text="Domain:").pack(side=tk.LEFT)
        self.domain_entry = ttk.Entry(self.input_frame, width=40)
        self.domain_entry.pack(side=tk.LEFT, padx=5)

        # Analyze button
        self.analyze_button = ttk.Button(
            self.input_frame,
            text="Analyze",
            command=self.start_analysis
        )
        self.analyze_button.pack(side=tk.LEFT, padx=5)

        # Clear button
        self.clear_button = ttk.Button(
            self.input_frame,
            text="Clear",
            command=self.clear_output
        )
        self.clear_button.pack(side=tk.LEFT)

        # Help button
        self.help_button = ttk.Button(
            self.input_frame,
            text="Help",
            command=self.show_help
        )
        self.help_button.pack(side=tk.LEFT, padx=5)

        # Save Results button
        self.save_button = ttk.Button(
            self.input_frame,
            text="Save Results",
            command=self.save_results
        )
        self.save_button.pack(side=tk.LEFT, padx=5)

        # Load Domain List button
        self.load_button = ttk.Button(
            self.input_frame,
            text="Load Domain List",
            command=self.load_domain_list
        )
        self.load_button.pack(side=tk.LEFT, padx=5)

        # Dark Mode toggle
        self.dark_mode_check = ttk.Checkbutton(
            self.input_frame,
            text="Dark Mode",
            variable=self.dark_mode
        )
        self.dark_mode_check.pack(side=tk.LEFT, padx=5)

    def create_analysis_options(self):
        """Create analysis options checkboxes"""
        # Analysis options
        self.options = {
            'whois': tk.BooleanVar(value=True),
            'dns_records': tk.BooleanVar(value=True),
            'ssl': tk.BooleanVar(value=True),
            'security': tk.BooleanVar(value=True),
            'reputation': tk.BooleanVar(value=True),
            'geolocation': tk.BooleanVar(value=True),  # New option for geolocation
            'subdomains': tk.BooleanVar(value=True)    # New option for subdomain enumeration
        }

        # Create checkboxes
        for i, (option, var) in enumerate(self.options.items()):
            ttk.Checkbutton(
                self.options_frame,
                text=option.replace('_', ' ').title(),
                variable=var
            ).pack(side=tk.LEFT, padx=10)

    def create_output_section(self):
        """Create output section with notebook tabs"""
        # Create notebook for tabbed output
        self.notebook = ttk.Notebook(self.output_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs
        self.tabs = {
            'Results': scrolledtext.ScrolledText(self.notebook, wrap=tk.WORD),
            'Raw Data': scrolledtext.ScrolledText(self.notebook, wrap=tk.WORD)
        }

        # Add tabs to notebook
        for name, widget in self.tabs.items():
            self.notebook.add(widget, text=name)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.output_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)

    def create_status_bar(self):
        """Create status bar"""
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X, padx=5, pady=2)
        self.status_var.set("Ready")

    def update_status(self, message: str):
        """Update status bar message"""
        self.queue.put(('status', message))

    def process_queue(self):
        """Process queued GUI updates"""
        try:
            while True:
                action, data = self.queue.get_nowait()
                if action == 'status':
                    self.status_var.set(data)
                elif action == 'result':
                    self.update_output(data)
                elif action == 'error':
                    messagebox.showerror("Error", data)
                elif action == 'progress':
                    self.progress_var.set(data)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def start_analysis(self):
        """Start domain analysis in a separate thread"""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Error", "Please enter a domain name")
            return

        # Strip protocol from the domain name
        domain = re.sub(r'^https?://', '', domain)

        # Disable analyze button during analysis
        self.analyze_button.state(['disabled'])
        self.update_status("Analysis in progress...")

        # Start analysis thread
        thread = threading.Thread(
            target=self.perform_analysis,
            args=(domain,)
        )
        thread.daemon = True
        thread.start()

    def perform_analysis(self, domain: str):
        """Perform domain analysis"""
        try:
            results = {}

            # Perform selected analyses
            if self.options['whois'].get():
                self.update_status("Getting WHOIS information...")
                results['whois'] = self.get_whois_info(domain)

            if self.options['dns_records'].get():
                self.update_status("Getting DNS records...")
                results['dns_records'] = self.get_dns_records(domain)

            if self.options['ssl'].get():
                self.update_status("Analyzing SSL certificate...")
                results['ssl'] = self.get_ssl_info(domain)

            if self.options['security'].get():
                self.update_status("Performing security checks...")
                results['security'] = self.check_security(domain)

            if self.options['reputation'].get():
                self.update_status("Checking domain reputation...")
                results['reputation'] = self.check_reputation(domain)

            if self.options['geolocation'].get():
                self.update_status("Getting geolocation information...")
                ip_address = socket.gethostbyname(domain)
                results['geolocation'] = self.get_geolocation(ip_address)

            if self.options['subdomains'].get():
                self.update_status("Enumerating subdomains...")
                results['subdomains'] = self.enumerate_subdomains(domain)

            # Queue results for display
            self.queue.put(('result', results))
            self.update_status("Analysis complete")

        except Exception as e:
            self.logger.error(f"Analysis error: {str(e)}")
            self.queue.put(('error', f"Analysis error: {str(e)}"))
            self.update_status("Analysis failed")
        finally:
            # Re-enable analyze button
            self.root.after(0, lambda: self.analyze_button.state(['!disabled']))

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information using whois"""
        try:
            self.logger.info(f"Fetching WHOIS information for {domain}")
            w = whois.whois(domain)
            self.logger.info(f"WHOIS information retrieved for {domain}")
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except Exception as e:
            self.logger.error(f"Unexpected error for {domain}: {str(e)}")
            return {'error': str(e)}

    def get_dns_records(self, domain: str) -> Dict[str, list]:
        """Get DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        results = {}

        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                results[record_type] = [f"Error: {str(e)}"]

        return results

    def get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.settings['timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
        except ssl.SSLError as e:
            return {'error': f"SSL Error: {str(e)}"}
        except socket.timeout:
            return {'error': "Connection timed out"}
        except Exception as e:
            return {'error': str(e)}

    def check_security(self, domain: str) -> Dict[str, Any]:
        """Perform security checks"""
        return {
            'spf': self.check_spf(domain),
            'dmarc': self.check_dmarc(domain),
            'dnssec': self.check_dnssec(domain)
        }

    def check_spf(self, domain: str) -> Dict[str, Any]:
        """Check SPF record"""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            spf_records = [str(r) for r in answers if 'v=spf1' in str(r)]
            return {
                'exists': bool(spf_records),
                'records': spf_records
            }
        except Exception as e:
            return {'error': str(e)}

    def check_dmarc(self, domain: str) -> Dict[str, Any]:
        """Check DMARC record"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [str(r) for r in answers if 'v=DMARC1' in str(r)]
            return {
                'exists': bool(dmarc_records),
                'records': dmarc_records
            }
        except Exception as e:
            return {'error': str(e)}

    def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC implementation"""
        try:
            answers = self.resolver.resolve(domain, 'DS')
            return {
                'enabled': True,
                'records': [str(r) for r in answers]
            }
        except dns.resolver.NoAnswer:
            return {'enabled': False}
        except Exception as e:
            return {'error': str(e)}

    def check_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using an external API"""
        try:
            api_key = "YOUR_API_KEY"  # Replace with your actual API key
            response = requests.get(f"https://api.example.com/reputation?domain={domain}&apikey={api_key}")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.error(f"Reputation check error: {str(e)}")
            return {'error': str(e)}

    def get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for an IP address"""
        try:
            geolocator = Nominatim(user_agent="dns_analyzer")
            location = geolocator.geocode(ip)
            return {
                'address': location.address,
                'latitude': location.latitude,
                'longitude': location.longitude
            }
        except Exception as e:
            self.logger.error(f"Geolocation error for IP {ip}: {str(e)}")
            return {'error': str(e)}

    def enumerate_subdomains(self, domain: str) -> Dict[str, Any]:
        """Enumerate subdomains using Sublist3r"""
        try:
            self.logger.info(f"Enumerating subdomains for {domain} using Sublist3r")
            subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=False, verbose=False, enable_bruteforce=False, engines=None)
            return {
                'subdomains': subdomains,
                'count': len(subdomains)
            }
        except Exception as e:
            self.logger.error(f"Unexpected error during subdomain enumeration: {str(e)}")
            return {'error': str(e)}

    def update_output(self, results: Dict[str, Any]):
        """Update output tabs with analysis results"""
        # Clear existing output
        for tab in self.tabs.values():
            tab.delete('1.0', tk.END)

        # Update Results tab with formatted output
        self.tabs['Results'].insert(tk.END, self.format_results(results))

        # Update Raw Data tab with JSON
        self.tabs['Raw Data'].insert(tk.END, json.dumps(results, indent=2))

    def format_results(self, results: Dict[str, Any]) -> str:
        """Format results for display"""
        output = []

        if 'whois' in results:
            output.append("=== WHOIS Information ===")
            whois_info = results['whois']
            output.append(f"Registrar: {whois_info.get('registrar', 'N/A')}")
            output.append(f"Created: {whois_info.get('creation_date', 'N/A')}")
            output.append(f"Expires: {whois_info.get('expiration_date', 'N/A')}")
            output.append("")

        if 'dns_records' in results:
            output.append("=== DNS Records ===")
            for record_type, records in results['dns_records'].items():
                output.append(f"{record_type} Records:")
                for record in records:
                    output.append(f"  {record}")
            output.append("")

        if 'ssl' in results:
            output.append("=== SSL Certificate ===")
            ssl_info = results['ssl']
            if 'error' not in ssl_info:
                output.append(f"Issuer: {ssl_info['issuer']}")
                output.append(f"Valid From: {ssl_info['notBefore']}")
                output.append(f"Valid Until: {ssl_info['notAfter']}")
            else:
                output.append(f"SSL Error: {ssl_info['error']}")
            output.append("")

        if 'security' in results:
            output.append("=== Security Checks ===")
            security = results['security']
            output.append(f"SPF: {security['spf']}")
            output.append(f"DMARC: {security['dmarc']}")
            output.append(f"DNSSEC: {security['dnssec']}")
            output.append("")

        if 'geolocation' in results:
            output.append("=== Geolocation Information ===")
            geolocation = results['geolocation']
            if 'error' not in geolocation:
                output.append(f"Address: {geolocation['address']}")
                output.append(f"Latitude: {geolocation['latitude']}")
                output.append(f"Longitude: {geolocation['longitude']}")
            else:
                output.append(f"Geolocation Error: {geolocation['error']}")
            output.append("")

        if 'subdomains' in results:
            output.append("=== Subdomain Enumeration ===")
            subdomains = results['subdomains']
            if 'error' not in subdomains:
                output.append(f"Subdomains: {subdomains['subdomains']}")
                output.append(f"Count: {subdomains['count']}")
            else:
                output.append(f"Subdomain Enumeration Error: {subdomains['error']}")
            output.append("")

        return "\n".join(output)

    def clear_output(self):
        """Clear all output tabs"""
        for tab in self.tabs.values():
            tab.delete('1.0', tk.END)
        self.status_var.set("Ready")

    def show_help(self):
        """Show help information in a new tab"""
        help_text = """
        === DNS Analysis Toolkit Help ===

        This tool is designed to perform various analyses on a given domain. Below is a detailed guide on each feature:

        1. WHOIS Information:
           - Provides details about the domain registrar, creation date, expiration date, and name servers.
           - Importance: Helps in understanding the domain's registration details and history.

        2. DNS Records:
           - Retrieves various DNS records such as A, AAAA, MX, NS, TXT, and SOA.
           - Importance: Essential for understanding the domain's DNS configuration and troubleshooting DNS issues.

           DNS Record Types:
           - A Record: Maps a domain name to an IPv4 address.
           - AAAA Record: Maps a domain name to an IPv6 address.
           - MX Record: Specifies the mail servers responsible for receiving email on behalf of the domain.
           - NS Record: Specifies the authoritative name servers for the domain.
           - TXT Record: Allows an administrator to insert arbitrary text into the DNS record. Often used for verification and security purposes.
           - SOA Record: Specifies authoritative information about a DNS zone, particularly the primary authoritative name server for the zone.

        3. SSL Certificate:
           - Analyzes the SSL certificate of the domain.
           - Importance: Ensures the domain's SSL certificate is valid and secure.

        4. Security Checks:
           - Performs checks for SPF, DMARC, and DNSSEC.
           - SPF (Sender Policy Framework):

            Allows domain owners to specify which mail servers are permitted to send emails on behalf of their domain.
            Helps prevent unauthorized parties from sending emails that appear to come from your domain, reducing the risk of email spoofing and phishing attacks.

           - DMARC (Domain-based Message Authentication, Reporting, and Conformance):

            Builds upon SPF and DKIM to provide a policy framework that allows domain owners to specify how email receivers should handle messages that fail authentication checks.
            Provides a reporting mechanism to monitor and improve email authentication practices.

           - DNSSEC (Domain Name System Security Extensions):

            Adds a layer of security to the DNS by enabling domain owners to digitally sign their DNS records.
            Ensures that the information received from a DNS query has not been tampered with, protecting users from attacks such as cache poisoning and man-in-the-middle attacks.
           - Importance: Enhances email security and domain trustworthiness.

        5. Domain Reputation:
           - Checks the domain's reputation (placeholder for API-based checks).
           - Importance: Helps in identifying potentially malicious domains.

        6. Geolocation:
           - Provides geolocation information for the domain's IP address.
           - Importance: Useful for understanding the physical location of the server.

        7. Subdomain Enumeration:
           - Enumerates subdomains using Sublist3r.
           - Importance: Helps in discovering subdomains for security assessments.

        === How to Use ===
        1. Enter the domain name in the input field.
        2. Select the analysis options you want to perform.
        3. Click the "Analyze" button to start the analysis.
        4. View the results in the "Results" and "Raw Data" tabs.

        === Additional Notes ===
        - The tool supports multithreading for efficient analysis.
        - Detailed logs are maintained for debugging and tracking purposes.
        - The status bar provides real-time updates on the analysis progress.
        """

        # Create a new tab for help information
        help_tab = scrolledtext.ScrolledText(self.notebook, wrap=tk.WORD)
        help_tab.insert(tk.END, help_text)
        self.notebook.add(help_tab, text="Help")

        # Add a back button to the help tab
        back_button = ttk.Button(help_tab, text="Back", command=self.back_to_main)
        help_tab.window_create(tk.END, window=back_button)

        # Switch to the help tab
        self.notebook.select(help_tab)

    def back_to_main(self):
        """Go back to the main tool tab"""
        # Switch back to the Results tab
        self.notebook.select(self.tabs['Results'])

    def save_results(self):
        """Save the analysis results to a file"""
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", ".json"), ("All files", ".*")])
        if file_path:
            results = self.tabs['Raw Data'].get("1.0", tk.END)
            with open(file_path, 'w') as file:
                file.write(results)
            messagebox.showinfo("Save Results", "Results saved successfully!")

    def load_domain_list(self):
        """Load a list of domains from a file for batch analysis"""
        file_path = filedialog.askopenfilename(filetypes=[("Text files", ".txt"), ("All files", ".*")])
        if file_path:
            with open(file_path, 'r') as file:
                domains = file.readlines()
                domains = [domain.strip() for domain in domains]
                self.batch_analysis(domains)

    def batch_analysis(self, domains: list):
        """Perform batch analysis on a list of domains"""
        total_domains = len(domains)
        self.progress_var.set(0)
        self.update_status("Batch analysis in progress...")

        for index, domain in enumerate(domains):
            self.update_status(f"Analyzing {domain} ({index + 1}/{total_domains})...")
            self.perform_analysis(domain)
            self.progress_var.set((index + 1) / total_domains * 100)

        self.update_status("Batch analysis complete")

    def toggle_dark_mode(self, *args):
        """Toggle dark mode"""
        if self.dark_mode.get():
            self.root.tk_setPalette(background='#2E2E2E', foreground='#E0E0E0', activeBackground='#4A4A4A', activeForeground='#E0E0E0')
        else:
            self.root.tk_setPalette(background='#E0E0E0', foreground='#000000', activeBackground='#C0C0C0', activeForeground='#000000')

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSAnalyzerGUI(root)
    root.mainloop()
