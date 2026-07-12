#!/usr/bin/env python3
"""
ZoneTransferChecker v2.0 - Complete Zone Transfer Vulnerability Scanner
Tests AXFR on multiple domains with custom port support
No missing code - Complete production-ready tool
"""

import asyncio
import aiodns
import dns.zone
import dns.query
import dns.resolver
import dns.rdatatype
import dns.exception
import socket
import sys
import os
import json
import csv
import time
import signal
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from collections import defaultdict
from urllib.parse import urlparse

# Try importing optional dependencies
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class tqdm:
        def __init__(self, *args, **kwargs):
            self.total = kwargs.get('total', 0)
            self.n = 0
            self.desc = kwargs.get('desc', '')
            self._closed = False
        def update(self, n=1):
            self.n += n
            if self.total > 0:
                pct = (self.n / self.total) * 100
                print(f"\r{self.desc}: {self.n}/{self.total} ({pct:.1f}%)", end='', flush=True)
        def close(self):
            if not self._closed:
                print()
                self._closed = True
        def __enter__(self):
            return self
        def __exit__(self, *args):
            self.close()
    
    @staticmethod
    def write(msg):
        print(msg)

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = LIGHTRED_EX = LIGHTGREEN_EX = LIGHTYELLOW_EX = LIGHTBLUE_EX = LIGHTMAGENTA_EX = LIGHTCYAN_EX = RESET = ''
    class Style:
        RESET_ALL = BRIGHT = DIM = NORMAL = ''
    class Back:
        RESET = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ''

# ============= CONFIGURATION CLASS =============

class ScanConfig:
    """Configuration for zone transfer scan"""
    def __init__(self):
        self.domain: Optional[str] = None
        self.domains_file: Optional[str] = None
        self.concurrency: int = 50
        self.timeout: int = 10
        self.dns_port: int = 53
        self.nameserver: Optional[str] = None
        self.output_dir: str = './output'
        self.output_format: str = 'json'
        self.quiet: bool = False
        self.debug: bool = False
        self.no_color: bool = False
        self.save_zones: bool = True
        self.max_nameservers: int = 5
        self.retries: int = 2

# ============= DNS RESOLVER =============

class DNSResolver:
    """DNS resolver with multiple fallback methods"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        try:
            self.async_resolver = aiodns.DNSResolver(timeout=timeout)
        except:
            self.async_resolver = None
    
    def resolve_ns(self, domain: str) -> List[str]:
        """Resolve NS records using system resolver"""
        nameservers = []
        try:
            answers = dns.resolver.resolve(domain, 'NS', lifetime=self.timeout)
            for rdata in answers:
                ns = str(rdata.target).rstrip('.')
                nameservers.append(ns)
        except Exception:
            pass
        return nameservers
    
    def resolve_a(self, hostname: str) -> List[str]:
        """Resolve A record using system resolver"""
        ips = []
        try:
            answers = dns.resolver.resolve(hostname, 'A', lifetime=self.timeout)
            for rdata in answers:
                ips.append(str(rdata.address))
        except Exception:
            pass
        return ips
    
    def gethostbyname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP using socket"""
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None
    
    async def async_resolve(self, domain: str, record_type: str) -> List[str]:
        """Async DNS resolution"""
        if not self.async_resolver:
            return []
        
        try:
            try:
                result = await self.async_resolver.query_dns(domain, record_type)
            except AttributeError:
                result = await self.async_resolver.query(domain, record_type)
            
            if record_type == 'NS':
                if isinstance(result, list):
                    return [str(r.host).rstrip('.') for r in result]
                return [str(result.host).rstrip('.')]
            elif record_type == 'A':
                if isinstance(result, list):
                    return [r.host for r in result]
                return [result.host]
        except Exception:
            return []

# ============= ZONE TRANSFER TESTER =============

class ZoneTransferTester:
    """Core zone transfer testing logic"""
    
    def __init__(self, timeout: int = 10, port: int = 53):
        self.timeout = timeout
        self.port = port
    
    def test(self, domain: str, nameserver_ip: str) -> Tuple[bool, List[str], str]:
        """Test zone transfer on a specific nameserver"""
        try:
            if self.port != 53:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(
                        nameserver_ip, domain,
                        port=self.port,
                        timeout=self.timeout,
                        lifetime=self.timeout
                    )
                )
            else:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(
                        nameserver_ip, domain,
                        timeout=self.timeout,
                        lifetime=self.timeout
                    )
                )
            
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        record_type = dns.rdatatype.to_text(rdataset.rdtype)
                        full_name = str(name)
                        if full_name == '@':
                            full_name = domain
                        elif not full_name.endswith('.'):
                            full_name = f"{full_name}.{domain}"
                        records.append(f"{full_name} {record_type} {rdata}")
            
            if records:
                return True, records, "Zone transfer successful"
            else:
                return False, [], "Zone transfer returned no records"
                
        except dns.exception.FormError:
            return False, [], "DNS Form Error - Server refused"
        except dns.query.TransferError as e:
            return False, [], f"Zone Transfer Refused: {str(e)}"
        except dns.query.BadResponse:
            return False, [], "Bad DNS Response from server"
        except dns.exception.Timeout:
            return False, [], "Connection Timeout"
        except ConnectionRefusedError:
            return False, [], "Connection Refused"
        except OSError as e:
            if "Network is unreachable" in str(e):
                return False, [], "Network Unreachable"
            return False, [], f"OS Error: {str(e)}"
        except Exception as e:
            return False, [], f"Error: {str(e)}"

# ============= MAIN SCANNER CLASS =============

class ZoneTransferChecker:
    """Main Zone Transfer Checker Application"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.resolver = DNSResolver(timeout=config.timeout)
        self.tester = ZoneTransferTester(timeout=config.timeout, port=config.dns_port)
        
        # Results storage
        self.vulnerable_domains: List[Dict[str, Any]] = []
        self.safe_domains: List[str] = []
        self.error_domains: List[Dict[str, Any]] = []
        
        # Statistics
        self.stats = {
            'total_domains': 0,
            'vulnerable_count': 0,
            'safe_count': 0,
            'error_count': 0,
            'total_nameservers_tested': 0,
            'total_records_found': 0,
            'start_time': 0.0,
            'end_time': 0.0,
            'duration': 0.0
        }
        
        # Concurrency control
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.results_lock = asyncio.Lock()
        self.stats_lock = asyncio.Lock()
        
        # Signal handling
        self.interrupted = False
    
    def _print_banner(self):
        """Display application banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  {Fore.YELLOW}███████╗ ██████╗ ███╗   ██╗███████╗{Fore.CYAN}                              ║
║  {Fore.YELLOW}╚══███╔╝██╔═══██╗████╗  ██║██╔════╝{Fore.CYAN}                              ║
║  {Fore.YELLOW}  ███╔╝ ██║   ██║██╔██╗ ██║█████╗  {Fore.CYAN}                              ║
║  {Fore.YELLOW} ███╔╝  ██║   ██║██║╚██╗██║██╔══╝  {Fore.CYAN}                              ║
║  {Fore.YELLOW}███████╗╚██████╔╝██║ ╚████║███████╗{Fore.CYAN}                              ║
║  {Fore.YELLOW}╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝{Fore.CYAN}                              ║
║                                                                  ║
║  {Fore.GREEN}████████╗██████╗  █████╗ ███╗   ██╗███████╗{Fore.CYAN}                    ║
║  {Fore.GREEN}╚══██╔══╝██╔══██╗██╔══██╗████╗  ██║██╔════╝{Fore.CYAN}                    ║
║  {Fore.GREEN}   ██║   ██████╔╝███████║██╔██╗ ██║███████╗{Fore.CYAN}                    ║
║  {Fore.GREEN}   ██║   ██╔══██╗██╔══██║██║╚██╗██║╚════██║{Fore.CYAN}                    ║
║  {Fore.GREEN}   ██║   ██║  ██║██║  ██║██║ ╚████║███████║{Fore.CYAN}                    ║
║  {Fore.GREEN}   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝{Fore.CYAN}                    ║
║                                                                  ║
║     {Fore.MAGENTA}Zone Transfer Vulnerability Scanner v2.0{Fore.CYAN}                    ║
║     {Fore.BLUE}Custom Port • Multi-Domain • AXFR Testing{Fore.CYAN}                   ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def _print_config(self):
        """Display scan configuration"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}Scan Configuration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"  {Fore.GREEN}DNS Port:          {Fore.WHITE}{self.config.dns_port}")
        if self.config.nameserver:
            print(f"  {Fore.GREEN}Nameserver:        {Fore.WHITE}{self.config.nameserver}")
        print(f"  {Fore.GREEN}Concurrency:       {Fore.WHITE}{self.config.concurrency}")
        print(f"  {Fore.GREEN}Timeout:           {Fore.WHITE}{self.config.timeout}s")
        print(f"  {Fore.GREEN}Output Format:     {Fore.WHITE}{self.config.output_format}")
        print(f"  {Fore.GREEN}Output Directory:  {Fore.WHITE}{self.config.output_dir}")
        print(f"{Fore.CYAN}{'='*60}\n")
    
    def _get_nameservers(self, domain: str) -> List[Tuple[str, str]]:
        """Get nameservers and their IPs for a domain"""
        ns_list = []
        
        # If specific nameserver is provided, use it
        if self.config.nameserver:
            ip = self.resolver.gethostbyname(self.config.nameserver)
            if ip:
                ns_list.append((self.config.nameserver, ip))
            else:
                # Try to use the nameserver as IP directly
                try:
                    socket.inet_aton(self.config.nameserver)
                    ns_list.append((self.config.nameserver, self.config.nameserver))
                except:
                    pass
            return ns_list[:self.config.max_nameservers]
        
        # Try system DNS resolver first
        ns_names = self.resolver.resolve_ns(domain)
        
        if ns_names:
            for ns_name in ns_names[:self.config.max_nameservers]:
                # Try multiple methods to resolve NS IP
                ip = self.resolver.gethostbyname(ns_name)
                if not ip:
                    ips = self.resolver.resolve_a(ns_name)
                    if ips:
                        ip = ips[0]
                
                if ip:
                    ns_list.append((ns_name, ip))
        else:
            # No NS records found, try common patterns
            parts = domain.split('.')
            if len(parts) >= 2:
                base = '.'.join(parts[-2:])
                for prefix in ['ns1', 'ns2', 'dns1', 'dns2', 'ns', 'dns']:
                    ns_name = f"{prefix}.{base}"
                    ip = self.resolver.gethostbyname(ns_name)
                    if ip:
                        ns_list.append((ns_name, ip))
        
        # If still no nameservers, try the domain itself
        if not ns_list:
            ip = self.resolver.gethostbyname(domain)
            if ip:
                ns_list.append((domain, ip))
        
        return ns_list[:self.config.max_nameservers]
    
    async def _check_domain(self, domain: str, pbar: Optional[tqdm] = None) -> Dict[str, Any]:
        """Check a single domain for zone transfer vulnerability"""
        result = {
            'domain': domain,
            'vulnerable': False,
            'nameservers_tested': [],
            'records': [],
            'record_count': 0,
            'error': None,
            'status': 'unknown',
            'vulnerable_ns': None,
            'vulnerable_ip': None,
            'scan_time': 0.0
        }
        
        scan_start = time.time()
        
        try:
            # Get nameservers for this domain
            nameservers = self._get_nameservers(domain)
            
            if not nameservers:
                result['error'] = "No nameservers found"
                result['status'] = 'error'
                async with self.stats_lock:
                    self.stats['error_count'] += 1
                    self.error_domains.append(result)
                if pbar:
                    pbar.update(1)
                return result
            
            # Test each nameserver
            for ns_name, ns_ip in nameservers:
                ns_entry = {
                    'nameserver': ns_name,
                    'ip': ns_ip,
                    'port': self.config.dns_port
                }
                result['nameservers_tested'].append(ns_entry)
                
                async with self.stats_lock:
                    self.stats['total_nameservers_tested'] += 1
                
                # Perform zone transfer test (synchronous, run in executor)
                loop = asyncio.get_event_loop()
                success, records, message = await loop.run_in_executor(
                    None, self.tester.test, domain, ns_ip
                )
                
                if self.config.debug:
                    tqdm.write(f"  [DEBUG] {domain} @ {ns_ip}:{self.config.dns_port} - {message}")
                
                if success and len(records) > 0:
                    result['vulnerable'] = True
                    result['records'] = records
                    result['record_count'] = len(records)
                    result['status'] = 'vulnerable'
                    result['vulnerable_ns'] = ns_name
                    result['vulnerable_ip'] = ns_ip
                    
                    async with self.results_lock:
                        self.vulnerable_domains.append(result)
                    
                    async with self.stats_lock:
                        self.stats['vulnerable_count'] += 1
                        self.stats['total_records_found'] += len(records)
                    
                    if pbar:
                        tqdm.write(
                            f"{Fore.RED}⚠ VULNERABLE: {Fore.YELLOW}{domain}{Fore.RED} "
                            f"via {ns_name}:{self.config.dns_port} "
                            f"({Fore.GREEN}{len(records)} records{Fore.RED}){Style.RESET_ALL}"
                        )
                    break  # Found vulnerability, no need to check other NS
                else:
                    if self.config.debug:
                        tqdm.write(
                            f"{Fore.GREEN}✓ SAFE: {domain} via {ns_name} - {message}{Style.RESET_ALL}"
                        )
            
            if not result['vulnerable']:
                result['status'] = 'safe'
                async with self.results_lock:
                    self.safe_domains.append(domain)
                async with self.stats_lock:
                    self.stats['safe_count'] += 1
        
        except Exception as e:
            result['error'] = str(e)
            result['status'] = 'error'
            async with self.stats_lock:
                self.stats['error_count'] += 1
                self.error_domains.append(result)
        
        result['scan_time'] = time.time() - scan_start
        
        if pbar:
            pbar.update(1)
        
        return result
    
    async def scan_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple domains for zone transfer vulnerabilities"""
        self.stats['total_domains'] = len(domains)
        self.stats['start_time'] = time.time()
        
        print(f"{Fore.CYAN}[*] Loaded {len(domains):,} domains to scan")
        print(f"{Fore.CYAN}[*] Concurrency: {self.config.concurrency} workers")
        print(f"{Fore.CYAN}[*] Timeout: {self.config.timeout}s per domain")
        print(f"{Fore.CYAN}{'─'*60}\n")
        
        results = []
        
        with tqdm(
            total=len(domains),
            desc=f"{Fore.GREEN}Testing Zone Transfers{Style.RESET_ALL}",
            unit="domain",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
            disable=self.config.quiet
        ) as pbar:
            
            async def bounded_scan(domain: str):
                async with self.semaphore:
                    return await self._check_domain(domain, pbar)
            
            tasks = [bounded_scan(domain) for domain in domains]
            results = await asyncio.gather(*tasks)
        
        self.stats['end_time'] = time.time()
        self.stats['duration'] = self.stats['end_time'] - self.stats['start_time']
        
        return results
    
    def load_domains_from_file(self, filepath: str) -> List[str]:
        """Load domains from a text file"""
        domains = []
        
        if not os.path.exists(filepath):
            print(f"{Fore.RED}[!] File not found: {filepath}{Style.RESET_ALL}")
            return domains
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip().lower()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Clean the line
                    # Remove protocols
                    if '://' in line:
                        parsed = urlparse(line)
                        line = parsed.hostname or parsed.path
                    
                    # Remove paths
                    if '/' in line:
                        line = line.split('/')[0]
                    
                    # Remove ports
                    if ':' in line:
                        parts = line.split(':')
                        if parts[-1].isdigit():
                            line = parts[0]
                    
                    # Remove whitespace and validate
                    line = line.strip()
                    if line and '.' in line and len(line) > 3:
                        domains.append(line)
                    elif self.config.debug:
                        print(f"  [DEBUG] Skipped line {line_num}: {line}")
            
            # Remove duplicates while preserving order
            seen = set()
            unique_domains = []
            for domain in domains:
                if domain not in seen:
                    seen.add(domain)
                    unique_domains.append(domain)
            
            print(f"{Fore.GREEN}[+] Loaded {len(unique_domains):,} unique domains from file")
            return unique_domains
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {e}{Style.RESET_ALL}")
            return []
    
    def print_results(self):
        """Print formatted scan results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}📊 ZONE TRANSFER SCAN RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"  {Fore.GREEN}Total Domains:     {Fore.WHITE}{self.stats['total_domains']:,}")
        print(f"  {Fore.RED}Vulnerable:        {Fore.WHITE}{self.stats['vulnerable_count']:,}")
        print(f"  {Fore.GREEN}Safe:              {Fore.WHITE}{self.stats['safe_count']:,}")
        print(f"  {Fore.YELLOW}Errors:            {Fore.WHITE}{self.stats['error_count']:,}")
        print(f"  {Fore.CYAN}NS Tested:         {Fore.WHITE}{self.stats['total_nameservers_tested']:,}")
        print(f"  {Fore.MAGENTA}Records Found:     {Fore.WHITE}{self.stats['total_records_found']:,}")
        print(f"  {Fore.BLUE}Duration:          {Fore.WHITE}{self.stats['duration']:.2f}s")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Print vulnerable domains in detail
        if self.vulnerable_domains:
            print(f"{Fore.RED}{'='*60}")
            print(f"{Fore.RED}{Style.BRIGHT}⚠️  VULNERABLE DOMAINS - ZONE TRANSFER ENABLED{Style.RESET_ALL}")
            print(f"{Fore.RED}{'='*60}\n")
            
            for i, vuln in enumerate(self.vulnerable_domains, 1):
                print(f"{Fore.RED}{Style.BRIGHT}{i}. {Fore.YELLOW}{vuln['domain']}{Style.RESET_ALL}")
                print(f"   {Fore.CYAN}Nameserver: {Fore.WHITE}{vuln['vulnerable_ns']} "
                      f"({vuln['vulnerable_ip']}:{self.config.dns_port})")
                print(f"   {Fore.GREEN}Records Found: {Fore.WHITE}{vuln['record_count']}")
                print(f"   {Fore.WHITE}Sample Records:")
                
                # Show first 5 records
                for record in vuln['records'][:5]:
                    print(f"     {Fore.BLUE}→ {record}")
                
                if vuln['record_count'] > 5:
                    print(f"     {Fore.MAGENTA}... and {vuln['record_count'] - 5} more records")
                print()
            
            print(f"{Fore.RED}{'='*60}\n")
        
        # Print safe domains summary
        if self.safe_domains and len(self.safe_domains) <= 20:
            print(f"{Fore.GREEN}{Style.BRIGHT}✓ Secure Domains (No Zone Transfer):{Style.RESET_ALL}")
            for domain in self.safe_domains:
                print(f"  {Fore.GREEN}• {domain}")
            print()
        elif self.safe_domains:
            print(f"{Fore.GREEN}✓ {len(self.safe_domains):,} domains are secure{Style.RESET_ALL}\n")
        
        # Print errors summary
        if self.error_domains:
            print(f"{Fore.YELLOW}{Style.BRIGHT}⚠ Domains with Errors:{Style.RESET_ALL}")
            for error in self.error_domains[:10]:
                print(f"  {Fore.YELLOW}• {error['domain']}: {error.get('error', 'Unknown error')}")
            if len(self.error_domains) > 10:
                print(f"  {Fore.CYAN}... and {len(self.error_domains) - 10} more errors")
            print()
    
    def save_results(self):
        """Save scan results to files"""
        output_path = Path(self.config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Prepare output data
        output_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'ZoneTransferChecker v2.0',
                'dns_port': self.config.dns_port,
                'nameserver': self.config.nameserver,
                'concurrency': self.config.concurrency,
                'timeout': self.config.timeout,
                'total_domains': self.stats['total_domains'],
                'vulnerable_count': self.stats['vulnerable_count'],
                'safe_count': self.stats['safe_count'],
                'error_count': self.stats['error_count'],
                'total_records': self.stats['total_records_found'],
                'duration_seconds': self.stats['duration']
            },
            'vulnerable_domains': [],
            'safe_domains': self.safe_domains,
            'error_domains': []
        }
        
        # Clean vulnerable domain data for output
        for vuln in self.vulnerable_domains:
            output_data['vulnerable_domains'].append({
                'domain': vuln['domain'],
                'nameserver': vuln['vulnerable_ns'],
                'ip': vuln['vulnerable_ip'],
                'port': self.config.dns_port,
                'record_count': vuln['record_count'],
                'records': vuln['records'],
                'scan_time': vuln['scan_time']
            })
        
        # Clean error domain data
        for err in self.error_domains:
            output_data['error_domains'].append({
                'domain': err['domain'],
                'error': err.get('error', 'Unknown error'),
                'scan_time': err['scan_time']
            })
        
        # Save JSON output
        if self.config.output_format in ['json', 'all']:
            json_file = output_path / f"zone_transfer_{timestamp}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}[+] JSON saved: {json_file}{Style.RESET_ALL}")
        
        # Save CSV output
        if self.config.output_format in ['csv', 'all']:
            csv_file = output_path / f"zone_transfer_{timestamp}.csv"
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Vulnerable', 'Nameserver', 'IP', 'Port', 'Records', 'Status'])
                
                for vuln in self.vulnerable_domains:
                    writer.writerow([
                        vuln['domain'], 'YES', vuln['vulnerable_ns'],
                        vuln['vulnerable_ip'], self.config.dns_port,
                        vuln['record_count'], 'VULNERABLE'
                    ])
                
                for domain in self.safe_domains:
                    writer.writerow([domain, 'NO', '', '', '', 0, 'SAFE'])
                
                for err in self.error_domains:
                    writer.writerow([
                        err['domain'], 'ERROR', '', '', '', 0,
                        err.get('error', 'Unknown')
                    ])
            
            print(f"{Fore.GREEN}[+] CSV saved: {csv_file}{Style.RESET_ALL}")
        
        # Save TXT output
        if self.config.output_format in ['txt', 'all']:
            txt_file = output_path / f"zone_transfer_{timestamp}.txt"
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("ZoneTransferChecker v2.0 - Scan Results\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Scan Date: {datetime.now().isoformat()}\n")
                f.write(f"DNS Port: {self.config.dns_port}\n")
                f.write(f"Total Domains: {self.stats['total_domains']}\n")
                f.write(f"Vulnerable: {self.stats['vulnerable_count']}\n")
                f.write(f"Safe: {self.stats['safe_count']}\n")
                f.write(f"Errors: {self.stats['error_count']}\n\n")
                
                if self.vulnerable_domains:
                    f.write("-" * 60 + "\n")
                    f.write("VULNERABLE DOMAINS\n")
                    f.write("-" * 60 + "\n\n")
                    
                    for vuln in self.vulnerable_domains:
                        f.write(f"Domain: {vuln['domain']}\n")
                        f.write(f"Nameserver: {vuln['vulnerable_ns']} ({vuln['vulnerable_ip']})\n")
                        f.write(f"Records: {vuln['record_count']}\n")
                        f.write("Zone Records:\n")
                        for record in vuln['records']:
                            f.write(f"  {record}\n")
                        f.write("\n")
                
                if self.safe_domains:
                    f.write("-" * 60 + "\n")
                    f.write("SAFE DOMAINS\n")
                    f.write("-" * 60 + "\n\n")
                    for domain in self.safe_domains:
                        f.write(f"  {domain}\n")
            
            print(f"{Fore.GREEN}[+] TXT saved: {txt_file}{Style.RESET_ALL}")
        
        # Save individual zone files for vulnerable domains
        if self.config.save_zones and self.vulnerable_domains:
            zones_dir = output_path / f"zone_files_{timestamp}"
            zones_dir.mkdir(exist_ok=True)
            
            for vuln in self.vulnerable_domains:
                safe_name = vuln['domain'].replace('.', '_').replace('/', '_')
                zone_file = zones_dir / f"{safe_name}_zone.txt"
                with open(zone_file, 'w', encoding='utf-8') as f:
                    f.write(f"; Zone file for {vuln['domain']}\n")
                    f.write(f"; Obtained via AXFR from {vuln['vulnerable_ns']} ({vuln['vulnerable_ip']})\n")
                    f.write(f"; Date: {datetime.now().isoformat()}\n")
                    f.write(f"; Total Records: {vuln['record_count']}\n\n")
                    for record in vuln['records']:
                        f.write(f"{record}\n")
            
            print(f"{Fore.GREEN}[+] Zone files saved in: {zones_dir}{Style.RESET_ALL}")

# ============= CLI =============

def create_argument_parser() -> 'argparse.ArgumentParser':
    """Create and configure argument parser"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description=f'{Fore.CYAN}ZoneTransferChecker v2.0 - Zone Transfer Vulnerability Scanner{Style.RESET_ALL}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.YELLOW}Examples:{Style.RESET_ALL}
  {Fore.GREEN}# Test single domain on default DNS port{Style.RESET_ALL}
  zone-transfer -d example.com

  {Fore.GREEN}# Test single domain on custom port (for local lab){Style.RESET_ALL}
  zone-transfer -d lab.local -p 5353 -n 127.0.0.1

  {Fore.GREEN}# Test multiple domains from file{Style.RESET_ALL}
  zone-transfer -f domains.txt

  {Fore.GREEN}# Test with custom port and high concurrency{Style.RESET_ALL}
  zone-transfer -f domains.txt -p 5353 -c 100 -t 5

  {Fore.GREEN}# Save results in all formats{Style.RESET_ALL}
  zone-transfer -f domains.txt --format all -o results

  {Fore.GREEN}# Debug mode{Style.RESET_ALL}
  zone-transfer -f domains.txt -p 5353 --debug
        """
    )
    
    # Target options
    target = parser.add_argument_group(f'{Fore.YELLOW}Target Options{Style.RESET_ALL}')
    target.add_argument('-d', '--domain', help='Single domain to test')
    target.add_argument('-f', '--file', help='File containing list of domains (one per line)')
    
    # DNS options
    dns_opts = parser.add_argument_group(f'{Fore.YELLOW}DNS Options{Style.RESET_ALL}')
    dns_opts.add_argument('-p', '--port', type=int, default=53,
                         help='DNS port (default: 53, use 5353 for local testing)')
    dns_opts.add_argument('-n', '--nameserver', 
                         help='Specific nameserver to test (bypasses NS lookup)')
    
    # Performance options
    perf = parser.add_argument_group(f'{Fore.YELLOW}Performance Options{Style.RESET_ALL}')
    perf.add_argument('-c', '--concurrency', type=int, default=50,
                     help='Number of concurrent domain tests (default: 50)')
    perf.add_argument('-t', '--timeout', type=int, default=10,
                     help='Timeout per domain in seconds (default: 10)')
    perf.add_argument('--max-ns', type=int, default=5,
                     help='Maximum nameservers to test per domain (default: 5)')
    
    # Output options
    output = parser.add_argument_group(f'{Fore.YELLOW}Output Options{Style.RESET_ALL}')
    output.add_argument('-o', '--output', default='./output',
                       help='Output directory (default: ./output)')
    output.add_argument('--format', choices=['json', 'csv', 'txt', 'all'], 
                       default='json',
                       help='Output format (default: json)')
    output.add_argument('--no-save-zones', action='store_true',
                       help='Do not save individual zone files')
    
    # Display options
    display = parser.add_argument_group(f'{Fore.YELLOW}Display Options{Style.RESET_ALL}')
    display.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode - suppress progress output')
    display.add_argument('--debug', action='store_true',
                        help='Enable debug output')
    display.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    return parser

def main():
    """Main entry point"""
    parser = create_argument_parser()
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    # Validate arguments
    if not args.domain and not args.file:
        print(f"\n{Fore.RED}[!] Error: Specify a domain (-d) or domains file (-f){Style.RESET_ALL}\n")
        parser.print_help()
        sys.exit(1)
    
    # Create configuration
    config = ScanConfig()
    config.domain = args.domain
    config.domains_file = args.file
    config.concurrency = args.concurrency
    config.timeout = args.timeout
    config.dns_port = args.port
    config.nameserver = args.nameserver
    config.output_dir = args.output
    config.output_format = args.format
    config.quiet = args.quiet
    config.debug = args.debug
    config.no_color = args.no_color
    config.save_zones = not args.no_save_zones
    config.max_nameservers = args.max_ns
    
    # Create scanner
    checker = ZoneTransferChecker(config)
    
    # Print banner and config
    checker._print_banner()
    checker._print_config()
    
    # Load domains
    if args.domain:
        domains = [args.domain]
        print(f"{Fore.CYAN}[*] Testing single domain: {Fore.YELLOW}{args.domain}{Style.RESET_ALL}\n")
    else:
        domains = checker.load_domains_from_file(args.file)
        if not domains:
            print(f"{Fore.RED}[!] No valid domains found in file{Style.RESET_ALL}")
            sys.exit(1)
    
    # Run scan
    try:
        results = asyncio.run(checker.scan_domains(domains))
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        # Still save partial results
        checker.stats['end_time'] = time.time()
        checker.stats['duration'] = checker.stats['end_time'] - checker.stats['start_time']
        checker.print_results()
        checker.save_results()
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        if config.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    # Print and save results
    checker.print_results()
    checker.save_results()
    
    print(f"{Fore.GREEN}{Style.BRIGHT}[+] Scan complete!{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
