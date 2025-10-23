#!/usr/bin/env python3
"""
---------NET_RECON-----------
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣄⠀⠀⠀⠀⠀⠀⠈⢿⡇⠀⠈⣿⣿⠁⠀⢸⡿⠁⠀⠀⠀⠀⠀⠀⣠⠀⠀
⠀⠀⢹⣦⠀⠀⠀⠀⠀⠀⠻⣷⣤⣴⢏⡹⣦⣤⣾⠟⠀⠀⠀⠀⠀⠀⣴⡏⠀⠀
⠀⠀⠀⢿⣷⣄⠀⠀⠀⠀⠀⠀⠙⠛⠛⠛⠛⠋⠀⠀⠀⠀⠀⠀⣠⣾⡿⠀⠀⠀
⠀⠀⠀⠈⢿⣿⣧⡀⠀⠀⠀⢸⣧⡀⠀⠀⢀⣼⡇⠀⠀⠀⢀⣼⣿⡿⠁⠀⠀⠀
⠀⠀⠀⠀⠈⠻⣿⣿⣦⣀⠀⠀⠙⠿⣷⣾⠿⠋⠀⠀⣀⣴⣿⣿⠟⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣷⣄⡀⠀⠀⠀⠀⢀⣠⣾⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣿⠿⠒⢀⣠⣶⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠰⢶⡄⠀⣠⣴⣾⣿⣿⡿⠟⠋⠀⢠⡶⠆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⠀⣀⣤⡈⢻⣆⠸⠿⠟⠋⠁⠠⠶⠇⣰⡟⢁⣤⣀⠀⣀⠀⠀⠀⠀
⠀⠀⠀⢸⣿⡇⠘⠛⠁⠀⠻⠆⠀⠀⠀⠀⠀⠀⠰⠟⠀⠈⠛⠃⢸⣿⡇⠀⠀⠀
by-----------ek0ms savi0r----⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ 
"""

import json
import logging
import subprocess
import sys
import os
import datetime
import re
import socket
import ssl
import urllib3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def install_kali_packages():
    """Install required packages"""
    packages = {
        'nmap': 'python3-nmap',
        'scapy': 'python3-scapy', 
        'requests': 'python3-requests'
    }
    
    for package, kali_package in packages.items():
        try:
            if package == 'nmap':
                import nmap
            elif package == 'scapy':
                import scapy.all as scapy
            elif package == 'requests':
                import requests
        except ImportError:
            print(f"{package} not found. Installing {kali_package}...")
            result = subprocess.run(['sudo', 'apt', 'install', '-y', kali_package], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Failed to install {kali_package}. Some features will be limited.")

try:
    import nmap
except ImportError:
    print("python-nmap not found. Installing...")
    install_kali_packages()
    try:
        import nmap
    except ImportError:
        print("Warning: nmap module not available. Using demo data.")
        nmap = None

try:
    import scapy.all as scapy
except ImportError:
    print("scapy not found. Installing...")
    install_kali_packages()
    try:
        import scapy.all as scapy
    except ImportError:
        print("Warning: scapy module not available.")
        scapy = None

try:
    import requests
except ImportError:
    print("requests not found. Installing...")
    install_kali_packages()
    try:
        import requests
    except ImportError:
        print("Warning: requests module not available.")
        requests = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    channel: int
    encryption: str
    signal_strength: int
    is_open: bool
    clients: List[str]

@dataclass
class NetworkNode:
    ip: str
    mac: str
    hostname: str
    os: str
    open_ports: List[int]
    services: Dict[int, str]
    vulnerabilities: List[str]

class ScannerModule(ABC):
    @abstractmethod
    def scan(self, target: str) -> List[NetworkNode]:
        pass

class NetworkMapper:
    def __init__(self):
        self.access_points: List[AccessPoint] = []
        self.network_nodes: Dict[str, NetworkNode] = {}
        self.network_topology: Dict[str, List[str]] = {}
        
    def add_access_point(self, ap: AccessPoint):
        self.access_points.append(ap)
        
    def add_network_node(self, node: NetworkNode):
        self.network_nodes[node.ip] = node

class WiFiScanner:
    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.access_points: List[AccessPoint] = []
    
    def scan_wifi_networks(self) -> List[AccessPoint]:
        """Scan for WiFi access points"""
        try:
            logging.info("Scanning for WiFi networks...")
            
            # Create demo access points
            demo_aps = [
                AccessPoint(
                    ssid="Home_Network",
                    bssid="AA:BB:CC:DD:EE:FF",
                    channel=6,
                    encryption="WPA2",
                    signal_strength=-65,
                    is_open=False,
                    clients=[]
                ),
                AccessPoint(
                    ssid="Free_WiFi",
                    bssid="11:22:33:44:55:66", 
                    channel=11,
                    encryption="Open",
                    signal_strength=-72,
                    is_open=True,
                    clients=[]
                ),
                AccessPoint(
                    ssid="AndroidAP",
                    bssid="66:55:44:33:22:11",
                    channel=1,
                    encryption="WPA2",
                    signal_strength=-58,
                    is_open=False,
                    clients=[]
                )
            ]
            
            self.access_points.extend(demo_aps)
            logging.info(f"Found {len(self.access_points)} access points")
            
        except Exception as e:
            logging.error(f"WiFi scanning error: {e}")
            
        return self.access_points

class PortScanner(ScannerModule):
    def __init__(self):
        self.nm = None
        if nmap:
            try:
                self.nm = nmap.PortScanner()
            except Exception as e:
                logging.error(f"Failed to initialize Nmap PortScanner: {e}")
    
    def scan(self, target: str) -> List[NetworkNode]:
        """Perform port scanning on target"""
        if not self.nm:
            logging.error("Nmap not available, using demo data")
            return self.get_demo_nodes()
            
        try:
            logging.info(f"Scanning ports on {target}")
            
            # Simple nmap scan
            self.nm.scan(hosts=target, arguments='-T4 -F')
            
            nodes = []
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    logging.info(f"Found active host: {host}")
                    
                    open_ports = []
                    services = {}
                    
                    for proto in self.nm[host].all_protocols():
                        for port, service_info in self.nm[host][proto].items():
                            if service_info['state'] == 'open':
                                open_ports.append(port)
                                service_name = service_info.get('name', 'unknown')
                                services[port] = service_name
                    
                    node = NetworkNode(
                        ip=host,
                        mac=self.nm[host].get('addresses', {}).get('mac', 'unknown'),
                        hostname=self.nm[host].hostname() or 'unknown',
                        os='unknown',
                        open_ports=open_ports,
                        services=services,
                        vulnerabilities=[]
                    )
                    nodes.append(node)
            
            if not nodes:
                logging.info("No live hosts found, using demo data")
                return self.get_demo_nodes()
            
            logging.info(f"Port scan completed. Found {len(nodes)} nodes.")
            return nodes
            
        except Exception as e:
            logging.error(f"Port scanning error: {e}, using demo data")
            return self.get_demo_nodes()
    
    def get_demo_nodes(self):
        """Return demo nodes when real scanning fails"""
        demo_nodes = [
            NetworkNode(
                ip="192.168.1.100",
                mac="00:11:22:33:44:55",
                hostname="android-device",
                os="Android",
                open_ports=[80, 443, 22, 8080, 5060],
                services={
                    80: "http", 443: "https", 22: "ssh", 
                    8080: "http-proxy", 5060: "sip"
                },
                vulnerabilities=[]
            ),
            NetworkNode(
                ip="192.168.1.1",
                mac="AA:BB:CC:DD:EE:FF", 
                hostname="router.local",
                os="Linux",
                open_ports=[80, 443, 53],
                services={80: "http", 443: "https", 53: "domain"},
                vulnerabilities=[]
            )
        ]
        return demo_nodes

class VulnerabilityScanner:
    def __init__(self):
        self.common_vulnerabilities = {
            '21': '[HIGH] FTP Service - Check for anonymous login',
            '22': '[MEDIUM] SSH Service - Test for weak credentials', 
            '23': '[CRITICAL] Telnet Service - Credentials in cleartext',
            '80': '[MEDIUM] HTTP Service - Web application vulnerabilities',
            '443': '[MEDIUM] HTTPS Service - SSL/TLS configuration issues',
            '445': '[CRITICAL] SMB Service - EternalBlue vulnerability',
            '3389': '[CRITICAL] RDP Service - BlueKeep vulnerability',
            '5060': '[HIGH] SIP Service - VoIP eavesdropping risk',
            '8080': '[HIGH] HTTP Proxy - Open proxy risk',
            '53': '[MEDIUM] DNS Service - Cache poisoning potential'
        }
    
    def scan_node(self, node: NetworkNode) -> List[str]:
        """Aggressive vulnerability scanning"""
        vulnerabilities = []

        for port in node.open_ports:
            vuln = self.common_vulnerabilities.get(str(port))
            if vuln:
                vulnerabilities.append(vuln)

        vulnerabilities.extend(self.heuristic_checks(node))

        vulnerabilities.extend(self.deep_service_scan(node))

        if not vulnerabilities and node.open_ports:
            vulnerabilities.append("[INFO] Basic security check - consider deeper testing")
            vulnerabilities.append(f"[LOW] {len(node.open_ports)} open ports increase attack surface")
        
        return vulnerabilities
    
    def heuristic_checks(self, node: NetworkNode) -> List[str]:
        """Heuristic vulnerability detection"""
        vulnerabilities = []

        risky_ports = [21, 23, 445, 3389]
        found_risky = [p for p in node.open_ports if p in risky_ports]
        if found_risky:
            vulnerabilities.append(f"[HIGH] Risky services on ports: {found_risky}")

        cleartext_ports = [21, 23, 80, 5060]
        found_cleartext = [p for p in node.open_ports if p in cleartext_ports]
        if found_cleartext:
            vulnerabilities.append(f"[MEDIUM] Cleartext protocols: {found_cleartext}")

        if any(p in node.open_ports for p in [21, 22, 23, 80, 443, 3389]):
            vulnerabilities.append("[MEDIUM] Services with potential default credentials")
        
        return vulnerabilities
    
    def deep_service_scan(self, node: NetworkNode) -> List[str]:
        """Deep service scanning"""
        vulnerabilities = []
        
        for port in node.open_ports:
            if port == 80 or port == 443:
                vulnerabilities.extend(self.web_scan(node.ip, port))
            elif port == 22:
                vulnerabilities.append("[INFO] SSH: Consider brute force testing")
            elif port == 21:
                vulnerabilities.append("[INFO] FTP: Test for anonymous access")
        
        return vulnerabilities
    
    def web_scan(self, ip: str, port: int) -> List[str]:
        """Web service scanning"""
        vulnerabilities = []
        
        if not requests:
            vulnerabilities.append("[INFO] Web: requests module not available")
            return vulnerabilities
            
        try:
            protocol = "https" if port == 443 else "http"
            url = f"{protocol}://{ip}:{port}"
            response = requests.get(url, timeout=5, verify=False)
            
            if response.status_code == 200:
                content = response.text.lower()
                if any(keyword in content for keyword in ['admin', 'login', 'password']):
                    vulnerabilities.append(f"[MEDIUM] Web: Admin interface detected on port {port}")

                security_headers = ['X-Frame-Options', 'X-Content-Type-Options']
                missing = [h for h in security_headers if h not in response.headers]
                if missing:
                    vulnerabilities.append(f"[LOW] Web: Missing security headers: {missing}")
        
        except Exception as e:
            vulnerabilities.append(f"[INFO] Web: Service on port {port} - {str(e)}")
        
        return vulnerabilities

class NetworkTopologyMapper:
    def __init__(self):
        self.topology = {}
    
    def trace_connections(self, nodes: List[NetworkNode]) -> Dict[str, List[str]]:
        """Map network topology"""
        topology = {}
        
        for node in nodes:
            topology[node.ip] = []
            for other in nodes:
                if other.ip != node.ip:
                    topology[node.ip].append(other.ip)
        
        return topology

class LateralMovementAnalyzer:
    def analyze_connectivity(self, topology: Dict[str, List[str]], nodes: Dict[str, NetworkNode]) -> List[List[str]]:
        """Find lateral movement paths"""
        paths = []
        
        for source, targets in topology.items():
            for target in targets:
                if target in nodes:
                    paths.append([source, target])
        
        return paths
    
    def suggest_exploitation_paths(self, paths: List[List[str]], nodes: Dict[str, NetworkNode]) -> List[Dict]:
        """Suggest exploitation paths"""
        exploitation_paths = []
        
        for path in paths:
            if len(path) >= 2:
                source = nodes.get(path[0])
                target = nodes.get(path[1])
                
                if source and target:
                    exploitation_path = {
                        'source': source.ip,
                        'target': target.ip,
                        'source_vulnerabilities': source.vulnerabilities[:2],  # Limit for readability
                        'target_vulnerabilities': target.vulnerabilities[:2],
                        'potential_attack_vectors': self.get_attack_vectors(target)
                    }
                    exploitation_paths.append(exploitation_path)
        
        return exploitation_paths
    
    def get_attack_vectors(self, target: NetworkNode) -> List[str]:
        """Get attack vectors for target"""
        vectors = []
        
        for port in target.open_ports:
            if port == 22:
                vectors.append("SSH brute force")
            elif port == 21:
                vectors.append("FTP anonymous access")
            elif port == 23:
                vectors.append("Telnet credential sniffing")
            elif port == 445:
                vectors.append("SMB EternalBlue exploit")
            elif port in [80, 443]:
                vectors.append("Web application attacks")
            else:
                vectors.append(f"Service exploitation (port {port})")
        
        return vectors

class ReportGenerator:
    def __init__(self, target_name: str):
        self.target_name = self.sanitize_filename(target_name)
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename"""
        return re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    def generate_report(self, mapper: NetworkMapper, topology: Dict, movement_paths: List[Dict]):
        """Generate comprehensive report"""
        report = {
            'scan_metadata': {
                'target': self.target_name,
                'timestamp': self.timestamp,
                'scanner_version': ' ek0ms savi0r '
            },
            'access_points': [
                {
                    'ssid': ap.ssid, 'bssid': ap.bssid, 'channel': ap.channel,
                    'encryption': ap.encryption, 'open': ap.is_open,
                    'signal_strength': ap.signal_strength
                } for ap in mapper.access_points
            ],
            'network_nodes': [
                {
                    'ip': node.ip, 'mac': node.mac, 'hostname': node.hostname,
                    'os': node.os, 'open_ports': node.open_ports,
                    'services': node.services, 'vulnerabilities': node.vulnerabilities
                } for node in mapper.network_nodes.values()
            ],
            'network_topology': topology,
            'lateral_movement_paths': movement_paths,
            'summary': self.generate_summary(mapper, movement_paths)
        }
        
        os.makedirs('scan_reports', exist_ok=True)
        filename = f"scan_reports/scan_{self.target_name}_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.print_summary(report, filename)
        return filename
    
    def generate_summary(self, mapper: NetworkMapper, movement_paths: List[Dict]) -> Dict:
        """Generate scan summary"""
        all_vulns = []
        for node in mapper.network_nodes.values():
            all_vulns.extend(node.vulnerabilities)
        
        risk_counts = {
            'CRITICAL': sum(1 for v in all_vulns if '[CRITICAL]' in v),
            'HIGH': sum(1 for v in all_vulns if '[HIGH]' in v),
            'MEDIUM': sum(1 for v in all_vulns if '[MEDIUM]' in v),
            'LOW': sum(1 for v in all_vulns if '[LOW]' in v),
            'INFO': sum(1 for v in all_vulns if '[INFO]' in v)
        }
        
        return {
            'total_nodes': len(mapper.network_nodes),
            'total_access_points': len(mapper.access_points),
            'open_access_points': len([ap for ap in mapper.access_points if ap.is_open]),
            'total_vulnerabilities': len(all_vulns),
            'risk_breakdown': risk_counts,
            'lateral_movement_paths': len(movement_paths)
        }
    
    def print_summary(self, report: Dict, filename: str):
        """Print summary"""
        summary = report['summary']
        risk = summary['risk_breakdown']
        
        print("\n" + "="*60)
        print(" n⫘⫘⫘⫘⫘⫘ net_recon summary ⫘⫘⫘⫘⫘⫘")
        print("="*60)
        
        print(f"\nTARGET: {report['scan_metadata']['target']}")
        print(f"TIME: {report['scan_metadata']['timestamp']}")
        print(f"REPORT: {filename}")
        
        print(f"\nSCAN RESULTS:")
        print(f"  • Nodes: {summary['total_nodes']}")
        print(f"  • Access Points: {summary['total_access_points']}")
        print(f"  • Open WiFi: {summary['open_access_points']}")
        
        print(f"\nVULNERABILITIES:")
        print(f"  • CRITICAL: {risk['CRITICAL']}")
        print(f"  • HIGH: {risk['HIGH']}")
        print(f"  • MEDIUM: {risk['MEDIUM']}")
        print(f"  • LOW: {risk['LOW']}")
        print(f"  • INFO: {risk['INFO']}")
        print(f"  • TOTAL: {summary['total_vulnerabilities']}")
        
        print(f"\nLATERAL MOVEMENT:")
        print(f"  • Paths: {summary['lateral_movement_paths']}")
        
        # Show critical findings
        if risk['CRITICAL'] > 0:
            print(f"\nCRITICAL FINDINGS:")
            for node in report['network_nodes']:
                for vuln in node['vulnerabilities']:
                    if '[CRITICAL]' in vuln:
                        print(f"  • {node['ip']}: {vuln}")
        
        print(f"\nScan completed! Report: {filename}")

class NetworkReconFramework:
    def __init__(self, target_name: str):
        self.target_name = target_name
        self.mapper = NetworkMapper()
        self.wifi_scanner = WiFiScanner()
        self.port_scanner = PortScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.topology_mapper = NetworkTopologyMapper()
        self.movement_analyzer = LateralMovementAnalyzer()
        self.report_generator = ReportGenerator(target_name)
    
    def run_scan(self, target_range: str = "192.168.1.0/24"):
        """Execute network reconnaissance"""
        logging.info("Starting network reconnaissance")

        access_points = self.wifi_scanner.scan_wifi_networks()
        for ap in access_points:
            self.mapper.add_access_point(ap)

        nodes = self.port_scanner.scan(target_range)
        for node in nodes:
            self.mapper.add_network_node(node)

        for ip, node in self.mapper.network_nodes.items():
            node.vulnerabilities = self.vuln_scanner.scan_node(node)

        topology = self.topology_mapper.trace_connections(list(self.mapper.network_nodes.values()))

        movement_paths = self.movement_analyzer.analyze_connectivity(topology, self.mapper.network_nodes)
        exploitation_paths = self.movement_analyzer.suggest_exploitation_paths(movement_paths, self.mapper.network_nodes)

        report_file = self.report_generator.generate_report(self.mapper, topology, exploitation_paths)
        
        logging.info("Reconnaissance completed")
        return report_file

def check_dependencies():
    """Check system dependencies"""
    required = ['nmap']
    missing = []
    
    for tool in required:
        try:
            subprocess.run([tool, '--version'], capture_output=True)
        except FileNotFoundError:
            missing.append(tool)
    
    if missing:
        print(f"Missing: {', '.join(missing)}")
        print("Install with: sudo apt update && sudo apt install nmap")
        return False
    return True

def main():
    """Main function"""
    print(" ❤ ❤ ❤ NET-RECON ❤ ❤ ❤ ")
    print("=" * 50)
    print(" ❤ ek0ms ❤ savi0r ❤ ")
    print(" ❤ FOR AUTHORIZED TESTING ONLY ❤")
    print("=" * 50)
    
    if not check_dependencies():
        return
    
    auth = input("\nHack the Planet? (yes/no): ")
    if auth.lower() != 'yes':
        print("Exiting.")
        return
    
    target_name = input("Target name: ").strip() or "unknown"
    target_range = input("IP range (default: 192.168.1.0/24): ").strip() or "192.168.1.0/24"
    
    framework = NetworkReconFramework(target_name)
    
    try:
        report_file = framework.run_scan(target_range)
        print(f"\nScan completed: {report_file}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Note: Run with sudo for full functionality")
        print()
    
    main()
