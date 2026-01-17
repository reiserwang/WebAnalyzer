import nmap
import logging
from typing import Dict, Any

class TopologyScanner:
    """
    Maps network topology using Nmap traceroute.
    """
    def __init__(self, target: str):
        self.target = target
        self.logger = logging.getLogger("TopologyScanner")
        self.nm = nmap.PortScanner()

    def scan(self) -> Dict[str, Any]:
        try:
            self.logger.info(f"Starting Topology Scan (Traceroute) for {self.target}")
            
            # -sn: Ping Scan (disable port scan)
            # --traceroute: Trace path to host
            # -Pn: Treat as online
            args = "-sn -Pn --traceroute"
            
            self.logger.info(f"Executing Nmap command with args: {args}")
            self.logger.info("Please wait, traceroute can take some time...")

            # We need sudo for traceroute sometimes, but nmap handles it reasonably well without
            # if using connect scan or similar, but --traceroute usually needs raw sockets (sudo).
            # If running as user, it might fail or fallback.
            # Let's hope the user has permissions or it works via non-icmp.
            
            self.nm.scan(self.target, arguments=args)
            
            self.logger.info("Nmap scan completed. Analyzing trace results...")
            
            hops = []
            
            if self.target in self.nm.all_hosts():
                host_data = self.nm[self.target]
                if 'trace' in host_data and 'port_used' in host_data['trace']:
                    # Nmap structure for trace:
                    # 'trace': {'port_used': '...', 'proto': '...', 'hop': [{...}, ...]}
                    raw_hops = host_data['trace'].get('hop', [])
                    self.logger.info(f"Trace data found. Processing {len(raw_hops)} hop(s)...")
                    for hop in raw_hops:
                        hops.append({
                            "ttl": int(hop.get('ttl', 0)),
                            "ip": hop.get('ipaddr', ''),
                            "rtt": hop.get('rtt', '--'),
                            "host": hop.get('host', '')
                        })
            
            # If no hops found (maybe permissions issue), usually the target itself is the last hop
            if not hops:
                 # Check if the host itself is up
                 if self.target in self.nm.all_hosts():
                     self.logger.warning("No intermediate hops found. Target is directly reachable or traceroute blocked.")
                     hops.append({"ttl": 1, "ip": self.target, "rtt": "N/A", "host": self.target})
                 else:
                     self.logger.error("Target appears down or unreachable.")
                     return {"error": "Could not trace route. Target might be down or permissions required."}

            self.logger.info(f"Topology Scan complete. Mapped {len(hops)} nodes.")
            return {
                "hops": hops,
                "target": self.target
            }

        except Exception as e:
            self.logger.error(f"Topology Scan Error: {e}")
            return {"error": str(e)}
