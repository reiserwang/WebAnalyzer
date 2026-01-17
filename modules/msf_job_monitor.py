import logging
import os
from typing import Dict, Any

class MSFJobMonitor:
    """
    Monitors active Metasploit jobs via RPC.
    """
    def __init__(self):
        self.logger = logging.getLogger("MSFJobMonitor")

    def run(self) -> Dict[str, Any]:
        """
        Connects to MSF RPC and retrieves the list of active jobs.
        """
        try:
             # Check if pymetasploit3 is available and configure credentials
            from pymetasploit3.msfrpc import MsfRpcClient
            
            MSF_PASSWORD = os.getenv("MSF_PASSWORD", "toor")
            MSF_HOST = os.getenv("MSF_HOST", "127.0.0.1")
            MSF_PORT = int(os.getenv("MSF_PORT", 55553))
            
            try:
                client = MsfRpcClient(MSF_PASSWORD, host=MSF_HOST, port=MSF_PORT, ssl=True)
            except Exception as e:
                return {"error": "Metasploit RPC not connected. Start msfrpcd first."}

            # Fetch active jobs
            jobs = client.jobs.list
            
            # Format nicely if needed, but the raw dict is usually {"job_id": "Job Name"}
            # Actually, pymetasploit3 jobs.list returns { '0': 'Exploit: ...', '1': ... } usually just names.
            # To get details, we might need to loop specifically if the library supports it.
            # But standard RPC `job.list` returns a map of ID -> Name.
            # To get more info, we might check `job.info` for each ID if possible.
            
            detailed_jobs = []
            for jid, name in jobs.items():
                job_info = {"id": jid, "name": name, "status": "Running"}
                try:
                    # Try to get more info if available
                    info = client.jobs.info(jid)
                    if info:
                        job_info.update(info)
                except:
                    pass
                detailed_jobs.append(job_info)

            return {
                "active_jobs_count": len(detailed_jobs),
                "jobs": detailed_jobs,
                "raw_list": jobs
            }

        except ImportError:
             return {"error": "pymetasploit3 not installed"}
        except Exception as e:
            self.logger.error(f"MSF Job Monitor error: {e}")
            return {"error": str(e)}
