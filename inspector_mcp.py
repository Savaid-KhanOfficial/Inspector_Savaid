#!/usr/bin/env python3
"""
Inspector AI MCP Client - Cybersecurity Operations Interface

Advanced security testing platform with automated reconnaissance
🔍 Vulnerability Research | Penetration Testing | Security Analysis

CORE CAPABILITIES (v1.0):
✅ Automated threat detection and analysis workflows
✅ Real-time security monitoring with visual feedback
✅ Intelligent vulnerability assessment and reporting
✅ MCP protocol integration for seamless tool coordination
✅ 100+ specialized security tools with adaptive configuration
✅ Enhanced logging system with operational status tracking

Design: MCP-based client for security operations coordination
Protocol: FastMCP framework for distributed tool execution
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import time
from datetime import datetime

from mcp.server.fastmcp import FastMCP

class InspectorColors:
    """Color scheme definitions for security operations terminal output"""
    
    # Base terminal color palette
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Security operations color scheme
    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    ELECTRIC_PURPLE = '\033[38;5;129m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    TERMINAL_GRAY = '\033[38;5;240m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Threat level indicator colors
    BLOOD_RED = '\033[38;5;124m'
    CRIMSON = '\033[38;5;160m'
    DARK_RED = '\033[38;5;88m'
    FIRE_RED = '\033[38;5;202m'
    ROSE_RED = '\033[38;5;167m'
    BURGUNDY = '\033[38;5;52m'
    SCARLET = '\033[38;5;197m'
    RUBY = '\033[38;5;161m'
    
    # Alert highlighting combinations
    HIGHLIGHT_RED = '\033[48;5;196m\033[38;5;15m'  # Critical alerts
    HIGHLIGHT_YELLOW = '\033[48;5;226m\033[38;5;16m'  # Warning highlights
    HIGHLIGHT_GREEN = '\033[48;5;46m\033[38;5;16m'  # Success indicators
    HIGHLIGHT_BLUE = '\033[48;5;51m\033[38;5;16m'  # Info displays
    HIGHLIGHT_PURPLE = '\033[48;5;129m\033[38;5;15m'  # Special operations
    
    # Task execution status colors
    SUCCESS = '\033[38;5;46m'  # Task completion
    WARNING = '\033[38;5;208m'  # Caution required
    ERROR = '\033[38;5;196m'  # Operation failed
    CRITICAL = '\033[48;5;196m\033[38;5;15m\033[1m'  # Immediate attention
    INFO = '\033[38;5;51m'  # General information
    DEBUG = '\033[38;5;240m'  # Development output
    
    # Vulnerability severity indicators
    VULN_CRITICAL = '\033[48;5;124m\033[38;5;15m\033[1m'  # Maximum threat level
    VULN_HIGH = '\033[38;5;196m\033[1m'  # Severe security issue
    VULN_MEDIUM = '\033[38;5;208m\033[1m'  # Moderate risk
    VULN_LOW = '\033[38;5;226m'  # Minor concern
    VULN_INFO = '\033[38;5;51m'  # Informational finding
    
    # Tool operational status indicators
    TOOL_RUNNING = '\033[38;5;46m\033[5m'  # Active scanning
    TOOL_SUCCESS = '\033[38;5;46m\033[1m'  # Scan completed
    TOOL_FAILED = '\033[38;5;196m\033[1m'  # Execution error
    TOOL_TIMEOUT = '\033[38;5;208m\033[1m'  # Time limit exceeded
    TOOL_RECOVERY = '\033[38;5;129m\033[1m'  # Auto-recovery mode

# Backward compatibility alias
Colors = InspectorColors

class ColoredFormatter(logging.Formatter):
    """Enhanced log formatting with visual status indicators"""
    
    COLORS = {
        'DEBUG': InspectorColors.DEBUG,
        'INFO': InspectorColors.SUCCESS,
        'WARNING': InspectorColors.WARNING,
        'ERROR': InspectorColors.ERROR,
        'CRITICAL': InspectorColors.CRITICAL
    }
    
    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '📘',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '💥'
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        emoji = self.EMOJIS.get(record.levelname, '')
        reset = '\033[0m'
        
        # Generate timestamp for log entry
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Build enhanced log message with visual indicators
        formatted = f"{log_color}[{timestamp}] {emoji} {record.getMessage()}{reset}"
        return formatted

# Initialize Inspector AI logging system
logging.basicConfig(
    level=logging.INFO,
    format="[🔥 Inspector MCP] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

# Configure visual log formatting
for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[🔥 Inspector MCP] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

logger = logging.getLogger(__name__)

# Platform connection configuration
DEFAULT_INSPECTOR_SERVER = "http://127.0.0.1:8888"  # Local API endpoint
DEFAULT_REQUEST_TIMEOUT = 300  # API call timeout limit
MAX_RETRIES = 3  # Connection retry attempts

class InspectorClient:
    """API communication handler for security operations platform"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize platform communication interface
        
        Args:
            server_url: Security platform API endpoint
            timeout: Request timeout duration in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        
        # Initialize connection with fault tolerance
        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"🔗 Attempting to connect to Inspector AI API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                # Validate server availability via health check
                try:
                    test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                    test_response.raise_for_status()
                    health_check = test_response.json()
                    connected = True
                    logger.info(f"🎯 Successfully connected to Inspector AI API Server at {server_url}")
                    logger.info(f"🏥 Server health status: {health_check.get('status', 'unknown')}")
                    logger.info(f"📊 Server version: {health_check.get('version', 'unknown')}")
                    break
                except requests.exceptions.ConnectionError:
                    logger.warning(f"🔌 Connection refused to {server_url}. Make sure the Inspector AI server is running.")
                    time.sleep(2)  # Retry delay
                except Exception as e:
                    logger.warning(f"⚠️  Connection test failed: {str(e)}")
                    time.sleep(2)  # Connection backoff
            except Exception as e:
                logger.warning(f"❌ Connection attempt {i+1} failed: {str(e)}")
                time.sleep(2)  # Attempt spacing
        
        if not connected:
            error_msg = f"Failed to establish connection to Inspector AI API Server at {server_url} after {MAX_RETRIES} attempts"
            logger.error(error_msg)
            # Allow MCP startup despite connection issues
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute HTTP GET operation with parameters
        
        Args:
            endpoint: Target API path
            params: URL query parameters
            
        Returns:
            JSON response as dict
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"📡 GET {url} with params: {params}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute HTTP POST with JSON payload
        
        Args:
            endpoint: Target API path
            data: Request body content
            
        Returns:
            Server response data
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"📡 POST {url} with data: {json_data}")
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def check_health(self) -> Dict[str, Any]:
        """
        Verify server availability and status
        
        Returns:
            Platform health metrics
        """
        return self.safe_get("api/health")

# Create global client instance
inspector_client = InspectorClient(DEFAULT_INSPECTOR_SERVER)

# Initialize MCP server
mcp = FastMCP("Inspector AI")

# ============================================================================
# PLATFORM MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
def server_health() -> Dict[str, Any]:
    """
    Verify server availability and status
    
    Returns:
        Platform health metrics
    """
    logger.info(f"🏥 Checking Inspector AI server health")
    result = inspector_client.check_health()
    if result.get("status") == "healthy":
        logger.info(f"✅ Server is healthy - {result.get('total_tools_available', 0)} tools available")
    else:
        logger.warning(f"⚠️  Server health check returned: {result.get('status', 'unknown')}")
    return result

@mcp.tool()
def get_cache_stats() -> Dict[str, Any]:
    """
    Retrieve server cache performance metrics
    
    Returns:
        Cache usage and efficiency data
    """
    logger.info(f"💾 Getting cache statistics")
    result = inspector_client.safe_get("api/cache/stats")
    if "hit_rate" in result:
        logger.info(f"📊 Cache hit rate: {result.get('hit_rate', 'unknown')}")
    return result

@mcp.tool()
def clear_cache() -> Dict[str, Any]:
    """
    Flush all cached data from server memory
    
    Returns:
        Cache clearing operation status
    """
    logger.info(f"🧹 Clearing server cache")
    result = inspector_client.safe_post("api/cache/clear", {})
    if result.get("success"):
        logger.info(f"✅ Cache cleared successfully")
    else:
        logger.error(f"❌ Failed to clear cache")
    return result

@mcp.tool()
def get_telemetry() -> Dict[str, Any]:
    """
    Collect platform performance and usage metrics
    
    Returns:
        System monitoring and analytics data
    """
    logger.info(f"📈 Getting system telemetry")
    result = inspector_client.safe_get("api/telemetry")
    if "commands_executed" in result:
        logger.info(f"📊 Commands executed: {result.get('commands_executed', 0)}")
    return result

# ============================================================================
# TASK ORCHESTRATION FRAMEWORK
# ============================================================================

@mcp.tool()
def list_active_processes() -> Dict[str, Any]:
    """
    Enumerate running operations and their current state
    
    Returns:
        Active task registry with execution status
    """
    logger.info("📊 Listing active processes")
    result = inspector_client.safe_get("api/processes/list")
    if result.get("success"):
        logger.info(f"✅ Found {result.get('total_count', 0)} active processes")
    return result

@mcp.tool()
def get_process_status(pid: str) -> Dict[str, Any]:
    """
    Check execution status of specific operation
    
    Args:
        pid: Process identifier to query
        
    Returns:
        Task progress and runtime information
    """
    logger.info(f"🔍 Checking status of process {pid}")
    result = inspector_client.safe_get(f"api/processes/status/{pid}")
    if result.get("success"):
        logger.info(f"✅ Process {pid} status retrieved")
    else:
        logger.error(f"❌ Process {pid} not found or error occurred")
    return result

@mcp.tool()
def terminate_process(pid: int) -> Dict[str, Any]:
    """
    Force stop a running operation by identifier
    
    Args:
        pid: Target process identifier
        
    Returns:
        Termination operation outcome
    """
    logger.info(f"🛑 Terminating process {pid}")
    result = inspector_client.safe_post("api/processes/terminate", {"pid": pid})
    if result.get("success"):
        logger.info(f"✅ Process {pid} terminated successfully")
    else:
        logger.error(f"❌ Failed to terminate process {pid}")
    return result

@mcp.tool()
def get_system_info() -> Dict[str, Any]:
    """
    Retrieve platform hardware and software information
    
    Returns:
        System configuration and resource data
    """
    logger.info(f"📊 Getting system info")
    result = inspector_client.safe_get("api/system/info")
    if result.get("success"):
        logger.info(f"✅ System info retrieved")
    else:
        logger.error(f"❌ Failed to get system info")
    return result

# ============================================================================
# NETWORK RECONNAISSANCE MODULES  
# ============================================================================

@mcp.tool()
def nmap_scan(target: str, scan_type: str = "default", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Resume a paused process.
        
        Args:
            pid: Process ID to resume
            
        Returns:
            Success status of the resume operation
        """
        logger.info(f"▶️ Resuming process {pid}")
        result = inspector_client.safe_post(f"api/processes/resume/{pid}", {})
        if result.get("success"):
            logger.info(f"✅ Process {pid} resumed successfully")
        else:
            logger.error(f"❌ Failed to resume process {pid}")
        return result

@mcp.tool()
def get_process_dashboard() -> Dict[str, Any]:
    """
    Retrieve operational dashboard with task monitoring
    
    Returns:
        Live process status with execution metrics and progress tracking
    """
    logger.info("📊 Getting process dashboard")
    result = inspector_client.safe_get("api/processes/dashboard")
    if result.get("success", True) and "total_processes" in result:
        total = result.get("total_processes", 0)
        logger.info(f"✅ Dashboard retrieved: {total} active processes")
        
        # Display operational summary for monitoring
        if total > 0:
            logger.info("📈 Active Processes Summary:")
            for proc in result.get("processes", [])[:3]:  # Show first 3
                logger.info(f"   ├─ PID {proc['pid']}: {proc['progress_bar']} {proc['progress_percent']}")
    else:
        logger.error("❌ Failed to get process dashboard")
    return result

@mcp.tool()
def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
    """
    Run system command through security platform interface
    
    Args:
        command: Shell command to execute
        use_cache: Enable result caching for performance
        
    Returns:
        Execution output with performance metrics
    """
    try:
        logger.info(f"⚡ Executing command: {command}")
        result = inspector_client.execute_command(command, use_cache)
        if "error" in result:
            logger.error(f"❌ Command failed: {result['error']}")
            return {
                "success": False,
                "error": result["error"],
                "stdout": "",
                "stderr": f"Error executing command: {result['error']}"
            }
            
        if result.get("success"):
            execution_time = result.get("execution_time", 0)
            logger.info(f"✅ Command completed successfully in {execution_time:.2f}s")
        else:
            logger.warning(f"⚠️  Command completed with errors")
        
        return result
    except Exception as e:
        logger.error(f"💥 Error executing command '{command}': {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "stdout": "",
            "stderr": f"Error executing command: {str(e)}"
        }

# ============================================================================
# SECURITY INTELLIGENCE MONITORING TOOLS
# ============================================================================

@mcp.tool()
def monitor_cve_feeds(hours: int = 24, severity_filter: str = "HIGH,CRITICAL", keywords: str = "") -> Dict[str, Any]:
    """
    Track vulnerability databases for emerging security threats
    
    Args:
        hours: Time window for vulnerability monitoring (default: 24)
        severity_filter: CVSS severity levels to include (LOW,MEDIUM,HIGH,CRITICAL,ALL)
        keywords: Search terms for vulnerability descriptions (comma-separated)
        
    Returns:
        Recent vulnerabilities with risk assessment and exploitation potential
            
    Example:
        monitor_cve_feeds(48, "CRITICAL", "remote code execution")
    """
    data = {
        "hours": hours,
        "severity_filter": severity_filter,
        "keywords": keywords
    }
    logger.info(f"🔍 Monitoring CVE feeds for last {hours} hours | Severity: {severity_filter}")
    result = inspector_client.safe_post("api/vuln-intel/cve-monitor", data)
    
    if result.get("success"):
        cve_count = len(result.get("cve_monitoring", {}).get("cves", []))
        exploit_analysis_count = len(result.get("exploitability_analysis", []))
        logger.info(f"✅ Found {cve_count} CVEs with {exploit_analysis_count} exploitability analyses")
    
    return result

@mcp.tool()
def generate_exploit_from_cve(cve_id: str, target_os: str = "", target_arch: str = "x64", exploit_type: str = "poc", evasion_level: str = "none") -> Dict[str, Any]:
    """
    Create exploit code from vulnerability data with automated analysis
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
        target_os: Target operating system (windows, linux, macos, any)
        target_arch: Target architecture (x86, x64, arm, any)
        exploit_type: Type of exploit to generate (poc, weaponized, stealth)
        evasion_level: Evasion sophistication (none, basic, advanced)
            
    Returns:
        Generated exploit code with testing instructions and evasion techniques
        
    Example:
        generate_exploit_from_cve("CVE-2024-1234", "linux", "x64", "weaponized", "advanced")
    """
    data = {
        "cve_id": cve_id,
        "target_os": target_os,
        "target_arch": target_arch,
        "exploit_type": exploit_type,
        "evasion_level": evasion_level
    }
    logger.info(f"🤖 Generating {exploit_type} exploit for {cve_id} | Target: {target_os} {target_arch}")
    result = inspector_client.safe_post("api/vuln-intel/exploit-generate", data)
    
    if result.get("success"):
        cve_analysis = result.get("cve_analysis", {})
        exploit_gen = result.get("exploit_generation", {})
        exploitability = cve_analysis.get("exploitability_level", "UNKNOWN")
        exploit_success = exploit_gen.get("success", False)
        
        logger.info(f"📊 CVE Analysis: {exploitability} exploitability")
        logger.info(f"🎯 Exploit Generation: {'SUCCESS' if exploit_success else 'FAILED'}")
    
    return result

@mcp.tool()
def discover_attack_chains(target_software: str, attack_depth: int = 3, include_zero_days: bool = False) -> Dict[str, Any]:
    """
    Map multi-stage attack vectors for target systems with correlation analysis
    
    Args:
        target_software: Target software/system (e.g., "Apache HTTP Server", "Windows Server 2019")
        attack_depth: Maximum number of stages in attack chain (1-5)
        include_zero_days: Include potential zero-day vulnerabilities in analysis
        
    Returns:
        Attack chains with vulnerability combinations, success probabilities, and exploit availability
            
    Example:
        discover_attack_chains("Apache HTTP Server 2.4", 4, True)
    """
    data = {
        "target_software": target_software,
        "attack_depth": min(max(attack_depth, 1), 5),  # Clamp between 1-5
        "include_zero_days": include_zero_days
    }
    logger.info(f"🔗 Discovering attack chains for {target_software} | Depth: {attack_depth} | Zero-days: {include_zero_days}")
    result = inspector_client.safe_post("api/vuln-intel/attack-chains", data)
    
    if result.get("success"):
        chains = result.get("attack_chain_discovery", {}).get("attack_chains", [])
        enhanced_chains = result.get("attack_chain_discovery", {}).get("enhanced_chains", [])
        
        logger.info(f"📊 Found {len(chains)} attack chains")
        if enhanced_chains:
            logger.info(f"🎯 Enhanced {len(enhanced_chains)} chains with exploit analysis")
    
    return result

@mcp.tool()
def research_zero_day_opportunities(target_software: str, analysis_depth: str = "standard", source_code_url: str = "") -> Dict[str, Any]:
    """
    Identify potential zero-day vulnerabilities through automated code analysis
    
    Args:
        target_software: Software to research for vulnerabilities (e.g., "nginx", "OpenSSL")
        analysis_depth: Depth of analysis (quick, standard, comprehensive)
        source_code_url: URL to source code repository for enhanced analysis
        
    Returns:
        Potential vulnerability areas with exploitation feasibility and research recommendations
            
    Example:
        research_zero_day_opportunities("nginx 1.20", "comprehensive", "https://github.com/nginx/nginx")
    """
    if analysis_depth not in ["quick", "standard", "comprehensive"]:
        analysis_depth = "standard"
    
    data = {
        "target_software": target_software,
        "analysis_depth": analysis_depth,
        "source_code_url": source_code_url
    }
    logger.info(f"🔬 Researching zero-day opportunities in {target_software} | Depth: {analysis_depth}")
    result = inspector_client.safe_post("api/vuln-intel/zero-day-research", data)
    
    if result.get("success"):
        research = result.get("zero_day_research", {})
        potential_vulns = len(research.get("potential_vulnerabilities", []))
        risk_score = research.get("risk_assessment", {}).get("risk_score", 0)
        
        logger.info(f"📊 Found {potential_vulns} potential vulnerability areas")
        logger.info(f"🎯 Risk Score: {risk_score}/100")
    
    return result

@mcp.tool()
def correlate_threat_intelligence(indicators: str, timeframe: str = "30d", sources: str = "all") -> Dict[str, Any]:
        """
        Correlate threat intelligence across multiple sources with advanced analysis.
        
        Args:
            indicators: Comma-separated IOCs (IPs, domains, hashes, CVEs, etc.)
            timeframe: Time window for correlation (7d, 30d, 90d, 1y)
            sources: Intelligence sources to query (cve, exploit-db, github, twitter, all)
            
        Returns:
            Correlated threat intelligence with attribution, timeline, and threat scoring
            
        Example:
            correlate_threat_intelligence("CVE-2024-1234,192.168.1.100,malware.exe", "90d", "all")
        """
        # Validate timeframe
        valid_timeframes = ["7d", "30d", "90d", "1y"]
        if timeframe not in valid_timeframes:
            timeframe = "30d"
        
        # Parse indicators
        indicator_list = [i.strip() for i in indicators.split(",") if i.strip()]
        
        if not indicator_list:
            logger.error("❌ No valid indicators provided")
            return {"success": False, "error": "No valid indicators provided"}
        
        data = {
            "indicators": indicator_list,
            "timeframe": timeframe,
            "sources": sources
        }
        logger.info(f"🧠 Correlating threat intelligence for {len(indicator_list)} indicators | Timeframe: {timeframe}")
        result = inspector_client.safe_post("api/vuln-intel/threat-feeds", data)
        
        if result.get("success"):
            threat_intel = result.get("threat_intelligence", {})
            correlations = len(threat_intel.get("correlations", []))
            threat_score = threat_intel.get("threat_score", 0)
            
            logger.info(f"📊 Found {correlations} threat correlations")
            logger.info(f"🎯 Overall Threat Score: {threat_score:.1f}/100")
        
        return result

@mcp.tool()
def advanced_payload_generation(attack_type: str, target_context: str = "", evasion_level: str = "standard", custom_constraints: str = "") -> Dict[str, Any]:
    """
    Generate advanced payloads with AI-powered evasion techniques and contextual adaptation.
    
    Args:
        attack_type: Type of attack (rce, privilege_escalation, persistence, exfiltration, xss, sqli)
        target_context: Target environment details (OS, software versions, security controls)
        evasion_level: Evasion sophistication (basic, standard, advanced, nation-state)
        custom_constraints: Custom payload constraints (size limits, character restrictions, etc.)
        
    Returns:
        Advanced payloads with multiple evasion techniques and deployment instructions
        
    Example:
        advanced_payload_generation("rce", "Windows 11 + Defender + AppLocker", "nation-state", "max_size:256,no_quotes")
    """
    valid_attack_types = ["rce", "privilege_escalation", "persistence", "exfiltration", "xss", "sqli", "lfi", "ssrf"]
    valid_evasion_levels = ["basic", "standard", "advanced", "nation-state"]
    
    if attack_type not in valid_attack_types:
        attack_type = "rce"
    
    if evasion_level not in valid_evasion_levels:
        evasion_level = "standard"
    
    data = {
        "attack_type": attack_type,
        "target_context": target_context,
        "evasion_level": evasion_level,
        "custom_constraints": custom_constraints
    }
    logger.info(f"🎯 Generating advanced {attack_type} payload | Evasion: {evasion_level}")
    if target_context:
        logger.info(f"🎯 Target Context: {target_context}")
    
    result = inspector_client.safe_post("api/ai/advanced-payload-generation", data)
    
    if result.get("success"):
        payload_gen = result.get("advanced_payload_generation", {})
        payload_count = payload_gen.get("payload_count", 0)
        evasion_applied = payload_gen.get("evasion_level", "none")
        
        logger.info(f"📊 Generated {payload_count} advanced payloads")
        logger.info(f"🛡️ Evasion Level Applied: {evasion_applied}")
    
    return result

@mcp.tool()
def vulnerability_intelligence_dashboard() -> Dict[str, Any]:
        """
        Get a comprehensive vulnerability intelligence dashboard with latest threats and trends.
        
        Returns:
            Dashboard with latest CVEs, trending vulnerabilities, exploit availability, and threat landscape
            
        Example:
            vulnerability_intelligence_dashboard()
        """
        logger.info("📊 Generating vulnerability intelligence dashboard")
        
        # Get latest critical CVEs
        latest_cves = inspector_client.safe_post("api/vuln-intel/cve-monitor", {
            "hours": 24,
            "severity_filter": "CRITICAL",
            "keywords": ""
        })
        
        # Get trending attack types
        trending_research = inspector_client.safe_post("api/vuln-intel/zero-day-research", {
            "target_software": "web applications",
            "analysis_depth": "quick"
        })
        
        # Compile dashboard
        dashboard = {
            "timestamp": time.time(),
            "latest_critical_cves": latest_cves.get("cve_monitoring", {}).get("cves", [])[:5],
            "threat_landscape": {
                "high_risk_software": ["Apache HTTP Server", "Microsoft Exchange", "VMware vCenter", "Fortinet FortiOS"],
                "trending_attack_vectors": ["Supply chain attacks", "Cloud misconfigurations", "Zero-day exploits", "AI-powered attacks"],
                "active_threat_groups": ["APT29", "Lazarus Group", "FIN7", "REvil"],
            },
            "exploit_intelligence": {
                "new_public_exploits": "Simulated data - check exploit-db for real data",
                "weaponized_exploits": "Monitor threat intelligence feeds",
                "exploit_kits": "Track underground markets"
            },
            "recommendations": [
                "Prioritize patching for critical CVEs discovered in last 24h",
                "Monitor for zero-day activity in trending attack vectors",
                "Implement advanced threat detection for active threat groups",
                "Review security controls against nation-state level attacks"
            ]
        }
        
        logger.info("✅ Vulnerability intelligence dashboard generated")
        return {
            "success": True,
            "dashboard": dashboard
        }

@mcp.tool()
def threat_hunting_assistant(target_environment: str, threat_indicators: str = "", hunt_focus: str = "general") -> Dict[str, Any]:
        """
        AI-powered threat hunting assistant with vulnerability correlation and attack simulation.
        
        Args:
            target_environment: Environment to hunt in (e.g., "Windows Domain", "Cloud Infrastructure")
            threat_indicators: Known IOCs or suspicious indicators to investigate
            hunt_focus: Focus area (general, apt, ransomware, insider_threat, supply_chain)
            
        Returns:
            Threat hunting playbook with detection queries, IOCs, and investigation steps
            
        Example:
            threat_hunting_assistant("Windows Domain", "suspicious_process.exe,192.168.1.100", "apt")
        """
        valid_hunt_focus = ["general", "apt", "ransomware", "insider_threat", "supply_chain"]
        if hunt_focus not in valid_hunt_focus:
            hunt_focus = "general"
        
        logger.info(f"🔍 Generating threat hunting playbook for {target_environment} | Focus: {hunt_focus}")
        
        # Parse indicators if provided
        indicators = [i.strip() for i in threat_indicators.split(",") if i.strip()] if threat_indicators else []
        
        # Generate hunting playbook
        hunting_playbook = {
            "target_environment": target_environment,
            "hunt_focus": hunt_focus,
            "indicators_analyzed": indicators,
            "detection_queries": [],
            "investigation_steps": [],
            "threat_scenarios": [],
            "mitigation_strategies": []
        }
        
        # Environment-specific detection queries
        if "windows" in target_environment.lower():
            hunting_playbook["detection_queries"] = [
                "Get-WinEvent | Where-Object {$_.Id -eq 4688 -and $_.Message -like '*suspicious*'}",
                "Get-Process | Where-Object {$_.ProcessName -notin @('explorer.exe', 'svchost.exe')}",
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemoteAddress -notlike '10.*'}"
            ]
        elif "cloud" in target_environment.lower():
            hunting_playbook["detection_queries"] = [
                "CloudTrail logs for unusual API calls",
                "Failed authentication attempts from unknown IPs",
                "Privilege escalation events",
                "Data exfiltration indicators"
            ]
        
        # Focus-specific threat scenarios
        focus_scenarios = {
            "apt": [
                "Spear phishing with weaponized documents",
                "Living-off-the-land techniques",
                "Lateral movement via stolen credentials",
                "Data staging and exfiltration"
            ],
            "ransomware": [
                "Initial access via RDP/VPN",
                "Privilege escalation and persistence",
                "Shadow copy deletion",
                "Encryption and ransom note deployment"
            ],
            "insider_threat": [
                "Unusual data access patterns",
                "After-hours activity",
                "Large data downloads",
                "Access to sensitive systems"
            ]
        }
        
        hunting_playbook["threat_scenarios"] = focus_scenarios.get(hunt_focus, [
            "Unauthorized access attempts",
            "Suspicious process execution",
            "Network anomalies",
            "Data access violations"
        ])
        
        # Investigation steps
        hunting_playbook["investigation_steps"] = [
            "1. Validate initial indicators and expand IOC list",
            "2. Run detection queries and analyze results",
            "3. Correlate events across multiple data sources",
            "4. Identify affected systems and user accounts",
            "5. Assess scope and impact of potential compromise",
            "6. Implement containment measures if threat confirmed",
            "7. Document findings and update detection rules"
        ]
        
        # Correlate with vulnerability intelligence if indicators provided
        if indicators:
            logger.info(f"🧠 Correlating {len(indicators)} indicators with threat intelligence")
            correlation_result = correlate_threat_intelligence(",".join(indicators), "30d", "all")
            
            if correlation_result.get("success"):
                hunting_playbook["threat_correlation"] = correlation_result.get("threat_intelligence", {})
        
        logger.info("✅ Threat hunting playbook generated")
        return {
            "success": True,
            "hunting_playbook": hunting_playbook
        }

    # ============================================================================
    # ENHANCED VISUAL OUTPUT TOOLS
    # ============================================================================
    
@mcp.tool()
def get_live_dashboard() -> Dict[str, Any]:
        """
        Get a beautiful live dashboard showing all active processes with enhanced visual formatting.
        
        Returns:
            Live dashboard with visual process monitoring and system metrics
        """
        logger.info("📊 Fetching live process dashboard")
        result = inspector_client.safe_get("api/processes/dashboard")
        if result.get("success", True):
            logger.info("✅ Live dashboard retrieved successfully")
        else:
            logger.error("❌ Failed to retrieve live dashboard")
        return result

@mcp.tool()
def create_vulnerability_report(vulnerabilities: str, target: str = "", scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Create a beautiful vulnerability report with severity-based styling and visual indicators.
        
        Args:
            vulnerabilities: JSON string containing vulnerability data
            target: Target that was scanned
            scan_type: Type of scan performed
            
        Returns:
            Formatted vulnerability report with visual enhancements
        """
        import json
        
        try:
            # Parse vulnerabilities if provided as JSON string
            if isinstance(vulnerabilities, str):
                vuln_data = json.loads(vulnerabilities)
            else:
                vuln_data = vulnerabilities
            
            logger.info(f"📋 Creating vulnerability report for {len(vuln_data)} findings")
            
            # Create individual vulnerability cards
            vulnerability_cards = []
            for vuln in vuln_data:
                card_result = inspector_client.safe_post("api/visual/vulnerability-card", vuln)
                if card_result.get("success"):
                    vulnerability_cards.append(card_result.get("vulnerability_card", ""))
            
            # Create summary report
            summary_data = {
                "target": target,
                "vulnerabilities": vuln_data,
                "tools_used": [scan_type],
                "execution_time": 0
            }
            
            summary_result = inspector_client.safe_post("api/visual/summary-report", summary_data)
            
            logger.info("✅ Vulnerability report created successfully")
            return {
                "success": True,
                "vulnerability_cards": vulnerability_cards,
                "summary_report": summary_result.get("summary_report", ""),
                "total_vulnerabilities": len(vuln_data),
                "timestamp": summary_result.get("timestamp", "")
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to create vulnerability report: {str(e)}")
            return {"success": False, "error": str(e)}

@mcp.tool()
def format_tool_output_visual(tool_name: str, output: str, success: bool = True) -> Dict[str, Any]:
        """
        Format tool output with beautiful visual styling, syntax highlighting, and structure.
        
        Args:
            tool_name: Name of the security tool
            output: Raw output from the tool
            success: Whether the tool execution was successful
            
        Returns:
            Beautifully formatted tool output with visual enhancements
        """
        logger.info(f"🎨 Formatting output for {tool_name}")
        
        data = {
            "tool": tool_name,
            "output": output,
            "success": success
        }
        
        result = inspector_client.safe_post("api/visual/tool-output", data)
        if result.get("success"):
            logger.info(f"✅ Tool output formatted successfully for {tool_name}")
        else:
            logger.error(f"❌ Failed to format tool output for {tool_name}")
        
        return result

@mcp.tool()
def create_scan_summary(target: str, tools_used: str, vulnerabilities_found: int = 0, 
                           execution_time: float = 0.0, findings: str = "") -> Dict[str, Any]:
        """
        Create a comprehensive scan summary report with beautiful visual formatting.
        
        Args:
            target: Target that was scanned
            tools_used: Comma-separated list of tools used
            vulnerabilities_found: Number of vulnerabilities discovered
            execution_time: Total execution time in seconds
            findings: Additional findings or notes
            
        Returns:
            Beautiful scan summary report with visual enhancements
        """
        logger.info(f"📊 Creating scan summary for {target}")
        
        tools_list = [tool.strip() for tool in tools_used.split(",")]
        
        summary_data = {
            "target": target,
            "tools_used": tools_list,
            "execution_time": execution_time,
            "vulnerabilities": [{"severity": "info"}] * vulnerabilities_found,  # Mock data for count
            "findings": findings
        }
        
        result = inspector_client.safe_post("api/visual/summary-report", summary_data)
        if result.get("success"):
            logger.info("✅ Scan summary created successfully")
        else:
            logger.error("❌ Failed to create scan summary")
        
        return result

@mcp.tool()
def display_system_metrics() -> Dict[str, Any]:
        """
        Display current system metrics and performance indicators with visual formatting.
        
        Returns:
            System metrics with beautiful visual presentation
        """
        logger.info("📈 Fetching system metrics")
        
        # Get telemetry data
        telemetry_result = inspector_client.safe_get("api/telemetry")
        
        if telemetry_result.get("success", True):
            logger.info("✅ System metrics retrieved successfully")
            
            # Format the metrics for better display
            metrics = telemetry_result.get("system_metrics", {})
            stats = {
                "cpu_percent": metrics.get("cpu_percent", 0),
                "memory_percent": metrics.get("memory_percent", 0),
                "disk_usage": metrics.get("disk_usage", 0),
                "uptime_seconds": telemetry_result.get("uptime_seconds", 0),
                "commands_executed": telemetry_result.get("commands_executed", 0),
                "success_rate": telemetry_result.get("success_rate", "0%")
            }
            
            return {
                "success": True,
                "metrics": stats,
                "formatted_display": f"""
🖥️  System Performance Metrics:
├─ CPU Usage: {stats['cpu_percent']:.1f}%
├─ Memory Usage: {stats['memory_percent']:.1f}%
├─ Disk Usage: {stats['disk_usage']:.1f}%
├─ Uptime: {stats['uptime_seconds']:.0f}s
├─ Commands Executed: {stats['commands_executed']}
└─ Success Rate: {stats['success_rate']}
""",
                "timestamp": telemetry_result.get("timestamp", "")
            }
        else:
            logger.error("❌ Failed to retrieve system metrics")
            return telemetry_result

    # ============================================================================
    # INTELLIGENT DECISION ENGINE TOOLS
    # ============================================================================
    
@mcp.tool()
def analyze_target_intelligence(target: str) -> Dict[str, Any]:
    """
    Analyze target using AI-powered intelligence to create comprehensive profile.
    
    Args:
        target: Target URL, IP address, or domain to analyze
            
    Returns:
        Comprehensive target profile with technology detection, risk assessment, and recommendations
    """
    logger.info(f"🧠 Analyzing target intelligence for: {target}")
    
    data = {"target": target}
    result = inspector_client.safe_post("api/intelligence/analyze-target", data)
    
    if result.get("success"):
        profile = result.get("target_profile", {})
        logger.info(f"✅ Target analysis completed - Type: {profile.get('target_type')}, Risk: {profile.get('risk_level')}")
    else:
        logger.error(f"❌ Target analysis failed for {target}")
    
    return result

    @mcp.tool()
    def select_optimal_tools_ai(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        Use AI to select optimal security tools based on target analysis and testing objective.
        
        Args:
            target: Target to analyze
            objective: Testing objective - "comprehensive", "quick", or "stealth"
            
        Returns:
            AI-selected optimal tools with effectiveness ratings and target profile
        """
        logger.info(f"🎯 Selecting optimal tools for {target} with objective: {objective}")
        
        data = {
            "target": target,
            "objective": objective
        }
        result = inspector_client.safe_post("api/intelligence/select-tools", data)
        
        if result.get("success"):
            tools = result.get("selected_tools", [])
            logger.info(f"✅ AI selected {len(tools)} optimal tools: {', '.join(tools[:3])}{'...' if len(tools) > 3 else ''}")
        else:
            logger.error(f"❌ Tool selection failed for {target}")
        
        return result

    @mcp.tool()
    def optimize_tool_parameters_ai(target: str, tool: str, context: str = "{}") -> Dict[str, Any]:
        """
        Use AI to optimize tool parameters based on target profile and context.
        
        Args:
            target: Target to test
            tool: Security tool to optimize
            context: JSON string with additional context (stealth, aggressive, etc.)
            
        Returns:
            AI-optimized parameters for maximum effectiveness
        """
        import json
        
        logger.info(f"⚙️  Optimizing parameters for {tool} against {target}")
        
        try:
            context_dict = json.loads(context) if context != "{}" else {}
        except:
            context_dict = {}
        
        data = {
            "target": target,
            "tool": tool,
            "context": context_dict
        }
        result = inspector_client.safe_post("api/intelligence/optimize-parameters", data)
        
        if result.get("success"):
            params = result.get("optimized_parameters", {})
            logger.info(f"✅ Parameters optimized for {tool} - {len(params)} parameters configured")
        else:
            logger.error(f"❌ Parameter optimization failed for {tool}")
        
        return result

    @mcp.tool()
    def create_attack_chain_ai(target: str, objective: str = "comprehensive") -> Dict[str, Any]:
        """
        Create an intelligent attack chain using AI-driven tool sequencing and optimization.
        
        Args:
            target: Target for the attack chain
            objective: Attack objective - "comprehensive", "quick", or "stealth"
            
        Returns:
            AI-generated attack chain with success probability and time estimates
        """
        logger.info(f"⚔️  Creating AI-driven attack chain for {target}")
        
        data = {
            "target": target,
            "objective": objective
        }
        result = inspector_client.safe_post("api/intelligence/create-attack-chain", data)
        
        if result.get("success"):
            chain = result.get("attack_chain", {})
            steps = len(chain.get("steps", []))
            success_prob = chain.get("success_probability", 0)
            estimated_time = chain.get("estimated_time", 0)
            
            logger.info(f"✅ Attack chain created - {steps} steps, {success_prob:.2f} success probability, ~{estimated_time}s")
        else:
            logger.error(f"❌ Attack chain creation failed for {target}")
        
        return result

    @mcp.tool()
    def intelligent_smart_scan(target: str, objective: str = "comprehensive", max_tools: int = 5) -> Dict[str, Any]:
        """
        Execute an intelligent scan using AI-driven tool selection and parameter optimization.
        
        Args:
            target: Target to scan
            objective: Scanning objective - "comprehensive", "quick", or "stealth"
            max_tools: Maximum number of tools to use
            
        Returns:
            Results from AI-optimized scanning with tool execution summary
        """
        logger.info(f"{InspectorColors.FIRE_RED}🚀 Starting intelligent smart scan for {target}{InspectorColors.RESET}")
        
        data = {
            "target": target,
            "objective": objective,
            "max_tools": max_tools
        }
        result = inspector_client.safe_post("api/intelligence/smart-scan", data)
        
        if result.get("success"):
            scan_results = result.get("scan_results", {})
            tools_executed = scan_results.get("tools_executed", [])
            execution_summary = scan_results.get("execution_summary", {})
            
            # Enhanced logging with detailed results
            logger.info(f"{InspectorColors.SUCCESS}✅ Intelligent scan completed for {target}{InspectorColors.RESET}")
            logger.info(f"{InspectorColors.CYBER_ORANGE}📊 Execution Summary:{InspectorColors.RESET}")
            logger.info(f"   • Tools executed: {execution_summary.get('successful_tools', 0)}/{execution_summary.get('total_tools', 0)}")
            logger.info(f"   • Success rate: {execution_summary.get('success_rate', 0):.1f}%")
            logger.info(f"   • Total vulnerabilities: {scan_results.get('total_vulnerabilities', 0)}")
            logger.info(f"   • Execution time: {execution_summary.get('total_execution_time', 0):.2f}s")
            
            # Log successful tools
            successful_tools = [t['tool'] for t in tools_executed if t.get('success')]
            if successful_tools:
                logger.info(f"{InspectorColors.HIGHLIGHT_GREEN} Successful tools: {', '.join(successful_tools)} {InspectorColors.RESET}")
            
            # Log failed tools
            failed_tools = [t['tool'] for t in tools_executed if not t.get('success')]
            if failed_tools:
                logger.warning(f"{InspectorColors.HIGHLIGHT_RED} Failed tools: {', '.join(failed_tools)} {InspectorColors.RESET}")
            
            # Log vulnerabilities found
            if scan_results.get('total_vulnerabilities', 0) > 0:
                logger.warning(f"{InspectorColors.VULN_HIGH}🚨 {scan_results['total_vulnerabilities']} vulnerabilities detected!{InspectorColors.RESET}")
        else:
            logger.error(f"{InspectorColors.ERROR}❌ Intelligent scan failed for {target}: {result.get('error', 'Unknown error')}{InspectorColors.RESET}")
        
        return result

    @mcp.tool()
    def detect_technologies_ai(target: str) -> Dict[str, Any]:
        """
        Use AI to detect technologies and provide technology-specific testing recommendations.
        
        Args:
            target: Target to analyze for technology detection
            
        Returns:
            Detected technologies with AI-generated testing recommendations
        """
        logger.info(f"🔍 Detecting technologies for {target}")
        
        data = {"target": target}
        result = inspector_client.safe_post("api/intelligence/technology-detection", data)
        
        if result.get("success"):
            technologies = result.get("detected_technologies", [])
            cms = result.get("cms_type")
            recommendations = result.get("technology_recommendations", {})
            
            tech_info = f"Technologies: {', '.join(technologies)}"
            if cms:
                tech_info += f", CMS: {cms}"
            
            logger.info(f"✅ Technology detection completed - {tech_info}")
            logger.info(f"📋 Generated {len(recommendations)} technology-specific recommendations")
        else:
            logger.error(f"❌ Technology detection failed for {target}")
        
        return result

    @mcp.tool()
    def ai_reconnaissance_workflow(target: str, depth: str = "standard") -> Dict[str, Any]:
        """
        Execute AI-driven reconnaissance workflow with intelligent tool chaining.
        
        Args:
            target: Target for reconnaissance
            depth: Reconnaissance depth - "surface", "standard", or "deep"
            
        Returns:
            Comprehensive reconnaissance results with AI-driven insights
        """
        logger.info(f"🕵️  Starting AI reconnaissance workflow for {target} (depth: {depth})")
        
        # First analyze the target
        analysis_result = inspector_client.safe_post("api/intelligence/analyze-target", {"target": target})
        
        if not analysis_result.get("success"):
            return analysis_result
        
        # Create attack chain for reconnaissance
        objective = "comprehensive" if depth == "deep" else "quick" if depth == "surface" else "comprehensive"
        chain_result = inspector_client.safe_post("api/intelligence/create-attack-chain", {
            "target": target,
            "objective": objective
        })
        
        if not chain_result.get("success"):
            return chain_result
        
        # Execute the reconnaissance
        scan_result = inspector_client.safe_post("api/intelligence/smart-scan", {
            "target": target,
            "objective": objective,
            "max_tools": 8 if depth == "deep" else 3 if depth == "surface" else 5
        })
        
        logger.info(f"✅ AI reconnaissance workflow completed for {target}")
        
        return {
            "success": True,
            "target": target,
            "depth": depth,
            "target_analysis": analysis_result.get("target_profile", {}),
            "attack_chain": chain_result.get("attack_chain", {}),
            "scan_results": scan_result.get("scan_results", {}),
            "timestamp": datetime.now().isoformat()
        }

    @mcp.tool()
    def ai_vulnerability_assessment(target: str, focus_areas: str = "all") -> Dict[str, Any]:
        """
        Perform AI-driven vulnerability assessment with intelligent prioritization.
        
        Args:
            target: Target for vulnerability assessment
            focus_areas: Comma-separated focus areas - "web", "network", "api", "all"
            
        Returns:
            Prioritized vulnerability assessment results with AI insights
        """
        logger.info(f"🔬 Starting AI vulnerability assessment for {target}")
        
        # Analyze target first
        analysis_result = inspector_client.safe_post("api/intelligence/analyze-target", {"target": target})
        
        if not analysis_result.get("success"):
            return analysis_result
        
        profile = analysis_result.get("target_profile", {})
        target_type = profile.get("target_type", "unknown")
        
        # Select tools based on focus areas and target type
        if focus_areas == "all":
            objective = "comprehensive"
        elif "web" in focus_areas and target_type == "web_application":
            objective = "comprehensive"
        elif "network" in focus_areas and target_type == "network_host":
            objective = "comprehensive"
        else:
            objective = "quick"
        
        # Execute vulnerability assessment
        scan_result = inspector_client.safe_post("api/intelligence/smart-scan", {
            "target": target,
            "objective": objective,
            "max_tools": 6
        })
        
        logger.info(f"✅ AI vulnerability assessment completed for {target}")
        
        return {
            "success": True,
            "target": target,
            "focus_areas": focus_areas,
            "target_analysis": profile,
            "vulnerability_scan": scan_result.get("scan_results", {}),
            "risk_assessment": {
                "risk_level": profile.get("risk_level", "unknown"),
                "attack_surface_score": profile.get("attack_surface_score", 0),
                "confidence_score": profile.get("confidence_score", 0)
            },
            "timestamp": datetime.now().isoformat()
        }

    # ============================================================================
    # BUG BOUNTY HUNTING SPECIALIZED WORKFLOWS
    # ============================================================================

    @mcp.tool()
    def bugbounty_reconnaissance_workflow(domain: str, scope: str = "", out_of_scope: str = "", 
                                        program_type: str = "web") -> Dict[str, Any]:
        """
        Create comprehensive reconnaissance workflow for bug bounty hunting.
        
        Args:
            domain: Target domain for bug bounty
            scope: Comma-separated list of in-scope domains/IPs
            out_of_scope: Comma-separated list of out-of-scope domains/IPs
            program_type: Type of program (web, api, mobile, iot)
            
        Returns:
            Comprehensive reconnaissance workflow with phases and tools
        """
        data = {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "out_of_scope": out_of_scope.split(",") if out_of_scope else [],
            "program_type": program_type
        }
        
        logger.info(f"🎯 Creating reconnaissance workflow for {domain}")
        result = inspector_client.safe_post("api/bugbounty/reconnaissance-workflow", data)
        
        if result.get("success"):
            workflow = result.get("workflow", {})
            logger.info(f"✅ Reconnaissance workflow created - {workflow.get('tools_count', 0)} tools, ~{workflow.get('estimated_time', 0)}s")
        else:
            logger.error(f"❌ Failed to create reconnaissance workflow for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_vulnerability_hunting(domain: str, priority_vulns: str = "rce,sqli,xss,idor,ssrf", 
                                       bounty_range: str = "unknown") -> Dict[str, Any]:
        """
        Create vulnerability hunting workflow prioritized by impact and bounty potential.
        
        Args:
            domain: Target domain for bug bounty
            priority_vulns: Comma-separated list of priority vulnerability types
            bounty_range: Expected bounty range (low, medium, high, critical)
            
        Returns:
            Vulnerability hunting workflow prioritized by impact
        """
        data = {
            "domain": domain,
            "priority_vulns": priority_vulns.split(",") if priority_vulns else [],
            "bounty_range": bounty_range
        }
        
        logger.info(f"🎯 Creating vulnerability hunting workflow for {domain}")
        result = inspector_client.safe_post("api/bugbounty/vulnerability-hunting-workflow", data)
        
        if result.get("success"):
            workflow = result.get("workflow", {})
            logger.info(f"✅ Vulnerability hunting workflow created - Priority score: {workflow.get('priority_score', 0)}")
        else:
            logger.error(f"❌ Failed to create vulnerability hunting workflow for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_business_logic_testing(domain: str, program_type: str = "web") -> Dict[str, Any]:
        """
        Create business logic testing workflow for advanced bug bounty hunting.
        
        Args:
            domain: Target domain for bug bounty
            program_type: Type of program (web, api, mobile)
            
        Returns:
            Business logic testing workflow with manual and automated tests
        """
        data = {
            "domain": domain,
            "program_type": program_type
        }
        
        logger.info(f"🎯 Creating business logic testing workflow for {domain}")
        result = inspector_client.safe_post("api/bugbounty/business-logic-workflow", data)
        
        if result.get("success"):
            workflow = result.get("workflow", {})
            test_count = sum(len(category["tests"]) for category in workflow.get("business_logic_tests", []))
            logger.info(f"✅ Business logic testing workflow created - {test_count} tests")
        else:
            logger.error(f"❌ Failed to create business logic testing workflow for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_osint_gathering(domain: str) -> Dict[str, Any]:
        """
        Create OSINT (Open Source Intelligence) gathering workflow for bug bounty reconnaissance.
        
        Args:
            domain: Target domain for OSINT gathering
            
        Returns:
            OSINT gathering workflow with multiple intelligence phases
        """
        data = {"domain": domain}
        
        logger.info(f"🎯 Creating OSINT gathering workflow for {domain}")
        result = inspector_client.safe_post("api/bugbounty/osint-workflow", data)
        
        if result.get("success"):
            workflow = result.get("workflow", {})
            phases = len(workflow.get("osint_phases", []))
            logger.info(f"✅ OSINT workflow created - {phases} intelligence phases")
        else:
            logger.error(f"❌ Failed to create OSINT workflow for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_file_upload_testing(target_url: str) -> Dict[str, Any]:
        """
        Create file upload vulnerability testing workflow with bypass techniques.
        
        Args:
            target_url: Target URL with file upload functionality
            
        Returns:
            File upload testing workflow with malicious files and bypass techniques
        """
        data = {"target_url": target_url}
        
        logger.info(f"🎯 Creating file upload testing workflow for {target_url}")
        result = inspector_client.safe_post("api/bugbounty/file-upload-testing", data)
        
        if result.get("success"):
            workflow = result.get("workflow", {})
            phases = len(workflow.get("test_phases", []))
            logger.info(f"✅ File upload testing workflow created - {phases} test phases")
        else:
            logger.error(f"❌ Failed to create file upload testing workflow for {target_url}")
        
        return result

    @mcp.tool()
    def bugbounty_comprehensive_assessment(domain: str, scope: str = "", 
                                         priority_vulns: str = "rce,sqli,xss,idor,ssrf",
                                         include_osint: bool = True, 
                                         include_business_logic: bool = True) -> Dict[str, Any]:
        """
        Create comprehensive bug bounty assessment combining all specialized workflows.
        
        Args:
            domain: Target domain for bug bounty
            scope: Comma-separated list of in-scope domains/IPs
            priority_vulns: Comma-separated list of priority vulnerability types
            include_osint: Include OSINT gathering workflow
            include_business_logic: Include business logic testing workflow
            
        Returns:
            Comprehensive bug bounty assessment with all workflows and summary
        """
        data = {
            "domain": domain,
            "scope": scope.split(",") if scope else [],
            "priority_vulns": priority_vulns.split(",") if priority_vulns else [],
            "include_osint": include_osint,
            "include_business_logic": include_business_logic
        }
        
        logger.info(f"🎯 Creating comprehensive bug bounty assessment for {domain}")
        result = inspector_client.safe_post("api/bugbounty/comprehensive-assessment", data)
        
        if result.get("success"):
            assessment = result.get("assessment", {})
            summary = assessment.get("summary", {})
            logger.info(f"✅ Comprehensive assessment created - {summary.get('workflow_count', 0)} workflows, ~{summary.get('total_estimated_time', 0)}s")
        else:
            logger.error(f"❌ Failed to create comprehensive assessment for {domain}")
        
        return result

    @mcp.tool()
    def bugbounty_authentication_bypass_testing(target_url: str, auth_type: str = "form") -> Dict[str, Any]:
        """
        Create authentication bypass testing workflow for bug bounty hunting.
        
        Args:
            target_url: Target URL with authentication
            auth_type: Type of authentication (form, jwt, oauth, saml)
            
        Returns:
            Authentication bypass testing strategies and techniques
        """
        bypass_techniques = {
            "form": [
                {"technique": "SQL Injection", "payloads": ["admin'--", "' OR '1'='1'--"]},
                {"technique": "Default Credentials", "payloads": ["admin:admin", "admin:password"]},
                {"technique": "Password Reset", "description": "Test password reset token reuse and manipulation"},
                {"technique": "Session Fixation", "description": "Test session ID prediction and fixation"}
            ],
            "jwt": [
                {"technique": "Algorithm Confusion", "description": "Change RS256 to HS256"},
                {"technique": "None Algorithm", "description": "Set algorithm to 'none'"},
                {"technique": "Key Confusion", "description": "Use public key as HMAC secret"},
                {"technique": "Token Manipulation", "description": "Modify claims and resign token"}
            ],
            "oauth": [
                {"technique": "Redirect URI Manipulation", "description": "Test open redirect in redirect_uri"},
                {"technique": "State Parameter", "description": "Test CSRF via missing/weak state parameter"},
                {"technique": "Code Reuse", "description": "Test authorization code reuse"},
                {"technique": "Client Secret", "description": "Test for exposed client secrets"}
            ],
            "saml": [
                {"technique": "XML Signature Wrapping", "description": "Manipulate SAML assertions"},
                {"technique": "XML External Entity", "description": "Test XXE in SAML requests"},
                {"technique": "Replay Attacks", "description": "Test assertion replay"},
                {"technique": "Signature Bypass", "description": "Test signature validation bypass"}
            ]
        }
        
        workflow = {
            "target": target_url,
            "auth_type": auth_type,
            "bypass_techniques": bypass_techniques.get(auth_type, []),
            "testing_phases": [
                {"phase": "reconnaissance", "description": "Identify authentication mechanisms"},
                {"phase": "baseline_testing", "description": "Test normal authentication flow"},
                {"phase": "bypass_testing", "description": "Apply bypass techniques"},
                {"phase": "privilege_escalation", "description": "Test for privilege escalation"}
            ],
            "estimated_time": 240,
            "manual_testing_required": True
        }
        
        logger.info(f"🎯 Created authentication bypass testing workflow for {target_url}")
        
        return {
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        }

    # ============================================================================
    # ENHANCED HTTP TESTING FRAMEWORK & BROWSER AGENT (BURP SUITE ALTERNATIVE)
    # ============================================================================
    
    @mcp.tool()
    def http_framework_test(url: str, method: str = "GET", data: dict = {}, 
                           headers: dict = {}, cookies: dict = {}, action: str = "request") -> Dict[str, Any]:
        """
        Enhanced HTTP testing framework (Burp Suite alternative) for comprehensive web security testing.
        
        Args:
            url: Target URL to test
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            data: Request data/parameters
            headers: Custom headers
            cookies: Custom cookies
            action: Action to perform (request, spider, proxy_history, set_rules, set_scope, repeater, intruder)
            
        Returns:
            HTTP testing results with vulnerability analysis
        """
        data_payload = {
            "url": url,
            "method": method,
            "data": data,
            "headers": headers,
            "cookies": cookies,
            "action": action
        }
        
        logger.info(f"{InspectorColors.FIRE_RED}🔥 Starting HTTP Framework {action}: {url}{InspectorColors.RESET}")
        result = inspector_client.safe_post("api/tools/http-framework", data_payload)
        
        if result.get("success"):
            logger.info(f"{InspectorColors.SUCCESS}✅ HTTP Framework {action} completed for {url}{InspectorColors.RESET}")
            
            # Enhanced logging for vulnerabilities found
            if result.get("result", {}).get("vulnerabilities"):
                vuln_count = len(result["result"]["vulnerabilities"])
                logger.info(f"{InspectorColors.HIGHLIGHT_RED} Found {vuln_count} potential vulnerabilities {InspectorColors.RESET}")
        else:
            logger.error(f"{InspectorColors.ERROR}❌ HTTP Framework {action} failed for {url}{InspectorColors.RESET}")
        
        return result

    @mcp.tool()
    def browser_agent_inspect(url: str, headless: bool = True, wait_time: int = 5, 
                             action: str = "navigate", proxy_port: int = None, active_tests: bool = False) -> Dict[str, Any]:
        """
        AI-powered browser agent for comprehensive web application inspection and security analysis.
        
        Args:
            url: Target URL to inspect
            headless: Run browser in headless mode
            wait_time: Time to wait after page load
            action: Action to perform (navigate, screenshot, close, status)
            proxy_port: Optional proxy port for request interception
            active_tests: Run lightweight active reflected XSS tests (safe GET-only)
            
        Returns:
            Browser inspection results with security analysis
        """
        data_payload = {
            "url": url,
            "headless": headless,
            "wait_time": wait_time,
            "action": action,
            "proxy_port": proxy_port,
            "active_tests": active_tests
        }
        
        logger.info(f"{InspectorColors.CRIMSON}🌐 Starting Browser Agent {action}: {url}{InspectorColors.RESET}")
        result = inspector_client.safe_post("api/tools/browser-agent", data_payload)
        
        if result.get("success"):
            logger.info(f"{InspectorColors.SUCCESS}✅ Browser Agent {action} completed for {url}{InspectorColors.RESET}")
            
            # Enhanced logging for security analysis
            if action == "navigate" and result.get("result", {}).get("security_analysis"):
                security_analysis = result["result"]["security_analysis"]
                issues_count = security_analysis.get("total_issues", 0)
                security_score = security_analysis.get("security_score", 0)
                
                if issues_count > 0:
                    logger.warning(f"{InspectorColors.HIGHLIGHT_YELLOW} Security Issues: {issues_count} | Score: {security_score}/100 {InspectorColors.RESET}")
                else:
                    logger.info(f"{InspectorColors.HIGHLIGHT_GREEN} No security issues found | Score: {security_score}/100 {InspectorColors.RESET}")
        else:
            logger.error(f"{InspectorColors.ERROR}❌ Browser Agent {action} failed for {url}{InspectorColors.RESET}")
        
        return result

    # ---------------- Additional HTTP Framework Tools (sync with server) ----------------
    @mcp.tool()
    def http_set_rules(rules: list) -> Dict[str, Any]:
        """Set match/replace rules used to rewrite parts of URL/query/headers/body before sending.
        Rule format: {'where':'url|query|headers|body','pattern':'regex','replacement':'string'}"""
        payload = {"action": "set_rules", "rules": rules}
        return inspector_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_set_scope(host: str, include_subdomains: bool = True) -> Dict[str, Any]:
        """Define in-scope host (and optionally subdomains) so out-of-scope requests are skipped."""
        payload = {"action": "set_scope", "host": host, "include_subdomains": include_subdomains}
        return inspector_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_repeater(request_spec: dict) -> Dict[str, Any]:
        """Send a crafted request (Burp Repeater equivalent). request_spec keys: url, method, headers, cookies, data."""
        payload = {"action": "repeater", "request": request_spec}
        return inspector_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def http_intruder(url: str, method: str = "GET", location: str = "query", params: list = None,
                      payloads: list = None, base_data: dict = None, max_requests: int = 100) -> Dict[str, Any]:
        """Simple Intruder (sniper) fuzzing. Iterates payloads over each param individually.
        location: query|body|headers|cookie."""
        payload = {
            "action": "intruder",
            "url": url,
            "method": method,
            "location": location,
            "params": params or [],
            "payloads": payloads or [],
            "base_data": base_data or {},
            "max_requests": max_requests
        }
        return inspector_client.safe_post("api/tools/http-framework", payload)

    @mcp.tool()
    def burpsuite_alternative_scan(target: str, scan_type: str = "comprehensive", 
                                  headless: bool = True, max_depth: int = 3, 
                                  max_pages: int = 50) -> Dict[str, Any]:
        """
        Comprehensive Burp Suite alternative combining HTTP framework and browser agent for complete web security testing.
        
        Args:
            target: Target URL or domain to scan
            scan_type: Type of scan (comprehensive, spider, passive, active)
            headless: Run browser in headless mode
            max_depth: Maximum crawling depth
            max_pages: Maximum pages to analyze
            
        Returns:
            Comprehensive security assessment results
        """
        data_payload = {
            "target": target,
            "scan_type": scan_type,
            "headless": headless,
            "max_depth": max_depth,
            "max_pages": max_pages
        }
        
        logger.info(f"{InspectorColors.BLOOD_RED}🔥 Starting Burp Suite Alternative {scan_type} scan: {target}{InspectorColors.RESET}")
        result = inspector_client.safe_post("api/tools/burpsuite-alternative", data_payload)
        
        if result.get("success"):
            logger.info(f"{InspectorColors.SUCCESS}✅ Burp Suite Alternative scan completed for {target}{InspectorColors.RESET}")
            
            # Enhanced logging for comprehensive results
            if result.get("result", {}).get("summary"):
                summary = result["result"]["summary"]
                total_vulns = summary.get("total_vulnerabilities", 0)
                pages_analyzed = summary.get("pages_analyzed", 0)
                security_score = summary.get("security_score", 0)
                
                logger.info(f"{InspectorColors.HIGHLIGHT_BLUE} SCAN SUMMARY {InspectorColors.RESET}")
                logger.info(f"  📊 Pages Analyzed: {pages_analyzed}")
                logger.info(f"  🚨 Vulnerabilities: {total_vulns}")
                logger.info(f"  🛡️  Security Score: {security_score}/100")
                
                # Log vulnerability breakdown
                vuln_breakdown = summary.get("vulnerability_breakdown", {})
                for severity, count in vuln_breakdown.items():
                    if count > 0:
                        color = {
                                    'critical': InspectorColors.CRITICAL,
        'high': InspectorColors.FIRE_RED,
        'medium': InspectorColors.CYBER_ORANGE,
        'low': InspectorColors.YELLOW,
        'info': InspectorColors.INFO
    }.get(severity.lower(), InspectorColors.WHITE)
                        
                        logger.info(f"  {color}{severity.upper()}: {count}{InspectorColors.RESET}")
        else:
            logger.error(f"{InspectorColors.ERROR}❌ Burp Suite Alternative scan failed for {target}{InspectorColors.RESET}")
        
        return result

    @mcp.tool()
    def error_handling_statistics() -> Dict[str, Any]:
        """
        Get intelligent error handling system statistics and recent error patterns.
        
        Returns:
            Error handling statistics and patterns
        """
        logger.info(f"{InspectorColors.ELECTRIC_PURPLE}📊 Retrieving error handling statistics{InspectorColors.RESET}")
        result = inspector_client.safe_get("api/error-handling/statistics")
        
        if result.get("success"):
            stats = result.get("statistics", {})
            total_errors = stats.get("total_errors", 0)
            recent_errors = stats.get("recent_errors_count", 0)
            
            logger.info(f"{InspectorColors.SUCCESS}✅ Error statistics retrieved{InspectorColors.RESET}")
            logger.info(f"  📈 Total Errors: {total_errors}")
            logger.info(f"  🕒 Recent Errors: {recent_errors}")
            
            # Log error breakdown by type
            error_counts = stats.get("error_counts_by_type", {})
            if error_counts:
                logger.info(f"{InspectorColors.HIGHLIGHT_BLUE} ERROR BREAKDOWN {InspectorColors.RESET}")
                for error_type, count in error_counts.items():
                                          logger.info(f"  {InspectorColors.FIRE_RED}{error_type}: {count}{InspectorColors.RESET}")
        else:
            logger.error(f"{InspectorColors.ERROR}❌ Failed to retrieve error statistics{InspectorColors.RESET}")
        
        return result

    @mcp.tool()
    def test_error_recovery(tool_name: str, error_type: str = "timeout", 
                           target: str = "example.com") -> Dict[str, Any]:
        """
        Test the intelligent error recovery system with simulated failures.
        
        Args:
            tool_name: Name of tool to simulate error for
            error_type: Type of error to simulate (timeout, permission_denied, network_unreachable, etc.)
            target: Target for the simulated test
            
        Returns:
            Recovery strategy and system response
        """
        data_payload = {
            "tool_name": tool_name,
            "error_type": error_type,
            "target": target
        }
        
        logger.info(f"{InspectorColors.RUBY}🧪 Testing error recovery for {tool_name} with {error_type}{InspectorColors.RESET}")
        result = inspector_client.safe_post("api/error-handling/test-recovery", data_payload)
        
        if result.get("success"):
            recovery_strategy = result.get("recovery_strategy", {})
            action = recovery_strategy.get("action", "unknown")
            success_prob = recovery_strategy.get("success_probability", 0)
            
            logger.info(f"{InspectorColors.SUCCESS}✅ Error recovery test completed{InspectorColors.RESET}")
            logger.info(f"  🔧 Recovery Action: {action}")
            logger.info(f"  📊 Success Probability: {success_prob:.2%}")
            
            # Log alternative tools if available
            alternatives = result.get("alternative_tools", [])
            if alternatives:
                logger.info(f"  🔄 Alternative Tools: {', '.join(alternatives)}")
        else:
            logger.error(f"{InspectorColors.ERROR}❌ Error recovery test failed{InspectorColors.RESET}")
        
        return result

def create_mcp_server():
    """Create and configure the MCP server with all security tools."""
    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Inspector AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_INSPECTOR_SERVER, 
                      help=f"Inspector AI API server URL (default: {DEFAULT_INSPECTOR_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Initialize logging system with visual enhancements debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")
    
    # MCP compatibility: No banner output to avoid JSON parsing issues
    logger.info(f"🚀 Starting Inspector AI MCP Client v1.0")
    logger.info(f"🔗 Connecting to: {args.server}")
    
    try:
        # Initialize the Inspector AI client
        inspector_client = InspectorClient(args.server, args.timeout)
        
        # Check server health and log the result
        health = inspector_client.check_health()
        if "error" in health:
            logger.warning(f"⚠️  Unable to connect to Inspector AI API server at {args.server}: {health['error']}")
            logger.warning("🚀 MCP server will start, but tool execution may fail")
        else:
            logger.info(f"🎯 Successfully connected to Inspector AI API server at {args.server}")
            logger.info(f"🏥 Server health status: {health['status']}")
            logger.info(f"📊 Version: {health.get('version', 'unknown')}")
            if not health.get("all_essential_tools_available", False):
                logger.warning("⚠️  Not all essential tools are available on the Inspector server")
                missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
                if missing_tools:
                    logger.warning(f"❌ Missing tools: {', '.join(missing_tools[:5])}{'...' if len(missing_tools) > 5 else ''}")
        
        # Set up and run the MCP server
        mcp = setup_mcp_server(inspector_client)
        logger.info("🚀 Starting Inspector AI MCP server")
        logger.info("🤖 Ready to serve AI agents with enhanced cybersecurity capabilities")
        mcp.run()
    except Exception as e:
        logger.error(f"💥 Error starting MCP server: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()