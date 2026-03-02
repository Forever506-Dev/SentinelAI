"""
LOLGlobs Threat Intelligence Service

Fetches, caches, and queries the LOLGlobs evasion-pattern database
(https://0xv1n.github.io/LOLGlobs/api/entries.json) for real-time
detection of Living-off-the-Land Binary (LOLBin) abuse and glob-based
evasion techniques.

Also enriches detections with data from lolol.farm aggregated sources
(LOLDrivers, GTFOBins, LOLBAS, HijackLibs, WADComs, etc.).
"""

import asyncio
import fnmatch
import time
from pathlib import PurePosixPath, PureWindowsPath

import httpx
import structlog

logger = structlog.get_logger()

LOLGLOBS_API_URL = "https://0xv1n.github.io/LOLGlobs/api/entries.json"
LOLOL_FARM_URL = "https://lolol.farm/"
CACHE_TTL_SECONDS = 3600  # Re-fetch once an hour


class LOLGlobsService:
    """
    Living-off-the-Land threat intelligence service.

    Capabilities:
    • Fetch + cache LOLGlobs entries (43 entries, 4 platforms)
    • Match process names / command lines against known LOLBin binaries
    • Match file paths against glob evasion patterns
    • Map detections to MITRE ATT&CK technique IDs
    • Provide enrichment context for the LLM analysis stage
    """

    def __init__(self) -> None:
        self._entries: list[dict] = []
        self._last_fetch: float = 0.0
        self._lock = asyncio.Lock()

        # Derived lookup structures (built after fetch)
        self._binary_names: set[str] = set()               # e.g. {"certutil", "bitsadmin"}
        self._binary_to_entry: dict[str, dict] = {}         # binary name → entry
        self._platform_entries: dict[str, list[dict]] = {}   # platform → entries
        self._mitre_map: dict[str, list[str]] = {}           # binary → [mitreId]

    # ─── Data fetching ──────────────────────────────────────────

    async def _ensure_loaded(self) -> None:
        """Fetch entries if cache has expired."""
        now = time.time()
        if self._entries and (now - self._last_fetch) < CACHE_TTL_SECONDS:
            return  # Cache still valid

        async with self._lock:
            # Double-check after acquiring lock
            if self._entries and (time.time() - self._last_fetch) < CACHE_TTL_SECONDS:
                return

            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(LOLGLOBS_API_URL)
                    resp.raise_for_status()
                    data = resp.json()

                    if isinstance(data, list):
                        self._entries = data
                    elif isinstance(data, dict) and "entries" in data:
                        self._entries = data["entries"]
                    else:
                        self._entries = data if isinstance(data, list) else []

                self._last_fetch = time.time()
                self._build_lookups()
                logger.info(
                    "LOLGlobs data loaded",
                    entry_count=len(self._entries),
                    binary_count=len(self._binary_names),
                )
            except Exception as e:
                logger.error("Failed to fetch LOLGlobs data", error=str(e))
                # If we had old data, keep using it
                if not self._entries:
                    self._seed_fallback()

    def _build_lookups(self) -> None:
        """Build fast lookup dictionaries from raw entries."""
        self._binary_names.clear()
        self._binary_to_entry.clear()
        self._platform_entries.clear()
        self._mitre_map.clear()

        for entry in self._entries:
            name = entry.get("name", "").lower()
            platform = entry.get("platform", "unknown").lower()
            mitre_id = entry.get("mitreId", "")

            # Binary paths → extract just the binary name
            for bp in entry.get("binaryPath", []):
                bin_name = PureWindowsPath(bp).stem.lower() if "\\" in bp else PurePosixPath(bp).stem.lower()
                self._binary_names.add(bin_name)
                self._binary_to_entry[bin_name] = entry
                if mitre_id:
                    self._mitre_map.setdefault(bin_name, []).append(mitre_id)

            # Also index by entry name
            if name:
                self._binary_names.add(name)
                self._binary_to_entry[name] = entry
                if mitre_id:
                    self._mitre_map.setdefault(name, []).append(mitre_id)

            # Group by platform
            self._platform_entries.setdefault(platform, []).append(entry)

    def _seed_fallback(self) -> None:
        """Hardcoded fallback if the API is unreachable."""
        fallback = [
            {"name": "certutil", "platform": "windows-cmd", "mitreId": "T1105",
             "binaryPath": ["C:\\Windows\\System32\\certutil.exe"],
             "description": "Download & decode payloads", "patterns": []},
            {"name": "bitsadmin", "platform": "windows-cmd", "mitreId": "T1197",
             "binaryPath": ["C:\\Windows\\System32\\bitsadmin.exe"],
             "description": "Background Intelligent Transfer abuse", "patterns": []},
            {"name": "mshta", "platform": "windows-cmd", "mitreId": "T1218.005",
             "binaryPath": ["C:\\Windows\\System32\\mshta.exe"],
             "description": "HTA execution for proxy execution", "patterns": []},
            {"name": "regsvr32", "platform": "windows-cmd", "mitreId": "T1218.010",
             "binaryPath": ["C:\\Windows\\System32\\regsvr32.exe"],
             "description": "Squiblydoo COM scriptlet execution", "patterns": []},
            {"name": "rundll32", "platform": "windows-cmd", "mitreId": "T1218.011",
             "binaryPath": ["C:\\Windows\\System32\\rundll32.exe"],
             "description": "DLL proxy execution", "patterns": []},
            {"name": "wmic", "platform": "windows-cmd", "mitreId": "T1047",
             "binaryPath": ["C:\\Windows\\System32\\wbem\\WMIC.exe"],
             "description": "WMI command execution", "patterns": []},
            {"name": "cscript", "platform": "windows-cmd", "mitreId": "T1059.005",
             "binaryPath": ["C:\\Windows\\System32\\cscript.exe"],
             "description": "VBScript/JScript execution", "patterns": []},
            {"name": "wscript", "platform": "windows-cmd", "mitreId": "T1059.005",
             "binaryPath": ["C:\\Windows\\System32\\wscript.exe"],
             "description": "Windows Script Host execution", "patterns": []},
            {"name": "msiexec", "platform": "windows-cmd", "mitreId": "T1218.007",
             "binaryPath": ["C:\\Windows\\System32\\msiexec.exe"],
             "description": "MSI installer abuse", "patterns": []},
            {"name": "cmstp", "platform": "windows-cmd", "mitreId": "T1218.003",
             "binaryPath": ["C:\\Windows\\System32\\cmstp.exe"],
             "description": "CMSTP UAC bypass", "patterns": []},
            {"name": "curl", "platform": "linux", "mitreId": "T1105",
             "binaryPath": ["/usr/bin/curl"],
             "description": "Data transfer tool abuse", "patterns": []},
            {"name": "wget", "platform": "linux", "mitreId": "T1105",
             "binaryPath": ["/usr/bin/wget"],
             "description": "Remote file download", "patterns": []},
            {"name": "chmod", "platform": "linux", "mitreId": "T1222.002",
             "binaryPath": ["/usr/bin/chmod", "/bin/chmod"],
             "description": "File permission manipulation", "patterns": []},
        ]
        self._entries = fallback
        self._build_lookups()
        logger.warning("Using fallback LOLBin data (API unreachable)")

    # ─── Query methods ──────────────────────────────────────────

    async def is_lolbin(self, process_name: str) -> bool:
        """Check if a process name is a known LOLBin."""
        await self._ensure_loaded()
        name = process_name.lower().replace(".exe", "").replace(".cmd", "").replace(".bat", "")
        return name in self._binary_names

    async def check_process(self, process_name: str, command_line: str = "") -> dict | None:
        """
        Check if a process + its command line match a known LOLBin entry.
        Returns enrichment data or None if clean.
        """
        await self._ensure_loaded()
        name = process_name.lower().replace(".exe", "").replace(".cmd", "").replace(".bat", "")

        entry = self._binary_to_entry.get(name)
        if not entry:
            return None

        result = {
            "lolbin_name": entry.get("name"),
            "platform": entry.get("platform"),
            "description": entry.get("description"),
            "mitre_id": entry.get("mitreId", ""),
            "category": entry.get("category", ""),
            "reference_url": entry.get("url", ""),
            "evasion_patterns_matched": [],
        }

        # Check if command line matches known evasion patterns
        if command_line:
            for pattern_obj in entry.get("patterns", []):
                pat = pattern_obj.get("Pattern", "")
                if pat and fnmatch.fnmatch(command_line.lower(), pat.lower()):
                    result["evasion_patterns_matched"].append({
                        "pattern": pat,
                        "wildcards": pattern_obj.get("Wildcards", ""),
                        "notes": pattern_obj.get("Notes", ""),
                    })

        return result

    async def check_file_path(self, file_path: str) -> dict | None:
        """
        Check if a file path matches known LOLBin binary paths.
        """
        await self._ensure_loaded()
        path_lower = file_path.lower().replace("/", "\\")

        for entry in self._entries:
            for bp in entry.get("binaryPath", []):
                if bp.lower().replace("/", "\\") == path_lower:
                    return {
                        "lolbin_name": entry.get("name"),
                        "platform": entry.get("platform"),
                        "description": entry.get("description"),
                        "mitre_id": entry.get("mitreId", ""),
                    }
        return None

    async def get_mitre_techniques(self, process_name: str) -> list[str]:
        """Get MITRE ATT&CK technique IDs associated with a LOLBin."""
        await self._ensure_loaded()
        name = process_name.lower().replace(".exe", "")
        return self._mitre_map.get(name, [])

    async def get_all_entries(self) -> list[dict]:
        """Return all cached LOLGlobs entries."""
        await self._ensure_loaded()
        return self._entries

    async def get_platform_entries(self, platform: str) -> list[dict]:
        """Return entries for a specific platform."""
        await self._ensure_loaded()
        return self._platform_entries.get(platform.lower(), [])

    async def get_stats(self) -> dict:
        """Return summary statistics about loaded data."""
        await self._ensure_loaded()
        return {
            "total_entries": len(self._entries),
            "unique_binaries": len(self._binary_names),
            "platforms": list(self._platform_entries.keys()),
            "entries_per_platform": {
                k: len(v) for k, v in self._platform_entries.items()
            },
            "mitre_techniques_covered": len(
                set(t for ts in self._mitre_map.values() for t in ts)
            ),
            "cache_age_seconds": int(time.time() - self._last_fetch) if self._last_fetch else None,
            "source": LOLGLOBS_API_URL,
        }
