"""
File Integrity Monitoring Engine
Phase 24 - File Integrity Monitoring Subsystem
SHA-256 Verification, Cryptographic Tamper-Sealing, Baseline Diffing,
and Multi-Dimensional Change Detection (Content, Permissions, Ownership).
"""

import hmac
import hashlib
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from backend.fim.fim_config import CRITICAL_LINUX_PATHS


def calculate_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of byte content."""
    return hashlib.sha256(data).hexdigest()


def generate_baseline_seal(records: List[Dict[str, Any]], secret_key: str = "fim-tamper-seal-secret") -> str:
    """
    Generate an HMAC-SHA256 seal across the sorted baseline records
    to protect baseline integrity against unauthorized database tampering.
    """
    sorted_recs = sorted(records, key=lambda r: r.get("file_path", ""))
    canonical_repr = json.dumps(
        [
            {
                "path": r.get("file_path"),
                "hash": r.get("sha256_hash"),
                "perm": r.get("permissions"),
                "owner": r.get("owner_name")
            }
            for r in sorted_recs
        ],
        sort_keys=True
    )
    return hmac.new(secret_key.encode(), canonical_repr.encode(), hashlib.sha256).hexdigest()


def verify_baseline_seal(records: List[Dict[str, Any]], seal: str, secret_key: str = "fim-tamper-seal-secret") -> bool:
    """Verify that the baseline matches the cryptographic seal."""
    calculated = generate_baseline_seal(records, secret_key)
    return hmac.compare_digest(calculated, seal)


class FimEngine:
    """
    Compares runtime file states against recorded baselines and outputs integrity violation events.
    """

    @staticmethod
    def compare_snapshot(
        baseline_records: List[Dict[str, Any]],
        current_records: List[Dict[str, Any]],
        hostname: str
    ) -> List[Dict[str, Any]]:
        """
        Compare active snapshot against baseline and identify:
        - FILE_CREATED
        - FILE_DELETED
        - FILE_MODIFIED (SHA-256 changed)
        - PERMISSION_CHANGED
        - OWNERSHIP_CHANGED
        """
        events = []
        base_map = {r["file_path"]: r for r in baseline_records}
        curr_map = {r["file_path"]: r for r in current_records}

        # 1. Check for Deleted and Modified Files
        for path, base_file in base_map.items():
            path_config = CRITICAL_LINUX_PATHS.get(path, {})
            base_sev = path_config.get("severity", "MEDIUM")

            if path not in curr_map:
                events.append({
                    "hostname": hostname,
                    "file_path": path,
                    "change_type": "DELETED",
                    "severity": "CRITICAL" if base_sev == "CRITICAL" else "HIGH",
                    "old_sha256": base_file.get("sha256_hash"),
                    "new_sha256": None,
                    "old_permissions": base_file.get("permissions"),
                    "new_permissions": None,
                    "old_owner": base_file.get("owner_name"),
                    "new_owner": None,
                    "details": f"Monitored critical file '{path}' was deleted from the system."
                })
                continue

            curr_file = curr_map[path]

            # SHA-256 Content Hash Modification
            if base_file.get("sha256_hash") != curr_file.get("sha256_hash"):
                events.append({
                    "hostname": hostname,
                    "file_path": path,
                    "change_type": "MODIFIED",
                    "severity": base_sev,
                    "old_sha256": base_file.get("sha256_hash"),
                    "new_sha256": curr_file.get("sha256_hash"),
                    "old_permissions": base_file.get("permissions"),
                    "new_permissions": curr_file.get("permissions"),
                    "old_owner": base_file.get("owner_name"),
                    "new_owner": curr_file.get("owner_name"),
                    "details": (
                        f"SHA-256 integrity violation: Content of '{path}' was modified. "
                        f"Old hash: {base_file.get('sha256_hash')[:12]}..., New hash: {curr_file.get('sha256_hash')[:12]}..."
                    )
                })

            # Permission Changes (e.g. SUID added or permissions relaxed)
            if base_file.get("permissions") != curr_file.get("permissions"):
                new_perm = str(curr_file.get("permissions", ""))
                perm_sev = "CRITICAL" if ("777" in new_perm or new_perm.startswith("4")) else "HIGH"
                events.append({
                    "hostname": hostname,
                    "file_path": path,
                    "change_type": "PERMISSION_CHANGED",
                    "severity": perm_sev,
                    "old_sha256": base_file.get("sha256_hash"),
                    "new_sha256": curr_file.get("sha256_hash"),
                    "old_permissions": base_file.get("permissions"),
                    "new_permissions": curr_file.get("permissions"),
                    "old_owner": base_file.get("owner_name"),
                    "new_owner": curr_file.get("owner_name"),
                    "details": f"Permissions changed on '{path}' from {base_file.get('permissions')} to {curr_file.get('permissions')}."
                })

            # Ownership Changes
            if base_file.get("owner_name") != curr_file.get("owner_name"):
                events.append({
                    "hostname": hostname,
                    "file_path": path,
                    "change_type": "OWNERSHIP_CHANGED",
                    "severity": "CRITICAL" if base_file.get("owner_name") == "root" else "HIGH",
                    "old_sha256": base_file.get("sha256_hash"),
                    "new_sha256": curr_file.get("sha256_hash"),
                    "old_permissions": base_file.get("permissions"),
                    "new_permissions": curr_file.get("permissions"),
                    "old_owner": base_file.get("owner_name"),
                    "new_owner": curr_file.get("owner_name"),
                    "details": f"File ownership of '{path}' changed from {base_file.get('owner_name')} to {curr_file.get('owner_name')}."
                })

        # 2. Check for Newly Created Files
        for path, curr_file in curr_map.items():
            if path not in base_map:
                events.append({
                    "hostname": hostname,
                    "file_path": path,
                    "change_type": "CREATED",
                    "severity": "HIGH",
                    "old_sha256": None,
                    "new_sha256": curr_file.get("sha256_hash"),
                    "old_permissions": None,
                    "new_permissions": curr_file.get("permissions"),
                    "old_owner": None,
                    "new_owner": curr_file.get("owner_name"),
                    "details": f"New file '{path}' detected in monitored critical hierarchy."
                })

        return events
