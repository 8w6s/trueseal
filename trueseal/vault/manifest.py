#
# TrueSeal Integrity Manifest Management
#
# Manages cryptographic checksums for vault segments. Ensures no
# supply-chain tampering has occurred before unlocking secrets.
#

import json
import hashlib
from datetime import datetime, timezone

class AegisTamperedError(Exception):
    """Exception raised when TrueSeal detects tampering during integrity check."""
    pass

class AegisManifest:
    """Manages integrity manifest for a TSVault to detect tampering."""
    
    def __init__(self):
        self.ts_records = {}
        self.ts_timestamp = datetime.now(timezone.utc).isoformat()
        
    def forge_payload(self, ts_rel_path, ts_payload):
        """Compute SHA256 for a payload and register it in the manifest."""
        payload_hash = hashlib.sha256(ts_payload).hexdigest()
        self.ts_records[ts_rel_path] = {
            'hash': payload_hash,
            'size': len(ts_payload)
        }
        
    def serialize(self):
        """Pack manifest records into encoded JSON byte stream."""
        manifest_blob = {
            'ts_version': 1,
            'timestamp': self.ts_timestamp,
            'records': self.ts_records
        }
        return json.dumps(manifest_blob, indent=2).encode('utf-8')
    
    @classmethod
    def deserialize(cls, ts_json_bytes):
        """Reconstruct manifest state from a JSON byte stream."""
        raw_dict = json.loads(ts_json_bytes.decode('utf-8'))
        ts_manifest = cls()
        ts_manifest.ts_timestamp = raw_dict.get('timestamp')
        ts_manifest.ts_records = raw_dict.get('records', {})
        return ts_manifest
        
    def verify_payload(self, ts_rel_path, ts_payload):
        """Verify if the unsealed payload exactly matches the original hash."""
        if ts_rel_path not in self.ts_records:
            raise AegisTamperedError(f"Payload not found in manifest for {ts_rel_path} (Possible MITM injection)")
        
        expected_hash = self.ts_records[ts_rel_path]['hash']
        expected_size = self.ts_records[ts_rel_path].get('size')
        
        if expected_size is not None and len(ts_payload) != expected_size:
            raise AegisTamperedError(f"Size mismatch for {ts_rel_path} (Possible truncation)")
            
        actual_hash = hashlib.sha256(ts_payload).hexdigest()
        
        import hmac
        if not hmac.compare_digest(expected_hash, actual_hash):
            raise AegisTamperedError(f"Integrity check failed for {ts_rel_path}")
            
        return True
