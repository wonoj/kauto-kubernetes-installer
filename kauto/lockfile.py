"""Exact-version, content-addressed metadata lock; never apply authorization."""
import hashlib
import json

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')

def sha256(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def make_lock(row, config_hash, policy_hash):
    from .compatibility import verified_candidate
    if not verified_candidate(row):
        raise ValueError('Cannot lock unverified or incompletely pinned candidate')
    result = {
        'schemaVersion':'kauto.lock/v1alpha1',
        'stackId':row['id'],
        'os':row['os'], 'infrastructure':row['infrastructure'],
        'kubernetes':row['kubernetes'], 'containerd':row['containerd'],
        'calico':row['calico'],
        'artifactDigests':row['artifactDigests'],
        'testEvidence':row['testEvidence'],
        'configurationSha256':config_hash,
        'policySha256':policy_hash,
        'applyAuthorized':False,
    }
    result['lockSha256'] = sha256(result)
    return result
