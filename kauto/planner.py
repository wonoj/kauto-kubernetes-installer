"""Read-only deterministic plan PREVIEW. No apply or remote actions."""
from .compatibility import decide
from .lockfile import sha256

def preview(resolved):
    decision = decide(resolved)
    nodes = resolved.inventory.get('nodes', [])
    ids = [n['id'] for n in nodes]
    cp = [n['id'] for n in nodes if n.get('role') == 'control-plane']
    workers = [n['id'] for n in nodes if n.get('role') == 'worker']
    tasks = [
        ('01-preflight', ids, 'Authenticated host and network inspection'),
        ('02-runtime', ids, 'Host setup and containerd CRI'),
        ('03-control-plane', cp, 'kubeadm init (versioned YAML)'),
        ('04-calico', ids, 'Calico installation and node network validation'),
        ('05-join', workers, 'CA-hash verified Worker join'),
        ('06-validate', ids, 'Nodes, Pod/Service networking, DNS, policies'),
    ]
    spec = resolved.cluster.get('spec', {})
    if spec.get('backup', {}).get('etcd', {}).get('enabled'):
        tasks.append(('07-snapshot', cp, 'Encrypted etcd snapshot'))
    if any(v.get('enabled') for v in spec.get('addons', {}).values()):
        tasks.append(('08-addons', cp, 'Validated optional add-ons'))
    blockers = (list(resolved.checks.get('errors', []))
                + list(decision.blockers)
                + list(resolved.checks.get('preflightRequired', []))
                + ['Read-only Step 1: authenticated remote preflight and apply are not implemented'])
    result = {
        'apiVersion':'kauto.plan-preview/v1alpha1',
        'status':'BLOCKED', 'executable':False, 'applyAuthorized':False,
        'clusterName':resolved.cluster.get('metadata', {}).get('name'),
        'staticStatus':resolved.checks['staticStatus'],
        'inputHashes':{
            'clusterSha256':sha256(resolved.cluster),
            'inventorySha256':sha256(resolved.inventory),
            'policySha256':sha256(resolved.policy),
        },
        'candidates':[{'id':r['id'], 'status':r['status']} for r in decision.candidates],
        'resolvedVersions':None if decision.selected is None else {
            'kubernetes':decision.selected['kubernetes']['version'],
            'containerd':decision.selected['containerd']['exactPatch'],
            'calico':decision.selected['calico']['version'],
        },
        'actionPreview':[{'id':i, 'targets':target, 'description':desc} for i,target,desc in tasks],
        'blockers':list(dict.fromkeys(blockers)),
        'warnings':resolved.checks.get('warnings', []),
    }
    result['previewSha256'] = sha256(result)
    return result
