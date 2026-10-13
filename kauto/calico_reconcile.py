"""Read-only Calico ownership/partial-install classification (SEC-802).

Only an in-memory review of observations supplied by a caller. No kubectl,
network, or installation actions. Imported observations are NOT trusted.
"""
from __future__ import annotations

from collections.abc import Mapping

EXPECTED = frozenset({'tigera-operator', 'calico-system',
                      'installations.operator.tigera.io'})


def review_calico_state(observed: Mapping | None, *, expected_install_id: str | None = None) -> dict:
    """Classify state without ever licensing changes or existing-object adoption.

    observed keys: namespace/operator & namespace/calico-system,
    crd/installations.operator.tigera.io, otherForeignObjects (boolean).
    Every value must be absent/present + optional ownership proof, but no
    caller-supplied proof alone is enough to authorize mutations.
    """
    if not isinstance(observed, Mapping) or not observed:
        return {'status': 'UNKNOWN_BLOCKED', 'applyAuthorized': False,
                'reasons': ['No reliable live Calico inventory provided']}
    keys = ('namespace/tigera-operator','namespace/calico-system',
            'crd/installations.operator.tigera.io')
    if any(k not in observed for k in keys):
        return {'status': 'UNKNOWN_BLOCKED', 'applyAuthorized': False,
                'reasons': ['Calico inventory is incomplete']}
    found = []
    for key in keys:
        value = observed[key]
        if not isinstance(value, Mapping) or type(value.get('exists')) is not bool:
            return {'status':'UNKNOWN_BLOCKED','applyAuthorized':False,
                    'reasons':['Malformed observed resource: '+key]}
        if value['exists']:
            found.append(key)
    if observed.get('otherForeignObjects') is not False:
        return {'status':'UNKNOWN_BLOCKED','applyAuthorized':False,
                'reasons':['Foreign/unexamined Calico objects cannot be excluded']}
    if not found:
        return {'status':'CLEAN_CANDIDATE', 'applyAuthorized':False,
                'reasons':['Live, authenticated cluster-side preflight still required']}
    for key in found:
        owner = observed[key].get('managedBy')
        install_id = observed[key].get('installId')
        if owner != 'kauto' or not expected_install_id or install_id != expected_install_id:
            return {'status':'FOREIGN_OR_UNOWNED_BLOCKED','applyAuthorized':False,
                    'reasons':['Existing Calico resources cannot be adopted: '+key]}
    if len(found) != len(keys):
        return {'status':'PARTIAL_OWNED_BLOCKED','applyAuthorized':False,
                'reasons':['Partially installed Calico requires manual recovery review']}
    return {'status':'OWNED_PRESENT_BLOCKED','applyAuthorized':False,
            'reasons':['Matching ownership claims still require live health and version drift validation']}
