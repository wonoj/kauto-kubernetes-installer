#!/usr/bin/env python3
"""Operator-invoked READ-ONLY acceptance snapshot against an explicitly selected lab context.

This script never changes Kubernetes state and cannot attest Pod/Service/Netpol
functional success. A human must separately run isolated active smoke probes.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from kauto.lifecycle import acquire_snapshot, assess_cluster


def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--kubeconfig',type=Path,required=True)
    ap.add_argument('--context',required=True)
    ap.add_argument('--expected-node',action='append',required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args(argv)
    if not args.expected_node or len(set(args.expected_node))!=len(args.expected_node):
        ap.error('Unique expected node names required')
    observed=acquire_snapshot(kubeconfig=args.kubeconfig,context=args.context)
    result=assess_cluster(observed,args.expected_node)
    result['schemaVersion']='kauto.step8-live-readonly/v1alpha1'
    result['source']='LIVE_EXPLICIT_CONTEXT'
    result['expectedNodeNames']=sorted(args.expected_node)
    result['passedInstallationIntegration']=False
    result['networkSmokeTestsExecuted']=False
    result['releaseAuthorized']=False
    data=json.dumps(result,indent=2,sort_keys=True)+'\n'
    args.output.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(args.output,os.O_EXCL|os.O_CREAT|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(data)
    print(json.dumps({'status':result['status'],'summary':result['summary'],
                      'releaseAuthorized':False,'report':str(args.output)}))
    return 2 if result['status']=='FAIL' else 3

if __name__=='__main__': raise SystemExit(main())
