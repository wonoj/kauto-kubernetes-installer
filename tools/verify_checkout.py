#!/usr/bin/env python3
"""Confirm a clean detached Git checkout from the exact first release tag.

This does NOT verify tag signatures or remote account provenance.
"""
from __future__ import annotations
import argparse
import json
import subprocess
from pathlib import Path

def command(repo:Path,*args:str):
    p=subprocess.run(['git','-C',str(repo),*args],capture_output=True,text=True,timeout=20)
    return p.returncode,p.stdout.strip()

def verify(repo:Path,tag:str,origin:str):
    checks={}
    status,sha=command(repo,'rev-parse','HEAD')
    checks['commitReadable']=status==0 and len(sha)==40
    status,tag_sha=command(repo,'rev-parse',f'refs/tags/{tag}^{{commit}}')
    checks['tagMatchesHEAD']=status==0 and tag_sha==sha
    status,remote=command(repo,'remote','get-url','origin')
    checks['expectedOrigin']=status==0 and remote==origin
    status,porcelain=command(repo,'status','--porcelain','--untracked-files=all')
    checks['checkoutClean']=status==0 and not porcelain
    status,branch=command(repo,'symbolic-ref','-q','HEAD')
    checks['detachedTagCheckout']=status!=0
    return {'status':'PASS' if all(checks.values()) else 'FAIL',
            'checks':checks, 'commit':sha if checks['commitReadable'] else None,
            'tag':tag, 'origin':remote if checks['expectedOrigin'] else None,
            'warning':'A matching remote URL and tag do not authenticate the GitHub publisher; independent commit/signature verification required.'}

def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument('--repo',type=Path,default=Path.cwd())
    ap.add_argument('--tag',required=True)
    ap.add_argument('--origin',required=True)
    ns=ap.parse_args(argv)
    result=verify(ns.repo,ns.tag,ns.origin)
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 3

if __name__=='__main__':raise SystemExit(main())
