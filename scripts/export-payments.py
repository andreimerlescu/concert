#!/usr/bin/env python3
"""Export settled receipts; USD valuation is intentionally left for accounting."""
import argparse, csv, json, sys
from decimal import Decimal
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('journal',help='fastlane.jsonl (read a consistent backup or stop Concert)')
p.add_argument('-o','--output',default='-')
a=p.parse_args();records={}
with open(a.journal,encoding='utf-8') as f:
    for line in f:
        if not line.endswith('\n'):raise SystemExit('Incomplete journal: reconcile before export')
        r=json.loads(line)
        if r['state']=='settled':records[r['fingerprint']]=r
fields=['receipt_id','settled_utc','network','asset','amount_atomic','amount_native','payer','pay_to','transaction','policy_assessment','usd_fmv','usd_fmv_source']
out=sys.stdout if a.output=='-' else open(a.output,'w',encoding='utf-8',newline='')
def cell(v):
    v=str(v)
    return "'"+v if v.startswith(('=','+','-','@','\t','\r')) else v
w=csv.DictWriter(out,fieldnames=fields);w.writeheader()
for r in sorted(records.values(),key=lambda x:x['settled']):
    q=r['requirements'];decimals={'xrpl':6,'stellar':7,'hedera':8,'solana':9}[r['network'].split(':')[0]]
    data=dict(zip(fields,[r['fingerprint'],r['settled'],r['network'],q['asset'],q['amount'],format(Decimal(q['amount'])/(10**decimals),'f'),r['payer'],q['payTo'],r['transaction'],r.get('policy_id',''),'','']))
    w.writerow({k:cell(v) for k,v in data.items()})
if out is not sys.stdout:out.close()