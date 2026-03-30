#!/usr/bin/env python3
"""ML-KEM KAT cross-library comparator."""
import os, sys, json, argparse
from pathlib import Path
from datetime import datetime

VARIANTS   = ['mlkem512','mlkem768','mlkem1024']
VDISPLAY   = {'mlkem512':'ML-KEM-512','mlkem768':'ML-KEM-768','mlkem1024':'ML-KEM-1024'}
LIBRARIES  = ['liboqs','pqclean','wolfssl','awslc']
LDISPLAY   = {'liboqs':'liboqs','pqclean':'PQClean','wolfssl':'wolfssl','awslc':'AWS-LC'}
FIELDS     = ['pk','sk','ct','ss']

def parse_rsp(path):
    vecs, cur = [], {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                if 'count' in cur:
                    vecs.append(cur); cur = {}
                continue
            if '=' in line:
                k,_,v = line.partition('=')
                k = k.strip().lower().replace(' ','')
                cur[k] = v.strip()
    if 'count' in cur: vecs.append(cur)
    return vecs

def discover(base):
    results = {v:{} for v in VARIANTS}
    patterns = {
        'liboqs' : ['liboqs_*.rsp'],
        'pqclean': ['pqclean_*.rsp','PQCkemKAT_*.rsp'],
        'wolfssl': ['wolfssl_*.rsp'],
        'awslc'  : ['awslc_*.rsp','*.txt'],
    }
    for v in VARIANTS:
        d = base/v
        if not d.exists(): continue
        for lib,pats in patterns.items():
            for pat in pats:
                matches = list(d.glob(pat))
                if matches:
                    try:
                        vecs = parse_rsp(str(matches[0]))
                        results[v][lib] = {'vecs':vecs,'path':str(matches[0]),'error':None}
                    except Exception as e:
                        results[v][lib] = {'vecs':[],'path':str(matches[0]),'error':str(e)}
                    break
    return results

def compare(data):
    reports = {}
    for variant in VARIANTS:
        libs_data = data.get(variant,{})
        ok_libs = [l for l,r in libs_data.items() if not r['error'] and r['vecs']]
        if len(ok_libs)<2:
            reports[variant]={'libs':ok_libs,'n':0,'field_pass':{},'lib_pass':{}}
            continue
        n = min(len(libs_data[l]['vecs']) for l in ok_libs)
        field_pass = {f:0 for f in FIELDS}
        lib_pass   = {l:0 for l in ok_libs}
        mismatches = []
        for i in range(n):
            vec_ok = {l:True for l in ok_libs}
            for f in FIELDS:
                vals = {l: libs_data[l]['vecs'][i].get(f,'') for l in ok_libs}
                uniq = set(v for v in vals.values() if v)
                if len(uniq)<=1:
                    field_pass[f]+=1
                else:
                    # find outlier
                    from collections import Counter
                    cnt = Counter(v for v in vals.values() if v)
                    dominant = cnt.most_common(1)[0][0]
                    for l,v in vals.items():
                        if v and v!=dominant:
                            vec_ok[l]=False
                            mismatches.append({'variant':VDISPLAY[variant],'count':i,'field':f,'library':l,'expected':dominant[:32]+'...','got':v[:32]+'...'})
            for l in ok_libs:
                if vec_ok[l]: lib_pass[l]+=1
        reports[variant]={'libs':ok_libs,'n':n,'field_pass':field_pass,'lib_pass':lib_pass,'mismatches':mismatches[:10]}
    return reports

def text_report(reports, data):
    W=72; lines=[]
    lines+=['='*W,'  ML-KEM KAT Cross-Library Comparison',
            f'  {datetime.now():%Y-%m-%d %H:%M:%S}','='*W,'']
    # Summary table
    lines+=['SUMMARY','─'*W]
    hdr = f"{'Variant':<16}"+''.join(f"{LDISPLAY[l]:>14}" for l in LIBRARIES)
    lines+=[hdr,'─'*W]
    for v in VARIANTS:
        r=reports.get(v,{}); row=f"{VDISPLAY[v]:<16}"
        for l in LIBRARIES:
            if l not in r.get('libs',[]):
                d=data.get(v,{}).get(l,{})
                cell='ERROR' if d.get('error') else 'N/A'
            else:
                p=r['lib_pass'].get(l,0); n=r['n']
                cell=f"✓{p}/{n}" if p==n else f"✗{p}/{n}" if p==0 else f"~{p}/{n}"
            row+=f"{cell:>14}"
        lines.append(row)
    lines+=['']
    # Field agreement
    lines+=['FIELD AGREEMENT','─'*W]
    for v in VARIANTS:
        r=reports.get(v,{})
        lines.append(f"  {VDISPLAY[v]} (n={r.get('n',0)}):")
        for f in FIELDS:
            p=r.get('field_pass',{}).get(f,0); n=r.get('n',0)
            bar='✓'*min(p,20)+'✗'*min(n-p,20) if n else ''
            lines.append(f"    {f:4s}  {p:3d}/{n if n else '?'}  {bar}")
        lines.append('')
    # Mismatches
    lines+=['MISMATCHES (first 10 per variant)','─'*W]
    any_mm=False
    for v in VARIANTS:
        mm=reports.get(v,{}).get('mismatches',[])
        if mm:
            any_mm=True
            lines.append(f"  {VDISPLAY[v]}:")
            for m in mm:
                lines.append(f"    count={m['count']} field={m['field']} lib={m['library']}")
                lines.append(f"      expected: {m['expected']}")
                lines.append(f"      got:      {m['got']}")
    if not any_mm:
        lines.append('  None — all libraries agree on all vectors.')
    lines+=['','='*W]
    return '\n'.join(lines)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--vectors',default=os.path.expanduser('~/pqc-kat-eval/vectors'))
    ap.add_argument('--out',default=os.path.expanduser('~/pqc-kat-eval/results'))
    ap.add_argument('--json',action='store_true')
    args=ap.parse_args()
    base=Path(args.vectors); out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    if not base.exists():
        print(f"ERROR: {base} not found. Run 00_setup.sh first."); sys.exit(1)
    print(f"Scanning {base}...")
    data=discover(base)
    print("\nFound:")
    for v in VARIANTS:
        print(f"  {VDISPLAY[v]}:")
        for l in LIBRARIES:
            r=data.get(v,{}).get(l)
            if r and not r['error']: print(f"    {LDISPLAY[l]:10s}: {len(r['vecs']):3d} vectors")
            elif r and r['error']:   print(f"    {LDISPLAY[l]:10s}: ERROR — {r['error']}")
            else:                    print(f"    {LDISPLAY[l]:10s}: not found")
    print("\nComparing...")
    reports=compare(data)
    txt=text_report(reports,data)
    (out/'mlkem_kat_comparison.txt').write_text(txt)
    print(f"\nReport: {out/'mlkem_kat_comparison.txt'}")
    if args.json:
        jout={v:{l:{'passed':reports.get(v,{}).get('lib_pass',{}).get(l),'total':reports.get(v,{}).get('n')} for l in LIBRARIES} for v in VARIANTS}
        (out/'mlkem_kat_comparison.json').write_text(json.dumps(jout,indent=2))
        print(f"JSON:   {out/'mlkem_kat_comparison.json'}")
    print('\n'+txt)

if __name__=='__main__': main()
