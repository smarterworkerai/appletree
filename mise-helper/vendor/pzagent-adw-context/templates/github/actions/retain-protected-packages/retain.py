#!/usr/bin/env python3
import datetime,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path
OWNER=os.environ.get('GITHUB_REPOSITORY','/').split('/',1)[0]; DRY=os.environ.get('DRY_RUN','true')=='true'
def block(x):print('blocked: '+x,file=sys.stderr);raise SystemExit(21)
def api(path,method='GET'):
 r=subprocess.run(['gh','api','--method',method,path],text=True,capture_output=True)
 if r.returncode:block('GitHub package read/write was ambiguous')
 try:return json.loads(r.stdout) if r.stdout.strip() else None
 except json.JSONDecodeError:block('GitHub package response malformed')
def snapshot(packages):
 result={}
 for package in packages:
  values=api(f'/orgs/{OWNER}/packages/container/{package}/versions?per_page=100')
  if not isinstance(values,list):block('package version inventory malformed')
  result[package]=sorted((str(v.get('id')),sorted(v.get('metadata',{}).get('container',{}).get('tags',[]))) for v in values)
 return result
def fingerprint(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
try:data=json.loads(Path(os.environ['INVENTORY_PATH']).read_text())
except (OSError,json.JSONDecodeError):block('closed retention inventory unavailable')
keys={'schema_version','repository','grace_hours','packages','versions','snapshot_sha256'}
if not isinstance(data,dict) or set(data)!=keys or data.get('schema_version')!='1.0.0' or data.get('repository')!=os.environ.get('GITHUB_REPOSITORY'):block('retention inventory invalid')
packages=data['packages']
if not isinstance(packages,list) or not packages or len(packages)!=len(set(packages)) or not all(re.fullmatch(r'[a-z0-9._-]+',x) for x in packages):block('managed package list invalid')
if not isinstance(data['grace_hours'],int) or not 1<=data['grace_hours']<=720:block('retention grace invalid')
versions=data['versions']; by={}
for v in versions:
 if not isinstance(v,dict) or set(v)!={'package','id','created_at','references'} or v['package'] not in packages or not str(v['id']).isdigit():block('retention version invalid')
 key=f"{v['package']}:{v['id']}"
 if key in by or not isinstance(v['references'],list):block('retention graph invalid')
 by[key]=v
live=snapshot(packages)
if fingerprint(live)!=data['snapshot_sha256']:block('managed package inventory changed after planning')
roots=set()
for package,values in live.items():
 for version_id,tags in values:
  if any(tag.endswith('-current') or tag.endswith('-rollback') for tag in tags):roots.add(f'{package}:{version_id}')
protected=set(); stack=list(roots)
while stack:
 key=stack.pop()
 if key in protected:continue
 if key not in by:block('protected version missing from closed graph')
 protected.add(key)
 for ref in by[key]['references']:
  if ref not in by:block('protected reference unknown')
  stack.append(ref)
cutoff=time.time()-data['grace_hours']*3600;candidates=[]
for key,value in by.items():
 try:created=datetime.datetime.fromisoformat(value['created_at'].replace('Z','+00:00')).timestamp()
 except (ValueError,AttributeError):block('retention timestamp invalid')
 if key not in protected and created<cutoff:candidates.append(key)
if DRY:print(json.dumps({'dry_run':True,'candidates':sorted(candidates),'protected':len(protected)}));raise SystemExit(0)
expected=live
for key in sorted(candidates):
 if snapshot(packages)!=expected:block('package/tag protection changed before deletion')
 package,version_id=key.split(':',1)
 api(f'/orgs/{OWNER}/packages/container/{package}/versions/{version_id}','DELETE')
 updated=snapshot(packages)
 if any(item[0]==version_id for item in updated[package]):block('deleted package version still present')
 for root in roots:
  p,i=root.split(':',1)
  if not any(item[0]==i for item in updated[p]):block('protected package version disappeared')
 expected=updated
print(json.dumps({'dry_run':False,'deleted':sorted(candidates),'protected':len(protected)}))
