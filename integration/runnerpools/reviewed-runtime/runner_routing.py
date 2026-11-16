"""Finite local/hosted routing and immutable recovery bundles for reviewed CI."""
import hashlib
import json
import re
from pathlib import Path

from pool_config import Failure, group_name, labels, require

FALLBACK={'linux':'ubuntu-24.04-arm','macos':'macos-15'}
CHECKOUT='11d5960a326750d5838078e36cf38b85af677262'
APP_TOKEN='fee1f7d63c2ff003460e3d139729b119787bc349'
LOCAL_ATTEMPT="github.run_attempt == 1 || vars.HYPERTEXT_HOSTED_CI_ENABLED != 'true'"


def selector(group,platform,*,repository=False):
    require(platform in FALLBACK and re.fullmatch(r'[a-z][a-z0-9-]+',group),'Unsupported runner routing target.')
    target={'labels':['self-hosted',{'linux':'Linux','macos':'macOS'}[platform],'ARM64',group]}
    if not repository:target={'group':group,**target}
    local=json.dumps(target,separators=(',',':'))
    return "${{ fromJSON(("+LOCAL_ATTEMPT+") && '"+local+"' || '"+json.dumps(FALLBACK[platform])+"') }}"


def parse_selector(value):
    if not isinstance(value,str):return None
    for platform in FALLBACK:
        match=re.search(r'"group":"([a-z][a-z0-9-]+)"',value)
        if match and value in (selector(match[1],platform),selector(match[1],platform).replace('('+LOCAL_ATTEMPT+')','github.run_attempt == 1')):
            return {'group':match[1],'labels':{'self-hosted',{'linux':'Linux','macos':'macOS'}[platform],'ARM64',match[1]},'fallback':FALLBACK[platform]}
        match=re.search(r'"labels":\["self-hosted","(?:Linux|macOS)","ARM64","([a-z][a-z0-9-]+)"\]',value)
        if match and value in (selector(match[1],platform,repository=True),selector(match[1],platform,repository=True).replace('('+LOCAL_ATTEMPT+')','github.run_attempt == 1')):
            return {'group':match[1],'labels':{'self-hosted',{'linux':'Linux','macos':'macOS'}[platform],'ARM64',match[1]},'fallback':FALLBACK[platform],'repository_scoped':True}
    return None


def eligible(source):
    # Package scripts explicitly named deploy:dry-run do not publish anything;
    # every real deployment/signing/migration term still excludes the workflow.
    checked=re.sub(r'\b(?:deploy|publish):dry-run\b','validate',source)
    checked=re.sub(r'(?m)^\s+-?\s*uses: TheHypertextStudio/release-engineering/actions/turbo-cache@[a-f0-9]{40}\s*$', '', checked)
    return not re.search(r'(?im)^\s+(?:environment|uses):\s*[^\n]*\.github/workflows|^\s+environment:',checked) and not re.search(r'(?i)\b(?:deploy|publish|release|codesign|notariz\w*|migrat\w*)\b',checked)


def prepare(source,consumer,profile):
    import pool_policy as policy
    policy.validate_workflow(source,consumer,profile)
    require(eligible(source),'Automatic recovery is for reviewed build/test workflows only; separate release/deploy/migration work first.')
    jobs=policy.workflow_jobs(source)
    lines=source.splitlines(keepends=True)
    result=[];index=0;field=None
    for line in lines:
        match=re.fullmatch(r'  ([A-Za-z0-9_-]+):\s*\n?',line)
        if match and any(j['name']==match[1] for j in jobs):index=next(i for i,j in enumerate(jobs) if j['name']==match[1])
        job=jobs[index]
        field_match=re.match(r'^    ([A-Za-z_][A-Za-z0-9_-]*):',line)
        if field_match:field=field_match[1]
        if job['group'] is not None and line.startswith('    runs-on:'):
            platform=next((p for p in consumer['pools'] if group_name(profile,p)==job['group']),None)
            require(platform is not None,'Job targets an unenrolled pool.')
            result.append('    runs-on: '+selector(job['group'],platform,repository=profile['owner']['type']=='User')+'\n')
        elif job['group'] is not None and field=='runs-on' and (line.startswith('      group:') or line.startswith('      labels:')):
            continue
        else:result.append(line)
    value=guest_preflights(''.join(result))
    policy.validate_workflow(value,consumer,profile)
    return value


def guest_preflights(source):
    """Keep the explicit guest-isolation preflight on local attempts only.

    Ordinary build/test steps are never skipped. A different existing step
    condition requires source review rather than silently replacing its intent.
    """
    pattern=r'(?m)^      - name: Verify fresh isolated (?:Linux|macOS) guest\n(?P<body>(?:(?!      - |  [A-Za-z_]).*\n)*)'
    def replace(match):
        text=match[0]
        require('/etc/runner-pool-generation.json' in text,'Guest preflight does not match the generation contract; review it explicitly.')
        conditions=re.findall(r'^        if: (.+)$',text,re.MULTILINE)
        condition='${{ '+LOCAL_ATTEMPT+' }}'
        require(not conditions or conditions in (['${{ github.run_attempt == 1 }}'],[condition]),'Guest preflight has a custom condition; review it explicitly.')
        if conditions:return text.replace('        if: '+conditions[0],'        if: '+condition,1)
        heading,body=text.split('\n',1)
        return heading+'\n        if: '+condition+'\n'+body
    return re.sub(pattern,replace,source)


def watchdog(workflow_names,*,personal=False):
    require(bool(workflow_names) and all(isinstance(n,str) and n and '\n' not in n for n in workflow_names),'Recovery needs explicit workflow names.')
    roster_permission='permission-administration: read' if personal else 'permission-organization-self-hosted-runners: read'
    return '''name: Hypertext CI recovery
on:
  workflow_run:
    workflows: '''+json.dumps(workflow_names)+'''
    types: [requested]
  workflow_dispatch:
    inputs:
      source_run_id:
        description: Source CI run to continue observing
        required: true
        type: string
      review_revision:
        description: Original trusted recovery workflow revision
        required: true
        type: string
permissions:
  contents: read
  actions: write
  checks: read
concurrency:
  group: hypertext-recovery-${{ github.event.workflow_run.id || inputs.source_run_id }}
  cancel-in-progress: false
jobs:
  recover:
    if: >-
      vars.HYPERTEXT_HOSTED_CI_ENABLED == 'true' && (
      (github.event_name == 'workflow_run' &&
      github.event.workflow_run.head_branch == 'main' &&
      github.event.workflow_run.head_repository.id == github.event.repository.id &&
      contains(fromJSON('["push","workflow_dispatch","schedule"]'), github.event.workflow_run.event) &&
      github.event.workflow_run.run_attempt == 1) ||
      (github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'))
    runs-on: ubuntu-24.04
    timeout-minutes: 55
    steps:
      - uses: actions/checkout@'''+CHECKOUT+'''
        with:
          ref: ${{ github.workflow_sha }}
          persist-credentials: false
          sparse-checkout: .github/hypertext
      - uses: actions/create-github-app-token@'''+APP_TOKEN+'''
        id: roster
        with:
          app-id: ${{ vars.HYPERTEXT_RECOVERY_APP_CLIENT_ID }}
          private-key: ${{ secrets.HYPERTEXT_RECOVERY_APP_PRIVATE_KEY }}
          owner: ${{ github.repository_owner }}
          '''+roster_permission+'''
      - name: Recover unavailable local CI
        env:
          GH_TOKEN: ${{ github.token }}
          RUNNER_ROSTER_TOKEN: ${{ steps.roster.outputs.token }}
        run: python3 .github/hypertext/runner_recovery.py --manifest .github/hypertext/recovery.json
'''


def bundle(workflows,*,personal=False):
    """Workflow mapping must contain only already reviewed repeatable CI sources."""
    entries=[];names=[]
    for path,source in sorted(workflows.items()):
        require(re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml',path),'Unsupported workflow path.')
        match=re.search(r'^name: ([^\n]+)$',source,re.MULTILINE)
        require(match is not None,'Recovery workflows need a literal name.')
        name=match[1].strip().strip('\"\'')
        require('${{' not in name,'Recovery needs a fixed workflow name.')
        names.append(name);entries.append({'path':path,'sha256':hashlib.sha256(source.encode()).hexdigest()})
    return {'.github/workflows/hypertext-recovery.yml':watchdog(names,personal=personal),
            '.github/hypertext/recovery.json':json.dumps({'schema_version':1,'workflows':entries},indent=2)+'\n',
            '.github/hypertext/runner_recovery.py':Path(__file__).with_name('runner_recovery.py').read_text()}

def refresh(profile,repo,checkout,*,write=False):
    """Refresh only generated recovery files from explicitly reviewed local CI."""
    import process_control
    from pool_config import validate
    profile=validate(profile);root=Path(checkout).resolve(strict=True)
    consumers=[c for c in profile['consumers'] if c['repo']==repo]
    require(bool(consumers),'Repository is not enrolled in this profile.')
    def target(path):
        value=root/path
        for part in [value,*value.parents]:
            if part==root:break
            require(not part.is_symlink(),'Recovery refresh refuses symlinked repository paths.')
        return value
    sources={}
    for consumer in consumers:
        path=consumer['workflow'];value=target(path).read_text()
        if not eligible(value):continue
        require(prepare(value,consumer,profile)==value,'Review and commit finite runner routing before refreshing recovery files.')
        sources[path]=value
    require(bool(sources),'No repeatable CI workflows are eligible for recovery.')
    changed=[]
    for path,value in sorted(bundle(sources,personal=profile['owner']['type']=='User').items()):
        destination=target(path)
        if destination.exists() and destination.read_text()==value:continue
        changed.append(path)
        if write:
            destination.parent.mkdir(parents=True,exist_ok=True)
            process_control.atomic_write(destination,value.encode(),mode=0o644)
    return changed


def main(argv=None):
    import argparse
    from pool_config import load
    parser=argparse.ArgumentParser(description='Refresh reviewed CI recovery files before committing workflow changes.')
    parser.add_argument('--profile',required=True);parser.add_argument('--repo',required=True)
    parser.add_argument('--checkout',default='.');parser.add_argument('--write',action='store_true')
    args=parser.parse_args(argv)
    try:
        changed=refresh(load(args.profile),args.repo,args.checkout,write=args.write)
        print(json.dumps({'schema_version':1,'changed':changed,'written':args.write}))
        return 0 if args.write or not changed else 1
    except (Failure,OSError,ValueError):
        print(json.dumps({'schema_version':1,'status':'blocked','reason':'Cannot refresh reviewed recovery files; check enrolled routing and filesystem paths.'}))
        return 2


if __name__=='__main__':raise SystemExit(main())
