"""Read-only activation checks. Controller keys never leave the host."""
import re
import pool_auth as auth
from pool_config import Failure,require

SECRET='HYPERTEXT_RECOVERY_APP_PRIVATE_KEY'
VARIABLE='HYPERTEXT_RECOVERY_APP_CLIENT_ID'
SLUG='HYPERTEXT_RECOVERY_APP_SLUG'


HOSTED_VARIABLE='HYPERTEXT_HOSTED_CI_ENABLED'


def hosted_recovery_enabled(profile,repo,api=None):
    """Observe repository overrides before inherited organization variables.

    GitHub compares strings without case sensitivity. No missing or unreadable
    inventory may be interpreted as a disabled hosted policy.
    """
    api=api or auth.gh_api
    require(isinstance(repo,str) and any(c['repo']==repo for c in profile['consumers']),
            'Hosted policy observation requires an exact reviewed repository.')
    def variables(kind):
        seen=set();total=None;count=0;found=None
        for page in range(1,101):
            response=api('GET',f'repos/{repo}/actions/{kind}?per_page=30&page={page}')
            require(isinstance(response,dict) and type(response.get('total_count')) is int
                    and 0<=response['total_count']<=3000 and isinstance(response.get('variables'),list),
                    'Hosted policy variable inventory is incomplete.')
            require(total is None or total==response['total_count'],'Hosted policy variable inventory changed; recheck before publication.')
            total=response['total_count'];rows=response['variables']
            require(len(rows)<=30,'Hosted policy variable page exceeds its bound.')
            for row in rows:
                require(isinstance(row,dict) and isinstance(row.get('name'),str)
                        and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,255}',row['name']),
                        'Hosted policy variable identity is invalid.')
                name=row['name'].upper()
                require(name not in seen,'Hosted policy variable inventory is ambiguous.')
                seen.add(name)
                if name==HOSTED_VARIABLE:
                    require(isinstance(row.get('value'),str),'Hosted policy variable value is invalid.')
                    found=row['value']
            count+=len(rows)
            require(count<=total,'Hosted policy variable inventory exceeds its declared count.')
            if count==total:return found
            require(bool(rows),'Hosted policy variable inventory ended early.')
        raise Failure('Hosted policy variable inventory exceeds its bound.')
    value=variables('variables')
    if value is None and profile['owner']['type']=='Organization':
        value=variables('organization-variables')
    return value is not None and value.casefold()=='true'


def _personal_budget_path(profile):
    from pathlib import Path
    return Path.home()/'.config/hypertext-studio/runner-budgets'/(str(profile['owner']['id'])+'.json')


def _personal_budget_ready(profile):
    import json,os,stat,time
    from pool_config import _unique
    path=_personal_budget_path(profile)
    require(all(not p.is_symlink() for p in (path,*path.parents)),'Personal budget observation must not traverse links.')
    try:info=path.lstat()
    except FileNotFoundError:return False
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=4096,'Personal budget observation is not private and owned.')
    try:value=json.loads(path.read_text(),object_pairs_hook=_unique)
    except (ValueError,UnicodeError):raise Failure('Personal budget observation is invalid; inspect the native account settings.') from None
    require(isinstance(value,dict) and set(value)=={'schema_version','owner','actions_limit_usd','stop_usage','observed_at','source'}
            and type(value['schema_version']) is int and value['schema_version']==1 and value['owner']==profile['owner']
            and type(value['actions_limit_usd']) is int and value['actions_limit_usd']==0 and value['stop_usage'] is True
            and type(value['observed_at']) in (int,float) and value['source']=='github-settings',
            'Personal budget observation differs from the exact account and zero-dollar stop.')
    return 0<=time.time()-value['observed_at']<=3600


def remember_personal_budget(profile):
    """Retain a recent native-settings observation; this is not an API check."""
    import os,json,stat,time
    import process_control as control
    require(profile['owner']['type']=='User','Native personal billing confirmation requires a personal account.')
    path=_personal_budget_path(profile)
    require(all(not p.is_symlink() for p in (path,*path.parents)),'Personal budget observation must not traverse links.')
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=path.parent.stat()
    require(info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700,'Personal budget observation directory must be private and owned.')
    if path.exists():_personal_budget_ready(profile)
    control.atomic_write(path,json.dumps({'schema_version':1,'owner':profile['owner'],'actions_limit_usd':0,'stop_usage':True,
        'observed_at':time.time(),'source':'github-settings'},sort_keys=True).encode(),mode=0o600)


def roster_permissions(profile):
    return {'administration' if profile['owner']['type']=='User' else 'organization_self_hosted_runners':'read'}


def readonly(profile,value):
    expected=roster_permissions(profile)
    return (isinstance(value,dict) and all(value.get(k)==v for k,v in expected.items())
            and all(k in ('organization_self_hosted_runners','administration','metadata') and v=='read' for k,v in value.items()))


def shared_reference(*, root=None):
    import os,json,stat
    from pathlib import Path
    from pool_config import app_reference,_unique
    root=Path(root) if root is not None else Path.home()/'.config/hypertext-studio/recovery'
    path=root/'shared.json'
    require(all(not p.is_symlink() for p in (path,*path.parents)), 'Shared recovery metadata must not traverse links.')
    if not path.exists():return None
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=65536,'Shared recovery authorization is not private and owned.')
    app=json.loads(path.read_text(),object_pairs_hook=_unique)
    require(isinstance(app,dict) and set(app)=={'owner','id','client_id','slug','pem'}, 'Shared recovery metadata is malformed.')
    return app_reference({k:app[k] for k in ('owner','client_id','slug')})


def recovery_reference(profile):
    return profile.get('recovery_app') or shared_reference()


def saved_app(profile,*,root=None):
    import os,json,stat
    from pathlib import Path
    from pool_config import _unique
    root=Path(root) if root is not None else Path.home()/'.config/hypertext-studio/recovery'
    reference=profile.get('recovery_app') or shared_reference(root=root)
    path=root/('shared.json' if reference else str(profile['owner']['id'])+'.json')
    require(all(not parent.is_symlink() for parent in (path,*path.parents)),'Recovery credentials must not traverse symlinks.')
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
        and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=65536,'Recovery credentials must be a private owned regular file.')
    app=json.loads(path.read_text(),object_pairs_hook=_unique)
    require(isinstance(app,dict) and set(app)=={'owner','id','client_id','slug','pem'}
        and app['owner']==(reference['owner'] if reference else profile['owner'])
        and (not reference or all(app.get(k)==reference[k] for k in ('client_id','slug'))),
        'Recovery credentials belong to another App identity.')
    return app


def free_budget(profile,api=auth.gh_api):
    """A real owner-wide hard stop, never an estimate of remaining minutes."""
    if profile['owner']['type']=='User':return _personal_budget_ready(profile)
    for page in range(1,101):
        value=api('GET',f'organizations/{profile["owner"]["login"]}/settings/billing/budgets?per_page=100&page={page}')
        rows=value.get('budgets')
        require(isinstance(rows,list),'Cannot verify GitHub spending controls.')
        if any(isinstance(v,dict) and v.get('budget_scope')=='organization'
            and (v.get('budget_product_sku')=='actions' or v.get('budget_product_skus')==['actions'])
            and type(v.get('budget_amount')) in (int,float) and v['budget_amount']==0
            and v.get('prevent_further_usage') is True for v in rows):return True
        if value.get('has_next_page') is False or len(rows)<100:return False
    raise Failure('Spending-control inventory exceeded its bound.')


def ensure_free_budget(profile,api=None):
    """Add a restrictive owner-wide stop only; never raise or remove a budget."""
    api=api or auth.gh_api
    if free_budget(profile,api):return True
    if profile['owner']['type']=='User':
        from runner_console import current_session
        session=current_session()
        require(session is None or not session.machine,
            'Personal account budget confirmation requires your normal Terminal. No spending limit was changed.')
        import sys
        import runner_organizations
        runner_organizations.recheck_account(profile['owner'],api)
        require(sys.stdin.isatty() and sys.stdout.isatty(),
            'Verify the personal account Actions budget is $0 with Stop usage enabled in GitHub settings, then resume in your normal Terminal. No personal budget API is available.')
        from runner_console import Console
        ui=Console()
        ui.note('Confirm the account-wide Actions budget for '+profile['owner']['login']+'. Keep it at $0 with Stop usage enabled.')
        ui.write('    https://github.com/settings/billing/budgets')
        require(ui.prompt('Is that exact account-wide $0 Actions stop enabled? [y/N]').strip().casefold() in ('y','yes'),
            'Personal hosted recovery is blocked until its native zero-dollar spending stop is confirmed.')
        remember_personal_budget(profile)
        return True
    path=f'organizations/{profile["owner"]["login"]}/settings/billing/budgets'
    candidates=[]
    for page in range(1,101):
        value=api('GET',path+f'?per_page=100&page={page}');rows=value.get('budgets')
        require(isinstance(rows,list),'Cannot verify existing spending controls.')
        candidates.extend(row for row in rows if row.get('budget_scope')=='organization'
            and (row.get('budget_product_sku')=='actions' or row.get('budget_product_skus')==['actions']))
        if value.get('has_next_page') is False or len(rows)<100:break
    else:raise Failure('Spending inventory exceeded its bound.')
    require(len(candidates)<=1,'Multiple owner-wide Actions budgets need explicit reconciliation.')
    if candidates:
        identifier=candidates[0].get('id')
        require(isinstance(identifier,str) and re.fullmatch(r'[A-Za-z0-9-]{1,100}',identifier),'Existing Actions budget identity is invalid.')
        # Only reduce this product's spending permission. Other products, alerts
        # and the repository-specific budget inventory remain unchanged.
        api('PATCH',path+'/'+identifier,{'budget_amount':0,'prevent_further_usage':True})
    else:
        api('POST',path,{
            'budget_amount':0,'prevent_further_usage':True,'budget_scope':'organization','budget_entity_name':'',
            'budget_type':'ProductPricing','budget_product_sku':'actions',
            'budget_alerting':{'will_alert':False,'alert_recipients':[]}})
    require(free_budget(profile,api),'GitHub did not confirm the owner-wide $0 Actions spending stop; no paid execution was authorized.')
    return True


def verify_consumers(profile,api):
    """Bind every settings destination to its reviewed immutable repository ID."""
    import pool_policy
    for consumer in profile['consumers']:
        pool_policy._repo(api('GET','repos/'+consumer['repo']),consumer,profile)


def repository_profile(profile,repository):
    """Scope recovery settings to one enrolled or previously accepted repository.

    This is a settings view, never a replacement native profile. Pending choices
    may prepare hosted recovery before their guarded native enrollment runs.
    """
    import pool_config as config
    import pool_policy as policy
    import runner_configuration as configuration
    import runner_routing as routing
    profile=config.validate(profile)
    require(isinstance(repository,str) and re.fullmatch(re.escape(profile['owner']['login'])+
        r'/[A-Za-z0-9_][A-Za-z0-9_.-]*',repository) is not None,
        'Choose an exact repository owned by this GitHub account.')
    selected=[consumer for consumer in profile['consumers'] if consumer['repo']==repository]
    extended=profile
    if not selected:
        selected=[consumer for consumer in configuration.selection(profile) if consumer['repo']==repository]
        require(bool(selected),'This repository is not enrolled or saved in the accepted repository selection.')
        _,extended=policy._extension(profile,dict(profile,consumers=[*profile['consumers'],*selected]))
    metadata=auth.gh_api('GET','repos/'+repository)
    for consumer in selected:
        policy._repo(metadata,consumer,extended)
        source=policy._workflow_source(consumer,auth.gh_api)
        require(routing.prepare(source,consumer,extended)==source,
            'Commit the reviewed bounded recovery routing before preparing this repository.')
    platforms={platform for consumer in selected for platform in consumer['pools']}
    return config.validate(dict(extended,consumers=selected,
        pools={name:pool for name,pool in extended['pools'].items() if name in platforms}))


def credentials_ready(profile,api=None):
    """Check repository settings and App scope, not successful watchdog execution.

    Personal installation inspection needs an App JWT unavailable on a second
    host. Reusing its encrypted settings checks public owner/permission metadata
    only; configure verifies a new installation with its separate key before
    publishing settings. Actual CI must prove installation and secret validity.
    """
    api=api or auth.gh_api
    verify_consumers(profile,api)
    controller=profile.get('github_app') or profile.get('controller_app')
    if not controller:return False
    for repo in sorted({v['repo'] for v in profile['consumers']}):
        found=False;seen=0
        for page in range(1,101):
            value=api('GET',f'repos/{repo}/actions/secrets?per_page=100&page={page}')
            rows=value.get('secrets');total=value.get('total_count')
            require(isinstance(rows,list) and type(total) is int,'Cannot inspect recovery secret metadata.')
            seen+=len(rows)
            found=found or any(isinstance(row,dict) and row.get('name')==SECRET for row in rows)
            if seen>=total:break
            require(bool(rows),'Recovery secret inventory ended early.')
        else:raise Failure('Recovery secret inventory exceeded its bound.')
        if not found:return False
        client=api('GET',f'repos/{repo}/actions/variables/{VARIABLE}').get('value')
        slug=api('GET',f'repos/{repo}/actions/variables/{SLUG}').get('value')
        if not isinstance(slug,str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]*',slug):return False
        app=api('GET','apps/'+slug)
        permissions=app.get('permissions',{})
        reference=recovery_reference(profile)
        expected=reference['owner'] if reference else profile['owner']
        if reference and (client!=reference['client_id'] or slug!=reference['slug']):return False
        if (not isinstance(app.get('owner'),dict) or any(app['owner'].get(k)!=expected[k] for k in ('login','id','type'))):return False
        if (not client or client==controller['client_id'] or app.get('client_id')!=client
                or not readonly(profile,permissions)):
            return False
        if profile['owner']['type']=='Organization' and not _installation(profile,app.get('id'),api):return False
    return True


def recovery_manifest(profile,redirect):
    """One account-wide read-only App, separate from every host controller App."""
    import hashlib
    value=auth.app_manifest(profile,redirect)
    suffix=hashlib.sha256(str(profile['owner']['id']).encode()).hexdigest()[:12]
    value['name']=profile['id'][:10]+'-recovery-'+suffix
    value['default_permissions']=roster_permissions(profile)
    return value


def adopt_shared_recovery(profile, root):
    """Select the existing issuer's read-only App; never create one per account."""
    import json
    from pathlib import Path
    import process_control as control
    issuer=profile.get('controller_app',{}).get('owner',profile['owner'])
    # This temporary value is used only to check issuer identity/read scope;
    # it is never an installed broker profile or an admission policy.
    checking=dict(profile,owner=issuer)
    source=Path(root)/(str(issuer['id'])+'.json')
    require(source.exists(), 'Reuse the existing read-only recovery App from its original configuring Mac; no additional App was created.')
    app=saved_app(checking,root=root)
    _current_app(checking,app)
    control.atomic_write(Path(root)/'shared.json',json.dumps(app,sort_keys=True).encode(),mode=0o600)
    return shared_reference(root=root)


def _require_consent():
    from runner_console import current_session
    import sys
    session=current_session()
    require((session is None or not session.machine) and sys.stdin.isatty() and sys.stdout.isatty(),
        'GitHub recovery approval is required in your normal Terminal. No new App or permission was approved.')


def configure(profile,browser='Hypertext Studio',*,shared=False):
    """Reuse verified grants headlessly; request native consent only if missing."""
    import os
    from pathlib import Path
    import stat
    import json
    import subprocess
    import time
    import pool_config as config
    import pool_setup
    import process_control as control
    import runner_organizations
    profile=config.validate(profile)
    runner_organizations.recheck_account(profile['owner'])
    verify_consumers(profile,auth.gh_api)
    ensure_free_budget(profile)
    if not shared and credentials_ready(profile):return {'schema_version':1,'status':'configured','reused':True}
    root=Path.home()/'.config/hypertext-studio/recovery'
    # Reject every pre-existing link, including intermediate user-config paths.
    for parent in reversed([root,*root.parents]):
        require(not parent.is_symlink(),'Recovery settings must not traverse symlinks.')
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    require(root.stat().st_uid==os.geteuid() and stat.S_IMODE(root.stat().st_mode)==0o700,'Recovery directory must be private and owned.')
    reference=profile.get('recovery_app') or shared_reference(root=root)
    if (shared or profile.get('controller_app')) and reference is None:
        reference=adopt_shared_recovery(profile,root)
    if reference:
        profile=dict(profile,recovery_app=reference)
    saved=root/('shared.json' if reference else str(profile['owner']['id'])+'.json')
    require(not reference or saved.exists(),
            'Configure the shared recovery App on the original configuring Mac; do not create another recovery App.')
    def persist(value):control.atomic_write(saved,json.dumps(value,sort_keys=True).encode(),mode=0o600)
    if saved.exists() or saved.is_symlink():
        info=saved.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
                and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=65536,'Recovery authorization file is unsafe.')
        app=json.loads(saved.read_text(),object_pairs_hook=config._unique)
    else:
        _require_consent()
        with pool_setup.ManifestFlow(profile,manifest_factory=recovery_manifest) as flow:
            from runner_console import Console
            Console().note('Approve the separate read-only recovery App in GitHub. No controller key is copied.')
            __import__('runner_pool').show_in_chrome(flow.start_url,browser)
            require(flow.event.wait(900) and flow.code is not None,'Recovery App consent is pending; rerun the same command.')
            value=auth._request('POST','app-manifests/'+flow.code+'/conversions')
        owner=value.get('owner',{});permissions=value.get('permissions',{})
        require(all(owner.get(k)==profile['owner'][k] for k in ('login','id','type'))
            and readonly(profile,permissions),
            'Converted recovery App has unexpected identity or permissions; no repository secret was written.')
        require(type(value.get('id')) is int and isinstance(value.get('pem'),str)
            and value['pem'].startswith(('-----BEGIN PRIVATE KEY-----','-----BEGIN RSA PRIVATE KEY-----'))
            and isinstance(value.get('client_id'),str) and re.fullmatch(r'[a-z0-9-]+',value.get('slug','')),
            'Recovery App conversion returned incomplete metadata; values suppressed.')
        app={'owner':profile['owner'],'id':value['id'],'client_id':value['client_id'],'slug':value['slug'],'pem':value['pem']}
        persist(app)
    require(set(app)=={'owner','id','client_id','slug','pem'} and app['owner']==(reference['owner'] if reference else profile['owner'])
            and type(app['id']) is int and re.fullmatch(r'[A-Za-z0-9_.-]+',app['client_id'])
            and re.fullmatch(r'[a-z0-9-]+',app['slug']) and app['client_id'] not in {profile.get(field,{}).get('client_id') for field in ('github_app','controller_app')},
            'Recovery authorization belongs to a different identity; preserve it and inspect.')
    _current_app(profile,app)
    def installed():return _installation(profile,app['id'],auth.gh_api,app=app)
    if not installed():
        _require_consent()
        url='https://github.com/apps/'+app['slug']+'/installations/new?target_id='+str(profile['owner']['id'])
        from runner_console import Console
        Console().note('Approve installation for this account and its reviewed CI repositories; choose selected repositories.')
        __import__('runner_pool').show_in_chrome(url,browser)
        deadline=time.monotonic()+900
        while not installed():
            require(time.monotonic()<deadline,'Recovery App installation is pending; rerun the same command.');time.sleep(5)
    # Recheck after approval: permission changes during the browser flow must
    # not cause an overprivileged key export.
    _current_app(profile,app)
    # Native gh encrypts stdin locally with each repository public key. Never
    # put PEM in argv, a guest, stdout or an exported controller configuration.
    env=dict(os.environ)
    for name in ('GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN','GH_DEBUG'):env.pop(name,None)
    env['PATH']='/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin';env['GH_PROMPT_DISABLED']='1'
    for repo in sorted({c['repo'] for c in profile['consumers']}):
        for name,value in ((VARIABLE,app['client_id']),(SLUG,app['slug'])):
            auth.gh_api('PATCH',f'repos/{repo}/actions/variables/{name}',{'name':name,'value':value}) if _variable_exists(repo,name) else auth.gh_api('POST',f'repos/{repo}/actions/variables',{'name':name,'value':value})
        result=subprocess.run(['gh','secret','set',SECRET,'--repo',repo],input=app['pem'],text=True,capture_output=True,timeout=60,env=env)
        require(result.returncode==0,'Recovery secret encryption failed; native output suppressed. Rerun the same command.')
    require(credentials_ready(profile),'Recovery metadata read-back did not confirm the separate read-only App.')
    return {'schema_version':1,'status':'configured','reused':False}


def _variable_exists(repo,name):
    # Collection pagination avoids treating authentication errors as a missing key.
    count=0
    for page in range(1,101):
        value=auth.gh_api('GET',f'repos/{repo}/actions/variables?per_page=100&page={page}');rows=value.get('variables')
        require(isinstance(rows,list) and type(value.get('total_count')) is int,'Variable inventory is incomplete.')
        if any(row.get('name')==name for row in rows):return True
        count+=len(rows)
        if count==value['total_count']:return False
        require(bool(rows),'Variable inventory ended early.')
    raise Failure('Variable inventory exceeds its bound.')


def _installation(profile,app_id,api,*,app=None):
    from pool_policy import _pages
    require(type(app_id) is int and app_id>0,'Recovery App identity is missing.')
    if profile['owner']['type']=='User':
        app=app or saved_app(profile)
        require(app['id']==app_id,'Saved recovery App differs from repository metadata.')
        _current_app(profile,app)
        jwt=_recovery_jwt(app);matches=[];seen=set()
        for page in range(1,101):
            rows=auth._request('GET',f'app/installations?per_page=100&page={page}',token=jwt,array=True)
            require(isinstance(rows,list) and len(rows)<=100,'Recovery installation inventory is invalid.')
            for row in rows:
                require(isinstance(row,dict) and type(row.get('id')) is int and row['id']>0 and row['id'] not in seen,
                    'Recovery installation inventory is ambiguous.')
                seen.add(row['id'])
                if row.get('app_id')==app_id and isinstance(row.get('account'),dict) and all(row['account'].get(k)==v for k,v in profile['owner'].items()):matches.append(row)
            if len(rows)<100:break
        else:raise Failure('Recovery installation inventory exceeds its bound.')
        if len(matches)!=1:return False
        row=matches[0]
        if row.get('suspended_at') is not None or row.get('repository_selection')!='selected' or not readonly(profile,row.get('permissions')):return False
        for repo in sorted({c['repo'] for c in profile['consumers']}):
            try:actual=auth._request('GET','repos/'+repo+'/installation',token=jwt)
            except Failure as error:
                if str(error)=='GitHub API operation failed (HTTP 404); response suppressed.':return False
                raise
            if actual!=row:
                require(actual.get('id')==row['id'] and actual.get('app_id')==app_id and actual.get('account')==row['account']
                    and actual.get('suspended_at') is None and actual.get('repository_selection')=='selected'
                    and readonly(profile,actual.get('permissions')),'Personal recovery installation differs for a selected repository.')
        return True
    rows=_pages(api,'orgs/'+profile['owner']['login']+'/installations','installations')
    matches=[row for row in rows if row.get('app_id')==app_id]
    if len(matches)!=1:return False
    row=matches[0];account=row.get('account',{});permissions=row.get('permissions',{})
    return (row.get('suspended_at') is None and row.get('repository_selection')=='selected'
        and all(account.get(k)==profile['owner'][k] for k in ('login','id','type'))
        and readonly(profile,permissions))


def _recovery_jwt(app):
    import base64,json,os,subprocess,tempfile,time
    require(isinstance(app.get('pem'),str) and app['pem'].startswith(('-----BEGIN PRIVATE KEY-----','-----BEGIN RSA PRIVATE KEY-----')),
            'Saved recovery key format is invalid; no secrets were exported.')
    def b64(raw):return base64.urlsafe_b64encode(raw).rstrip(b'=')
    now=int(time.time())
    message=b64(b'{"alg":"RS256","typ":"JWT"}')+b'.'+b64(json.dumps({'iat':now-60,'exp':now+540,'iss':app['client_id']},separators=(',',':')).encode())
    # tempfile uses a mode-0600 file inside a mode-0700 owned directory. The
    # key is separate read-only App material; no controller key is read here.
    with tempfile.TemporaryDirectory(prefix='hypertext-recovery-key-') as directory:
        path=__import__('pathlib').Path(directory)/'key.pem'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as out:out.write(app['pem'])
        try:result=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-sign',str(path)],input=message,capture_output=True,timeout=15)
        except (OSError,subprocess.SubprocessError):raise Failure('Recovery key signing unavailable; values suppressed.') from None
        require(result.returncode==0 and result.stdout,'Recovery key signing failed; native output suppressed.')
    return (message+b'.'+b64(result.stdout)).decode()


def _current_app(profile,saved):
    reference=recovery_reference(profile)
    value=auth._request('GET','app',token=_recovery_jwt(saved))
    owner=value.get('owner',{});permissions=value.get('permissions',{})
    require(value.get('id')==saved['id'] and value.get('client_id')==saved['client_id']
        and value.get('client_id') not in {profile.get(field,{}).get('client_id') for field in ('github_app','controller_app')}
        and saved['owner']==(reference['owner'] if reference else profile['owner'])
        and all(owner.get(k)==saved['owner'][k] for k in ('login','id','type'))
        and (not reference or (all(saved.get(k)==reference[k] for k in ('client_id','slug')) and value.get('slug')==reference['slug']))
        and readonly(profile,permissions),
        'Recovery key identity or permissions changed; no repository authorization was exported.')
    return value
