#!/usr/bin/env python3
"""Resumable native fleet migration; never kills a busy job or exports App keys."""
import argparse
from contextlib import ExitStack, redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import pool_config as config
from pool_config import Failure,require
import pool_host as host
import pool_auth as auth
import pool_policy as policy
import process_control as control
import runner_fleet as fleet

LEGACY=frozenset(('runner_pool.py','pool_setup.py','pool_config.py','pool_policy.py','pool_auth.py',
    'pool_vm.py','pool_guest.py','pool_host.py','pool_runtime.py','pool_account.py','pool_python.py',
    'macos_host.py','self_hosted_runner.py','process_control.py','runner_console.py'))
STAGES=('prepared','quiesced','stopped','recovering','publishing','resuming','complete')


def propose(profile,identity,role):
    require(re.fullmatch(r'[a-f0-9]{12}',identity or '') and role in ('desktop','laptop'),'Invalid host admission identity.')
    result=config.validate(profile);result['fleet']={'host_id':identity,'role':role}
    return config.validate(result)


def transition(before,after):
    before,after=config.validate(before),config.validate(after)
    shared = after.get('controller_app')
    allowed = {'fleet'} | ({'controller_app', 'github_app'} if shared else set())
    require({k:v for k,v in before.items() if k not in allowed}=={k:v for k,v in after.items() if k not in allowed},
            'Fleet migration cannot change repository access, resources or account identity.')
    if shared:
        require(before.get('controller_app') in (None, shared)
                and after.get('github_app', {}).get('client_id') == shared['client_id'],
                'Shared migration must use the selected controller registration and its exact installation.')
    require('fleet' in after and ('fleet' not in before or before['fleet']==after['fleet']),
            'Fleet migration cannot move an installed host identity to another Mac.')
    return before,after


def advance(backend):
    """Checkpoints precede interruption-sensitive operations, never inferred success."""
    require(backend.stage in STAGES,'Unknown migration stage; preserved for inspection.')
    if backend.stage=='prepared':backend.quiesce();backend.checkpoint('quiesced')
    if backend.stage=='quiesced':backend.stop();backend.checkpoint('stopped')
    if backend.stage=='stopped':backend.checkpoint('recovering')
    if backend.stage=='recovering':backend.recover();backend.checkpoint('publishing')
    if backend.stage=='publishing':backend.publish();backend.checkpoint('resuming')
    if backend.stage=='resuming':backend.resume();backend.checkpoint('complete')
    return {'schema_version':1,'status':'migrated','profile':getattr(backend,'after',{}).get('id')}


def shared_reference(profile):
    reference = host.shared_controller_reference() or profile.get('controller_app')
    if reference:
        return config.app_reference(reference)
    require('github_app' in profile, 'Choose the existing configured Studio controller before migrating another account.')
    path = config.paths(profile)['install']/'app.json'
    host.protected(path)
    value = json.loads(path.read_text(), object_pairs_hook=config._unique)
    require(value.get('client_id') == profile['github_app']['client_id'], 'Installed App metadata differs; preserve it.')
    return config.app_reference({'owner':profile['owner'], 'client_id':value['client_id'], 'slug':value.get('slug')})


class Native:
    def __init__(self,profile,source,*,shared=False):
        require(os.geteuid()==0,'Use the normal macOS administrator approval for migration.')
        host.require_no_image_upgrade(profile,allow_shared_migration=shared)
        self.paths=config.paths(profile);self.source=Path(source).resolve(strict=True)
        self.target=self.paths['state']/('shared-controller-migration.json' if shared else 'fleet-migration.json')
        host.protected(self.paths['state'],directory=True)
        self.contents={}
        for name in host.PAYLOAD:
            path=self.source/name;info=path.lstat()
            require(path.is_file() and not path.is_symlink() and info.st_nlink==1 and info.st_size<=2*1024*1024,
                    'Migration source must be the complete reviewed regular-file package.')
            self.contents[name]=path.read_bytes()
        self.receipt={n:hashlib.sha256(v).hexdigest() for n,v in self.contents.items()}
        if self.target.exists() or self.target.is_symlink():
            host.protected(self.target)
            require(self.target.stat().st_size<=131072,'Migration journal exceeds its bound.')
            self.plan=json.loads(self.target.read_text(),object_pairs_hook=config._unique)
            require(set(self.plan)==({'schema_version','before','after','baseline','before_receipt','after_receipt','token','stage'}
                    | ({'app_metadata'} if shared else set()))
                    and self.plan['schema_version']==1 and self.plan['stage'] in STAGES
                    and re.fullmatch(r'[a-f0-9]{32}',self.plan['token']), 'Migration journal is invalid; preserve it.')
            self.before,self.after=transition(self.plan['before'],self.plan['after'])
            require(profile in (self.before,self.after) and self.plan['after_receipt']==self.receipt,
                    'Resume the exact reviewed migration package; a different update is not permitted.')
        else:
            if shared:
                # Check both mirrors before adopting a key or publishing a
                # second transaction. Otherwise each migration owns a pause
                # that the other refuses to finish.
                for directory in (self.paths['state'],self.paths['install']):
                    marker=directory/'fleet-migration.json'
                    if marker.exists() or marker.is_symlink():
                        info=host.protected(marker)
                        require(info.st_nlink==1 and info.st_size<=131072,
                                'Existing fleet migration receipt is unsafe; preserve it.')
                        value=json.loads(marker.read_text(),object_pairs_hook=config._unique)
                        require(isinstance(value,dict) and value.get('stage')=='complete',
                                'Finish the existing fleet migration before starting shared controller migration.')
            for name in ('enrollment.json','maintenance.json'):
                require(not (self.paths['state']/name).exists() and not (self.paths['install']/name).exists(),
                        'Finish the existing enrollment/maintenance transaction before fleet migration.')
            self.before=config.validate(profile);self.after=propose(profile,fleet.host_id(),fleet.role())
            host.verify_install(profile)
            if shared:
                reference = shared_reference(profile)
                host.adopt_shared_controller(profile, reference)
                candidate = dict(self.after, controller_app=reference)
                candidate.pop('github_app', None)
                installation = auth.discover_installation(candidate, self.paths['state'], reference['client_id'])
                require(installation is not None,
                        'Install the existing shared controller App in this account before migrating; existing CI is unchanged.')
                self.after = config.validate(dict(candidate, github_app=installation))
                transition(self.before, self.after)
            baseline=self.read_json(self.paths['install']/'baseline-profile.json')
            old=self.read_json(self.paths['install']/'runtime.json')
            require(set(old) in (LEGACY,frozenset(host.PAYLOAD)),'Installed runtime has an unknown payload; no migration performed.')
            self.plan={'schema_version':1,'before':self.before,'after':self.after,'baseline':baseline,
                'before_receipt':old,'after_receipt':self.receipt,'token':uuid.uuid4().hex,'stage':'prepared'}
            if shared:
                metadata=self.read_json(self.paths['install']/'app.json')
                require(metadata.get('client_id')==self.before['github_app']['client_id'], 'Installed App metadata differs from the migration source.')
                reference=self.after['controller_app']
                self.plan['app_metadata']={'before':metadata,'after':{'client_id':reference['client_id'],'slug':reference['slug']}}
            if shared:self.stage_source()
            self.checkpoint('prepared')
        if shared:self.stage_source()
        require(self.after['fleet']['host_id']==fleet.host_id(),'This saved migration belongs to another physical Mac.')
        self.stage=self.plan['stage'];self.validate_bytes()
        if shared:self.checkpoint(self.stage)  # Repair a stale/missing public mirror from the validated private journal.
        # Verify the additional Actions-read grant before closing admission.
        replacement=auth.GitHubApp(self.after,self.paths['state']);replacement._refresh()
        self.api=auth.GitHubApp(self.before,self.paths['state']).api

    def stage_source(self):
        directory=self.paths['install']/'shared-controller-source'
        marker=self.paths['install']/self.target.name
        committed=self.target.exists() or self.target.is_symlink() or marker.exists() or marker.is_symlink()
        host.root_directory(directory)
        entries={path.name:path for path in directory.iterdir()}
        mismatch=bool(set(entries)-set(self.contents))
        for name,path in entries.items():
            info=host.protected(path)
            require(info.st_nlink==1 and info.st_size<=2*1024*1024, 'Shared migration staging contains an unsafe source file.')
            if name in self.receipt and hashlib.sha256(path.read_bytes()).hexdigest()!=self.receipt[name]:mismatch=True
        if mismatch:
            require(not committed, 'Shared migration snapshot differs; preserve it and resume its exact command.')
            # No transaction selected these bytes yet. Retain the abandoned
            # candidate rather than requiring manual cleanup after an update.
            os.rename(directory,directory.with_name(directory.name+'.uncommitted.'+uuid.uuid4().hex))
            host.root_directory(directory)
        for name,raw in self.contents.items():
            target=directory/name
            if target.exists() or target.is_symlink():
                info=host.protected(target)
                require(info.st_nlink==1 and hashlib.sha256(target.read_bytes()).hexdigest()==self.receipt[name],
                        'Shared migration snapshot differs; preserve it and resume its exact command.')
            else:
                require(not committed, 'A staged shared migration source file disappeared; preserve the transaction.')
                control.atomic_write(target,raw,mode=0o644)

    def read_json(self,path):
        info=host.protected(path);require(info.st_size<=131072,'Migration metadata exceeds its bound.')
        return json.loads(path.read_text(),object_pairs_hook=config._unique)

    def validate_bytes(self):
        old=self.plan['before_receipt']
        require(set(old) in (LEGACY,frozenset(host.PAYLOAD))
                and all(isinstance(v,str) and re.fullmatch(r'[a-f0-9]{64}',v) for v in old.values()),'Invalid installed source receipt.')
        require(self.read_json(self.paths['install']/'runtime.json') in (old,self.receipt),'Installed source receipt changed outside migration.')
        require(config.load(self.paths['profile']) in (self.before,self.after),'Installed profile changed outside migration.')
        if 'app_metadata' in self.plan:
            metadata=self.plan['app_metadata']
            require(isinstance(metadata,dict) and set(metadata)=={'before','after'}
                    and metadata['before'].get('client_id')==self.before['github_app']['client_id']
                    and metadata['after']=={'client_id':self.after['controller_app']['client_id'],'slug':self.after['controller_app']['slug']}
                    and self.read_json(self.paths['install']/'app.json') in (metadata['before'],metadata['after']),
                    'App metadata differs from both shared migration receipts; preserve it.')
        for name in host.PAYLOAD:
            target=self.paths['install']/name
            if not target.exists() and not target.is_symlink():
                require(name not in old,'An existing installed source file disappeared.');continue
            host.protected(target)
            require(hashlib.sha256(target.read_bytes()).hexdigest() in (old.get(name),self.receipt[name]),
                    'Installed source differs from both migration receipts; preserve it.')

    def checkpoint(self,stage):
        self.plan['stage']=stage;self.stage=stage
        public={'schema_version':1,'profile':self.plan['before']['id'],'stage':stage}
        if 'app_metadata' in self.plan:
            public.update(before=self.before,after=self.after,source_receipt=self.receipt)
        marker=self.paths['install']/self.target.name
        if 'app_metadata' in self.plan and not self.target.exists():
            # Publish the mutation exclusion before the first private checkpoint;
            # a failed private write must not leave an invisible transaction.
            if marker.exists() or marker.is_symlink():
                previous=self.read_json(marker)
                require(previous==public, 'An unmatched public shared migration intent exists; preserve it.')
            else:
                control.atomic_write(marker,json.dumps(public).encode(),mode=0o644)
        control.atomic_write(self.target,(json.dumps(self.plan,sort_keys=True)+'\n').encode(),mode=0o600)
        control.atomic_write(marker,json.dumps(public).encode(),mode=0o644)

    def runtime(self):
        from pool_runtime import Runtime
        return Runtime(self.before,self.paths['state'],self.api,host.Worker(self.before),
            storage_uid=0,health=lambda _:None)

    def quiesce(self):
        # A private owned pause is resumable; a manually drained pool stays paused.
        drain=self.paths['state']/'drain';token=self.plan['token']+'\n'
        if drain.exists() or drain.is_symlink():
            host.protected(drain);require(drain.read_text()==token,'This admission pause belongs to another operation.')
        else:
            with control.file_lock(self.paths['state'].parent/'.resources.lock'):
                control.atomic_write(drain,token.encode(),mode=0o600)
        status=host.inspect_service(self.before)
        if status['loaded']:
            require(status['fresh'] and set(status['pools'])==set(self.before['pools'])
                and all(v['state'] not in ('busy','creating','preparing','starting','cleanup-required') for v in status['pools'].values()),
                'Existing jobs or preparation are active. They were preserved; rerun migration when they finish.')
        records=host._repair_slot_records(self.before);runtime=self.runtime()
        inspected=policy.inspect(self.before,self.api,strict_selectors=False)
        for platform,group in inspected['groups'].items():
            require(isinstance(group,dict),'An expected runner group is missing; migration stopped.')
            rows=policy.pool_runners(self.before,self.api,platform,group['id'])
            known={r['name'] for r in records if r['state']!='idle' and r['platform']==platform}
            # Other Macs may share the group. Preserve recognized foreign hosts.
            for row in rows:
                parsed=fleet.parse_runner(row.get('name'),self.before['id'],platform)
                require(parsed is not None,'Unrecognized runner shares this pool; preserve it and reconcile enrollment.')
                if parsed['host_id'] not in (None,self.after['fleet']['host_id']):continue
                require(row.get('busy') is False and row.get('name') in known,'A runner is busy or unjournaled; its job was preserved.')
        for record in records:
            if record['state']!='idle':runtime._unregister_idle(record)

    def stop(self):
        label=host.service_spec(self.before)['Label']
        state=host.native(['/bin/launchctl','print','system/'+label],'Inspect controller for migration',allowed=(0,113))
        if state.returncode==0:host.native(['/bin/launchctl','bootout','system/'+label],'Stop idle controller for migration')
        deadline=time.monotonic()+30
        while host.native(['/bin/launchctl','print','system/'+label],'Confirm controller stopped',allowed=(0,113)).returncode!=113:
            require(time.monotonic()<deadline,'Controller shutdown is not confirmed; source remains unchanged.');time.sleep(1)

    def recover(self):
        with ExitStack() as stack:
            stack.enter_context(control.file_lock(self.paths['state']/'controller.lock'))
            for platform in sorted(self.before['pools']):stack.enter_context(control.file_lock(self.paths['state']/(platform+'.lock')))
            processes=host.native(['/bin/ps','-axo','pid=,command='],'Verify old workers exited')
            require(not re.search(re.escape(str(self.paths['install']/'runner_pool.py'))+r'\s+worker\b',processes.stdout),
                    'An old worker is still running; its environment was preserved.')
            runtime=self.runtime()
            for platform in self.before['pools']:
                require(runtime._recover(platform).get('state')=='idle','Guest cleanup remains uncertain; no source published.')
            host._idle_repair_slots(self.before)

    def publish(self):
        config.preflight_disk(self.before)
        self.validate_bytes()
        with control.file_lock(self.paths['state']/'controller.lock'):
            host._idle_repair_slots(self.before)
            backup=self.paths['state']/'fleet-runtime-backup';host.root_directory(backup,0o700)
            for name in self.plan['before_receipt']:
                saved=backup/name
                if not saved.exists():control.atomic_write(saved,(self.paths['install']/name).read_bytes(),mode=0o600)
            for name,raw in self.contents.items():control.atomic_write(self.paths['install']/name,raw,mode=0o644)
            baseline=dict(self.plan['baseline'],fleet=self.after['fleet'])
            if 'app_metadata' in self.plan:
                control.atomic_write(self.paths['install']/'app.json', json.dumps(self.plan['app_metadata']['after'],sort_keys=True).encode(),mode=0o644)
            for target,value in ((self.paths['install']/'baseline-profile.json',baseline),
                                 (self.paths['profile'],self.after),(self.paths['install']/'runtime.json',self.receipt)):
                control.atomic_write(target,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode(),mode=0o644)
            host.verify_install(self.after)

    def resume(self):
        host.verify_install(self.after)
        drain=self.paths['state']/'drain'
        if drain.exists() or drain.is_symlink():
            host.protected(drain);require(drain.read_text()==self.plan['token']+'\n','Admission pause ownership changed.');drain.unlink()
        if 'app_metadata' in self.plan:
            host.activate(self.after,migration_token=self.plan['token'])
        else:
            host.activate(self.after)


def arguments(argv=None, *, private=False):
    from runner_console import ArgumentParser
    parser_class=argparse.ArgumentParser if private else ArgumentParser
    parser=parser_class(description=__doc__)
    parser.add_argument('--profile',required=True,type=Path);parser.add_argument('--native',action='store_true')
    parser.add_argument('--shared-app',action='store_true');parser.add_argument('--json',action='store_true')
    return parser.parse_args(argv)


def execute(argv=None):
    """Preview only; the operator owns native authorization and migration execution."""
    from runner_console import Outcome
    args=arguments(argv)
    try:
        require(not args.native,'Native migration uses its dedicated private transport.')
        profile=config.load(args.profile)
        command='hypertext runners migrate --org '+profile['owner']['login']+(' --shared-app' if args.shared_app else '')+' --apply'
        if args.shared_app:
            result={'schema_version':1,'status':'approval_required','profile':profile['id'],
                'controller_app':shared_reference(profile),'preserves':['active_jobs','old_credentials','repositories','images','resource_limits'],
                'command':command}
        else:
            result={'schema_version':1,'status':'approval_required','profile':profile['id'],
                'after':propose(profile,fleet.host_id(),fleet.role()),'command':command}
        return Outcome('approval_required','Runner migration is ready for review.',
                       'Active jobs, credentials, repository access, images and resource limits are preserved.',
                       next_action=command,payload=result,code=1)
    except (Failure,control.StateError,OSError,ValueError,KeyError,TypeError):
        return Outcome('blocked','Migration needs attention; existing state is preserved.',
                       'Review the installed profile and resume the exact migration package.',code=2)


def private_main(argv=None):
    """Privileged transport, independent of the public terminal renderer."""
    args=arguments(argv,private=True)
    code=0
    try:
        with redirect_stdout(sys.stderr):
            require(args.native,'Native migration requires its private invocation.')
            profile=config.load(args.profile)
            with host.setup_lock(profile):result=advance(Native(profile,HERE,shared=args.shared_app))
    except (Failure,control.StateError,OSError,ValueError,KeyError,TypeError):
        result={'schema_version':1,'status':'blocked','reason':'Migration interrupted; resume the exact package. Existing jobs, keys and journals are preserved.'}
        code=2
    print(json.dumps(result))
    return code


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if '--native' in argv:return private_main(argv)
    import runner_operator
    return runner_operator.main(['migrate',*argv])


if __name__=='__main__':raise SystemExit(main())
