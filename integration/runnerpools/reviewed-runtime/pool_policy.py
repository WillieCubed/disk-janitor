"""Exact organization runner group admission and conservative workflow inspection."""
import base64
import copy
import re
from urllib.parse import quote
from runner_routing import parse_selector

from pool_config import Failure, consumer_events, consumer_tag_prefix, group_name, labels, require, validate

GUARD = "github.ref=='refs/heads/main'&&(github.event_name=='push'||github.event_name=='workflow_dispatch')"
LOCAL_RECOVERY_SOURCE_GUARD = (
    "github.run_attempt==1&&github.event_name=='workflow_run'&&github.event.action=='completed'&&"
    "github.event.workflow_run.head_branch=='main'&&"
    "github.event.workflow_run.head_repository.id==github.event.repository.id&&"
    "github.event.workflow_run.run_attempt==1&&github.event.workflow_run.conclusion=='failure'&&"
    "(github.event.workflow_run.event=='push'||github.event.workflow_run.event=='workflow_dispatch'||"
    "github.event.workflow_run.event=='schedule')")


def literal_name(value):
    match = re.fullmatch(r"(?:'([A-Za-z0-9_.-]+)'|\"([A-Za-z0-9_.-]+)\"|([A-Za-z0-9_.-]+))", value)
    require(match is not None, 'Runner selectors require literal names; unsupported YAML must be reviewed.')
    return next(part for part in match.groups() if part is not None)


def workflow_jobs(source):
    """Classify every job in the supported literal YAML subset, never skip a selector."""
    lines = source.splitlines()
    starts = [index for index, line in enumerate(lines) if re.match(r'^jobs:', line)]
    require(len(starts) == 1 and lines[starts[0]].rstrip() == 'jobs:',
            'Main workflow needs exactly one canonical jobs mapping.')
    # Multiline quoted/flow top-level values can contain text resembling jobs.
    # They are outside this deliberately small parser rather than safe to ignore.
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith('#') or line.startswith(' '):
            continue
        if index == 0 and line == '---':
            continue
        top = re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*: *(.*)', line)
        require(top is not None, 'Top-level workflow keys must be literal; quoted keys and YAML merges require review.')
        if top:
            value = top.group(1).strip()
            require(not value or value[0] not in "'\"[{" or
                    (value[0] in "'\"" and len(value) > 1 and value[-1] == value[0]) or
                    (value[0] == '[' and value.endswith(']')) or
                    (value[0] == '{' and value.endswith('}')),
                    'Multiline quoted/flow workflow values require manual YAML review.')
    jobs = []
    current = None
    for line in lines[starts[0] + 1:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not line.startswith(' '):
            break
        require('\t' not in line[:len(line) - len(line.lstrip())], 'Tabs in workflow indentation are unsupported.')
        if not line.startswith('   '):
            match = re.fullmatch(r'  ([A-Za-z_][A-Za-z0-9_-]*): *', line)
            require(match is not None and all(job['name'] != match.group(1) for job in jobs),
                    'Every job must have a unique literal block mapping; aliases, merges and flow jobs require review.')
            current = {'name': match.group(1), 'lines': []}
            jobs.append(current)
        else:
            require(current is not None and line.startswith('    '), 'Unsupported jobs mapping indentation.')
            current['lines'].append(line)
    require(bool(jobs), 'Main workflow has no canonical jobs.')
    for job in jobs:
        fields = {}
        field = None
        for line in job['lines']:
            if not line.startswith('     '):
                match = re.fullmatch(r'    ([A-Za-z_][A-Za-z0-9_-]*): *(.*)', line)
                require(match is not None and match.group(1) not in fields,
                        'Job fields must be unique literal keys; quoted keys, aliases and merges require review.')
                field = match.group(1)
                fields[field] = [match.group(2), []]
            else:
                require(field is not None and line.startswith('      '), 'Unsupported job field indentation.')
                fields[field][1].append(line)
        require('runs-on' in fields, 'Every job requires an explicit supported runner selector; reusable jobs require review.')
        value, nested = fields['runs-on']
        job['fields'] = fields
        if value:
            routed = parse_selector(value)
            if routed is not None:
                require(not nested, 'Routed runner selector cannot contain nested overrides.')
                job.update(routed)
                continue
            label = literal_name(value)
            require(not nested and re.fullmatch(r'(?:ubuntu|macos|windows)-(?:latest|[0-9]+(?:\.[0-9]+)*(?:-(?:arm|arm64|intel|large|xlarge))?)', label),
                    'Only literal GitHub-hosted labels or canonical self-hosted group mappings are supported.')
            job['group'] = None
            continue
        require(len(nested) == 2 and re.fullmatch(r'      group: +.+', nested[0]) and nested[1].startswith('      labels:'),
                'Self-hosted jobs require the canonical group followed by inline literal labels; unsupported YAML must be reviewed.')
        group = literal_name(nested[0][len('      group:'):].strip())
        match = re.fullmatch(r'      labels: *\[([^\[\]]+)\] *', nested[1])
        require(match is not None, 'Self-hosted jobs require inline literal labels; expressions and block lists require review.')
        labels = [literal_name(value.strip()) for value in match.group(1).split(',')]
        require(len(labels) == len(set(labels)) and 'self-hosted' in labels,
                'Self-hosted labels must be unique and include self-hosted.')
        job.update(group=group, labels=set(labels))
    return jobs


def workflow_ref(consumer):
    return consumer['repo'] + '/' + consumer['workflow'] + '@refs/heads/main'


def guard_terms(consumer):
    """The literal trusted-event boundary every self-hosted job must start with.

    Pull requests, pull_request_target and workflow_run events from forks share
    the base repository name and can even report the base main ref, so only the
    exact event names below admit a job. Tag releases replace the main ref with
    one reviewed literal tag prefix for both the ref and the workflow ref.
    """
    events = consumer_events(consumer)
    prefix = consumer_tag_prefix(consumer)
    trigger = "(github.event_name == '" + events[0] + "' || github.event_name == '" + events[1] + "')"
    if prefix is not None:
        tag = 'refs/tags/' + prefix
        return ["github.repository == '" + consumer['repo'] + "'", "startsWith(github.ref, '" + tag + "')", trigger,
                "startsWith(github.workflow_ref, '" + consumer['repo'] + '/' + consumer['workflow'] + '@' + tag + "')"]
    terms = ["github.repository == '" + consumer['repo'] + "'", "github.ref == 'refs/heads/main'", trigger,
             "github.workflow_ref == '" + workflow_ref(consumer) + "'"]
    if events == ['workflow_run', 'workflow_dispatch']:
        terms.append(LOCAL_RECOVERY_SOURCE_GUARD)
    return terms


def guard(consumer):
    return ' && '.join(guard_terms(consumer))


def _literal_pattern(expression):
    # Escape every literal in the complete boundary. Whitespace is allowed only
    # around its operators and argument separators.
    parts = (part.strip() for part in re.split(r'(==|&&|\|\||[(),])', expression))
    return r'\s*'.join(re.escape(part) for part in parts if part)


def validate_workflow(source, consumer, profile, *, strict_selectors=True):
    p = validate(profile)
    require(consumer in p['consumers'], 'Workflow consumer is not enrolled in this profile.')
    require(isinstance(source, str), 'Workflow source must be UTF-8 text.')
    # The optional final conjunction can only narrow the boundary.
    base = _literal_pattern(guard(consumer))
    allowed = r'\s*' + base + r"(?:\s*&&\s*vars\.[A-Z][A-Z0-9_]*\s*==\s*'true')?\s*"
    selected = []
    groups = {group_name(p, platform): platform for platform in consumer['pools']}
    for job in workflow_jobs(source):
        if job['group'] is None:
            continue
        require(bool(job.get('repository_scoped')) == (p['owner']['type'] == 'User'),
                'Runner selector scope must match the reviewed account admission boundary.')
        condition = job['fields'].get('if', ['', []])
        match = re.fullmatch(r'\$\{\{(.*?)\}\} *', condition[0])
        require(not condition[1] and match is not None and re.fullmatch(allowed, match.group(1)) is not None,
                'Every self-hosted job requires the canonical literal repository, main or reviewed tag, configured events and workflow-ref guard.')
        if strict_selectors:
            require(job['group'] in groups, 'Self-hosted job selects an unreviewed pool group.')
            platform = groups[job['group']]
            require(job['labels'] == set(labels(p, platform)), 'Self-hosted job must select the exact configured pool labels.')
        selected.append(job)
    require(bool(selected), 'Main workflow must contain an explicitly guarded self-hosted job.')


def _pages(api, path, key):
    """Compare complete lists; inconsistent totals or repeated pages fail closed."""
    result = []
    total = None
    for page in range(1, 10001):
        response = api('GET', path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        require(isinstance(response, dict) and type(response.get('total_count')) is int
                and response['total_count'] >= 0 and isinstance(response.get(key), list),
                'GitHub returned an unsupported paginated policy response.')
        require(total is None or total == response['total_count'], 'GitHub policy changed during pagination; inspect again.')
        total = response['total_count']
        items = response[key]
        require(all(isinstance(item, dict) for item in items), 'GitHub policy list contains malformed entries.')
        result.extend(items)
        require(len(result) <= total, 'GitHub policy pagination exceeds its declared total.')
        if len(result) == total:
            return result
        require(bool(items), 'GitHub policy pagination is incomplete.')
    raise Failure('GitHub policy pagination exceeds the supported bound.')


def _positive_id(value):
    return type(value) is int and value > 0


def _repo(repo, consumer, profile):
    require(isinstance(repo, dict), 'Repository metadata must be an object.')
    owner = repo.get('owner')
    expected = profile['owner']
    require(isinstance(owner, dict) and owner.get('login') == expected['login']
            and type(owner.get('id')) is int and owner['id'] == expected['id']
            and owner.get('type') == expected['type'], 'Repository owner identity does not match the profile.')
    require(type(repo.get('id')) is int and repo['id'] == consumer['id'] and repo.get('full_name') == consumer['repo'],
            'Repository immutable identity does not match the profile.')
    require(repo.get('private') is (consumer.get('visibility','private')=='private') and repo.get('fork') is False and repo.get('archived') is False
            and repo.get('default_branch') == 'main', 'Consumers must match their explicit visibility and be active nonfork repositories with default branch main.')


def _expected(profile, platform):
    consumers = [c for c in profile['consumers'] if platform in c['pools']]
    return dict(name=group_name(profile, platform), visibility='selected', allows_public_repositories=any(c.get('visibility')=='public' for c in consumers),
                restricted_to_workflows=True, selected_repository_ids=sorted({c['id'] for c in consumers}),
                selected_workflows=sorted(workflow_ref(c) for c in consumers))


def _group(group, repositories, expected):
    require(isinstance(group, dict) and _positive_id(group.get('id')) and group.get('name') == expected['name'],
            'Runner group identity does not match the requested pool.')
    require(group.get('visibility') == 'selected' and group.get('allows_public_repositories') is expected['allows_public_repositories']
            and group.get('default') is False and group.get('inherited') is False,
            'Runner group must be organization-owned, nondefault, selected-only with exactly the reviewed public-access policy.')
    workflows = group.get('selected_workflows')
    require(group.get('restricted_to_workflows') is True and isinstance(workflows, list)
            and all(isinstance(item, str) for item in workflows)
            and len(workflows) == len(set(workflows)) and set(workflows) == set(expected['selected_workflows']),
            'Runner group workflow allowlist differs from the complete expected main workflow refs.')
    ids = [repo.get('id') for repo in repositories]
    require(all(_positive_id(value) for value in ids) and len(ids) == len(set(ids))
            and set(ids) == set(expected['selected_repository_ids']),
            'Runner group repository allowlist differs from the complete expected immutable repository IDs.')


def _identity_sources(profile, api, workflows=True, *, strict_selectors=True):
    p = validate(profile)
    owner = api('GET', owner_path(p))
    require(isinstance(owner, dict) and all(owner.get(key) == p['owner'][key] for key in ('login', 'id', 'type'))
            and type(owner.get('id')) is int, 'GitHub organization immutable identity does not match the profile.')
    repositories = {}
    for consumer in p['consumers']:
        repo = api('GET', 'repos/' + consumer['repo'])
        _repo(repo, consumer, p)
        repositories[consumer['repo']] = repo
        if workflows:
            validate_workflow(_workflow_source(consumer, api), consumer, p, strict_selectors=strict_selectors)
    return dict(owner=owner, repositories=repositories)


def owner_path(profile):
    p=validate(profile)
    return ('users/' if p['owner']['type']=='User' else 'orgs/')+p['owner']['login']


def _workflow_source(consumer, api):
    response = api('GET', 'repos/' + consumer['repo'] + '/contents/' + consumer['workflow'] + '?ref=main')
    try:
        require(isinstance(response, dict) and response.get('encoding') == 'base64', 'Unsupported workflow content encoding.')
        return base64.b64decode(''.join(response['content'].split()), validate=True).decode('utf-8')
    except (KeyError, ValueError, UnicodeError, TypeError, AttributeError):
        raise Failure('Cannot read committed main workflow source.') from None


def _groups(p, api, proposed=None):
    if p['owner']['type'] == 'User':
        # These are local routing identities, never fabricated GitHub groups.
        return dict(groups={platform:dict(id=next(c['id'] for c in p['consumers'] if platform in c['pools']),
            name=group_name(p,platform),scope='repository') for platform in p['pools']},missing=[])
    owner_path = 'orgs/' + quote(p['owner']['login'], safe='')
    root = owner_path + '/actions/runner-groups'
    server_groups = _pages(api, root, 'runner_groups')
    require(all(_positive_id(group.get('id')) and isinstance(group.get('name'), str) for group in server_groups),
            'GitHub returned invalid runner group identities.')
    require(len({g['id'] for g in server_groups}) == len(server_groups), 'GitHub returned duplicate runner group identities.')
    groups, missing = {}, []
    for platform in p['pools']:
        expected = _expected(p, platform)
        matches = [g for g in server_groups if g['name'].lower() == expected['name'].lower()]
        require(all(g['name'] == expected['name'] for g in matches), 'Runner group name collides with another capitalization.')
        require(len(matches) <= 1, 'Multiple runner groups collide with the configured pool name.')
        if not matches:
            missing.append(platform)
            groups[platform] = None
            continue
        group = api('GET', root + '/' + str(matches[0]['id']))
        require(isinstance(group, dict) and group.get('id') == matches[0]['id'], 'Runner group detail identity changed.')
        selected = _pages(api, root + '/' + str(group['id']) + '/repositories', 'repositories')
        if proposed is None:
            _group(group, selected, expected)
        else:
            _enrollment_group(group, selected, expected, _expected(proposed, platform))
        groups[platform] = group
    return dict(groups=groups, missing=missing)


def inspect(profile, api, workflows=True, *, strict_selectors=True):
    p = validate(profile)
    result = _identity_sources(p, api, workflows, strict_selectors=strict_selectors)
    result.update(_groups(p, api))
    return result


def runner_root(profile, repository_id=None):
    """Resolve a journal identity through reviewed immutable repository policy."""
    p = validate(profile)
    if p['owner']['type'] == 'Organization':
        return 'orgs/' + p['owner']['login'] + '/actions/runners'
    matches = {c['repo'] for c in p['consumers'] if type(repository_id) is int and c['id'] == repository_id}
    require(len(matches) == 1, 'Saved personal runner repository is not enrolled; preserve its generation.')
    return 'repos/' + matches.pop() + '/actions/runners'


def pool_runners(profile,api,platform,group_id):
    p=validate(profile)
    require(platform in p['pools'],'Unknown runner platform.')
    if p['owner']['type']=='Organization':
        return _pages(api,'orgs/'+p['owner']['login']+'/actions/runner-groups/'+str(group_id)+'/runners','runners')
    ids=sorted({c['id'] for c in p['consumers'] if platform in c['pools']})
    prefix=p['id']+'-'+platform+'-'
    return [row for identity in ids for row in _pages(api,runner_root(p,identity),'runners')
            if isinstance(row.get('name'),str) and row['name'].startswith(prefix)]


def reconcile(profile, api, apply=False):
    p = validate(profile)
    result = inspect(p, api, strict_selectors=False)
    result['planned'] = {platform: _expected(p, platform) for platform in result['missing']}
    result['created'] = []
    if apply:
        root = 'orgs/' + quote(p['owner']['login'], safe='') + '/actions/runner-groups'
        for platform, payload in result['planned'].items():
            group = api('POST', root, payload)
            require(isinstance(group, dict) and _positive_id(group.get('id')), 'GitHub did not confirm new runner group identity.')
            # Read back server policy after every write rather than trusting a request receipt.
            saved = api('GET', root + '/' + str(group['id']))
            require(isinstance(saved, dict) and saved.get('id') == group['id'], 'Created runner group identity mismatch.')
            selected = _pages(api, root + '/' + str(group['id']) + '/repositories', 'repositories')
            _group(saved, selected, payload)
            result['groups'][platform] = saved
            result['created'].append(platform)
        result['missing'] = []
    return result


def _extension(current, proposed):
    """Validate the complete proposal; enrollment can only extend consumer access."""
    old, new = validate(current), validate(proposed)
    require({k: v for k, v in old.items() if k != 'consumers'} ==
            {k: v for k, v in new.items() if k != 'consumers'},
            'Enrollment cannot change owner, pool resources, credentials or other profile policy.')
    require(len(new['consumers']) >= len(old['consumers']), 'Enrollment cannot remove consumers.')
    for before, after in zip(old['consumers'], new['consumers']):
        require(all(before[k] == after[k] for k in ('repo', 'id', 'workflow'))
                and consumer_events(before) == consumer_events(after) and before.get('visibility','private') == after.get('visibility','private')
                and before.get('credentials') == after.get('credentials') and before.get('tag_prefix') == after.get('tag_prefix')
                and set(before['pools']) <= set(after['pools']),
                'Enrollment can only append consumers or add platforms to an unchanged consumer identity/workflow.')
    return old, new


def _changes(old, new):
    result = {}
    for platform in old['pools']:
        before, after = _expected(old, platform), _expected(new, platform)
        if before != after:
            result[platform] = dict(before=before, after=after)
    return result


def plan_enrollment(profile, repo, workflow, platforms, api, *, events=None, credentials=False, tag_prefix=None):
    """Read-only proposal; source changes must already exist on committed main."""
    current = validate(profile)
    inspected = inspect(current, api, strict_selectors=False)
    require(not inspected['missing'], 'Provision exact pool groups before enrolling consumers.')
    require(isinstance(repo, str) and re.fullmatch(re.escape(current['owner']['login']) +
            r'/[A-Za-z0-9_.-]+', repo) is not None and repo.rsplit('/',1)[-1] not in ('.','..'),
            'Enrollment repository must belong to the exact profile organization.')
    require(isinstance(workflow, str) and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_][A-Za-z0-9_.-]*\.ya?ml', workflow)
            is not None and '..' not in workflow, 'Enrollment workflow must be a direct literal workflow YAML path.')
    require(isinstance(platforms, (list, tuple)) and bool(platforms) and all(isinstance(v, str) for v in platforms)
            and len(platforms) == len(set(platforms)) and set(platforms) <= set(current['pools']),
            'Enrollment platforms must be unique configured pool names.')
    actual = api('GET', 'repos/' + repo)
    require(isinstance(actual, dict) and _positive_id(actual.get('id')), 'GitHub did not return a valid immutable repository ID.')
    proposed = copy.deepcopy(current)
    requested_events = consumer_events({} if events is None else {'events': events})
    existing = next((c for c in proposed['consumers'] if (c['repo'], c['workflow']) == (repo, workflow)), None)
    if existing:
        require(existing['id'] == actual['id'] and consumer_events(existing) == requested_events
                and bool(existing.get('credentials')) == bool(credentials) and existing.get('tag_prefix') == tag_prefix,
                'Existing enrollment immutable ID, workflow, events, credential review and tag policy must match; only platforms can be added.')
        existing['pools'] = [p for p in proposed['pools'] if p in set(existing['pools']) | set(platforms)]
        consumer = existing
    else:
        consumer = dict(repo=repo, id=actual['id'], workflow=workflow, pools=list(platforms))
        if actual.get('private') is False:consumer['visibility']='public'
        if events is not None:
            consumer['events'] = list(requested_events)
        if credentials:
            consumer['credentials'] = True
        if tag_prefix is not None:
            consumer['tag_prefix'] = tag_prefix
        proposed['consumers'].append(consumer)
    proposed = validate(proposed)
    _repo(actual, consumer, proposed)
    validate_workflow(_workflow_source(consumer, api), consumer, proposed, strict_selectors=False)
    _extension(current, proposed)
    return dict(profile=proposed, changes=_changes(current, proposed))


def _enrollment_group(group, repositories, before, after):
    """Allow resumable old/new dimensions only; every group boundary stays exact."""
    workflows = group.get('selected_workflows') if isinstance(group, dict) else None
    ids = [r.get('id') for r in repositories]
    require(isinstance(workflows, list) and all(isinstance(v, str) for v in workflows)
            and all(_positive_id(v) for v in ids), 'Malformed enrollment policy state.')
    require(any(sorted(workflows) == expected['selected_workflows'] for expected in (before, after))
            and any(sorted(ids) == expected['selected_repository_ids'] for expected in (before, after)),
            'Enrollment server state differs from both exact old and proposed policy; preserve the drained state.')
    require(type(group.get('allows_public_repositories')) is bool and group.get('allows_public_repositories') in (before['allows_public_repositories'],after['allows_public_repositories']), 'Enrollment public access differs from both reviewed policies.')
    mixed = dict(before, selected_workflows=workflows, selected_repository_ids=ids, allows_public_repositories=group.get('allows_public_repositories'))
    _group(group, repositories, mixed)


def apply_enrollment(current, new, api):
    """Apply only consumer extensions. Caller must first drain and establish idle pools.

    Keep that state until the caller installs the verified profile and reconciles App
    access. A failed write preserves provider state for an explicit same-plan resume;
    it never broadens unrelated policy or attempts an automatic rollback.
    """
    old, proposed = _extension(current, new)
    _identity_sources(old, api, strict_selectors=False)
    original = _groups(old, api, proposed)
    require(not original['missing'], 'Enrollment requires existing exact profile groups.')
    # Verify all new immutable identities and committed sources before the first write.
    _identity_sources(proposed, api, strict_selectors=False)
    changes = _changes(old, proposed)
    if old['owner']['type']=='User':
        result=inspect(proposed,api,strict_selectors=False)
        result.update(profile=proposed,changes=changes)
        return result
    root = 'orgs/' + quote(old['owner']['login'], safe='') + '/actions/runner-groups'
    for platform, change in changes.items():
        group_id = original['groups'][platform]['id']
        path = root + '/' + str(group_id)
        group = api('GET', path)
        require(isinstance(group, dict) and group.get('id') == group_id, 'Enrollment group identity changed.')
        repositories = _pages(api, path + '/repositories', 'repositories')
        _enrollment_group(group, repositories, change['before'], change['after'])
        after = change['after']
        patch = dict(name=after['name'])
        if sorted(group['selected_workflows']) != after['selected_workflows']:
            patch['selected_workflows'] = after['selected_workflows']
        if group['allows_public_repositories'] is not after['allows_public_repositories']:
            patch['allows_public_repositories'] = after['allows_public_repositories']
        if len(patch) > 1:
            api('PATCH', path, patch)
        if sorted(repo['id'] for repo in repositories) != after['selected_repository_ids']:
            api('PUT', path + '/repositories', dict(selected_repository_ids=after['selected_repository_ids']))
        saved = api('GET', path)
        require(isinstance(saved, dict) and saved.get('id') == group_id, 'Enrollment readback group identity changed.')
        selected = _pages(api, path + '/repositories', 'repositories')
        _group(saved, selected, after)
    result = inspect(proposed, api, strict_selectors=False)
    require(not result['missing'], 'Enrollment final verification found a missing pool group.')
    result.update(profile=proposed, changes=changes)
    return result
