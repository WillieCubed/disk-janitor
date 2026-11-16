"""Serialized, journaled creation of one organization's locked native account."""

import json
import ctypes
import errno
import math
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import threading
from types import SimpleNamespace
import uuid
from xml.parsers.expat import ExpatError

import macos_host
from pool_config import Failure, paths, require, username, validate
import pool_config as config
import process_control as control

_ALLOCATION_MUTEX = threading.Lock()


def _administrator():
    require(
        os.geteuid() == 0,
        "Native account allocation requires the normal administrator handoff.",
    )


def _metadata(path):
    return Path(path).lstat()


def _open_directory(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _fd_info(fd):
    return os.fstat(fd)


def _volume_uuid(fd):
    """Read Darwin's persistent volume UUID from the already opened directory."""

    class Attributes(ctypes.Structure):
        _fields_ = [
            ("bitmapcount", ctypes.c_ushort),
            ("reserved", ctypes.c_ushort),
            ("commonattr", ctypes.c_uint32),
            ("volattr", ctypes.c_uint32),
            ("dirattr", ctypes.c_uint32),
            ("fileattr", ctypes.c_uint32),
            ("forkattr", ctypes.c_uint32),
        ]

    # SDK sys/attr.h: ATTR_VOL_INFO | ATTR_VOL_UUID; result is uint32 + uuid_t.
    attributes = Attributes(5, 0, 0, 0x80040000, 0, 0, 0)
    buffer = ctypes.create_string_buffer(20)
    try:
        function = ctypes.CDLL(
            "/usr/lib/libSystem.B.dylib", use_errno=True
        ).fgetattrlist
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(fd, ctypes.byref(attributes), buffer, len(buffer), 0)
    except (AttributeError, OSError):
        raise Failure(
            "Persistent account volume identity is unavailable; preserve the account."
        ) from None
    require(
        result == 0,
        "Persistent account volume identity is unavailable (OS error "
        + str(ctypes.get_errno())
        + "); preserve the account.",
    )
    length = int.from_bytes(buffer.raw[:4], "little")
    value = uuid.UUID(bytes=buffer.raw[4:])
    require(
        length == 20 and value.int != 0,
        "Persistent account volume identity is malformed; preserve the account.",
    )
    return str(value).upper()


def _assign(fd, uid, gid):
    os.fchown(fd, uid, gid)


def _protected_directory(path):
    info = _metadata(path)
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
        "Account allocation requires protected root-owned native directories.",
    )


def _native(argv, context, **kwargs):
    try:
        return macos_host.native(argv, context, **kwargs)
    except macos_host.Failure as error:
        raise Failure(str(error)) from None


def _dscl(verb, path, *args):
    return _native(
        ["/usr/bin/dscl", ".", verb, path, *args], "Native pool account " + verb
    )[0]


def _inventory():
    names, numbers = {}, {}
    for kind in ("Users", "Groups"):
        rows = [
            line.strip()
            for line in _dscl("-list", "/" + kind).splitlines()
            if line.strip()
        ]
        require(
            len(rows) == len(set(rows))
            and len(rows) == len({name.lower() for name in rows}),
            "Directory Services contains ambiguous record names.",
        )
        names[kind] = set(rows)
    for kind, field in (
        ("Users", "UniqueID"),
        ("Users", "PrimaryGroupID"),
        ("Groups", "PrimaryGroupID"),
    ):
        values = {}
        for line in _dscl("-list", "/" + kind, field).splitlines():
            line = line.strip()
            if not line or line in names[kind]:
                continue  # Partial records can legitimately lack this attribute.
            parts = line.rsplit(None, 1)
            require(
                len(parts) == 2
                and parts[0] in names[kind]
                and re.fullmatch(r"-?[0-9]+", parts[1])
                and parts[0] not in values,
                "Native account numeric inventory is malformed.",
            )
            values[parts[0]] = int(parts[1])
        numbers[kind, field] = values
    return names, numbers


def _validate_intent(value, profile_id, home_parent):
    fields = {
        "schema_version",
        "profile_id",
        "owner",
        "user",
        "uid",
        "gid",
        "user_uuid",
        "group_uuid",
        "home",
        "stage",
        "home_inode",
        "state",
    }
    require(
        isinstance(value, dict)
        and set(value) == fields
        and type(value["schema_version"]) is int
        and value["schema_version"] in (1, 2)
        and value["profile_id"] == profile_id
        and re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", profile_id)
        and len(profile_id) <= 20,
        "Account intent identity is invalid; preserve it and inspect.",
    )
    owner = value["owner"]
    require(
        isinstance(owner, dict)
        and set(owner) == {"login", "id", "type"}
        and owner["type"] in ("Organization", "User")
        and type(owner["id"]) is int
        and owner["id"] > 0
        and isinstance(owner["login"], str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", owner["login"]),
        "Account intent owner is invalid.",
    )
    require(
        value["user"] == "ci-pools-" + profile_id
        and type(value["uid"]) is int
        and 550 <= value["uid"] <= 999
        and value["gid"] == value["uid"]
        and type(value["gid"]) is int,
        "Account intent UID/GID or username is invalid.",
    )
    for key in ("user_uuid", "group_uuid"):
        require(
            isinstance(value[key], str)
            and re.fullmatch(
                r"[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}", value[key]
            ),
            "Account intent generated identity is invalid.",
        )
    require(
        value["home"] == str(home_parent / value["user"])
        and isinstance(value["stage"], str)
        and Path(value["stage"]).parent == home_parent
        and re.fullmatch(
            r"\.runner-pools-home-" + re.escape(profile_id) + r"-[a-f0-9]{32}",
            Path(value["stage"]).name,
        ),
        "Account home intent is outside its exact native namespace.",
    )
    inode = value["home_inode"]
    inode_fields = {"dev", "ino"} | (
        {"volume_uuid"} if value["schema_version"] == 2 else set()
    )
    require(
        inode is None
        or isinstance(inode, dict)
        and set(inode) == inode_fields
        and type(inode["dev"]) is int
        and inode["dev"] >= 0
        and type(inode["ino"]) is int
        and inode["ino"] > 0,
        "Account home inode intent is invalid.",
    )
    if inode is not None and value["schema_version"] == 2:
        require(
            isinstance(inode["volume_uuid"], str)
            and re.fullmatch(
                r"[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}", inode["volume_uuid"]
            )
            and uuid.UUID(inode["volume_uuid"]).int != 0,
            "Account home volume intent is invalid.",
        )
    require(
        value["state"] in ("allocating", "ready")
        and (value["state"] != "ready" or inode is not None),
        "Account allocation state is invalid.",
    )
    return value


def _read(path, profile_id, home_parent):
    info = _metadata(path)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_size <= 65536,
        "Account intent must be a private root-owned regular file.",
    )
    try:
        value = json.loads(path.read_text(), object_pairs_hook=config._unique)
    except (OSError, ValueError, UnicodeError):
        raise Failure("Account intent is malformed; preserve it and inspect.") from None
    return _validate_intent(value, profile_id, home_parent)


def _save(path, value):
    control.atomic_write(
        path, (json.dumps(value, sort_keys=True) + "\n").encode(), mode=0o600
    )


def _reservations(root, home_parent):
    result = {}
    for directory in root.iterdir():
        if directory.name in (".resources.lock", ".fairness.json"):
            continue
        _protected_directory(directory)
        path = directory / "account.json"
        if not path.exists() and not path.is_symlink():
            continue
        intent = _read(path, directory.name, home_parent)
        require(
            intent["uid"] not in result,
            "Two organizations reserve the same native UID/GID; allocation is blocked.",
        )
        result[intent["uid"]] = intent["profile_id"]
    return result


def _unique(intent, inventory, reserved):
    names, numbers = inventory
    for kind in ("Users", "Groups"):
        require(
            all(
                name == intent["user"]
                for name in names[kind]
                if name.lower() == intent["user"].lower()
            ),
            "Native account name collides with another capitalization.",
        )
    for values in numbers.values():
        require(
            all(
                name == intent["user"]
                for name, number in values.items()
                if number == intent["uid"]
            ),
            "The native UID/GID is shared with another user or group; preserve both accounts.",
        )
    require(
        reserved.get(intent["uid"], intent["profile_id"]) == intent["profile_id"],
        "Another organization owns this pending native UID/GID.",
    )


def _presentation_metadata(kind, name, key, value):
    """Recognize only the observed inert user preferences and self-writer grants."""
    expected = {
        "AvatarRepresentation": "",
        "inputSources": "",
        "unlockOptions": "0",
        "_writers_AvatarRepresentation": name,
        "_writers_hint": name,
        "_writers_inputSources": name,
        "_writers_jpegphoto": name,
        "_writers_picture": name,
        "_writers_unlockOptions": name,
    }
    prefix = "dsAttrTypeNative:"
    if not key.startswith(prefix) or key.removeprefix(prefix) not in expected:
        return False
    require(
        kind == "Users" and value == expected[key.removeprefix(prefix)],
        "Native user presentation metadata differs from the supported inert values; preserve it.",
    )
    return True


def _record(path):
    output = _native(
        ["/usr/bin/dscl", "-plist", ".", "-read", path],
        "Inspect native pool account attributes",
    )[0]
    try:
        values = plistlib.loads(output.encode())
    except (ValueError, TypeError, UnicodeError, OverflowError, ExpatError):
        raise Failure(
            "Native account plist is malformed; preserve the account."
        ) from None
    require(isinstance(values, dict), "Native account plist is not a record.")
    kind = path.strip("/").split("/")[0]
    require(
        kind in ("Users", "Groups")
        and values.get("dsAttrTypeStandard:RecordType")
        == ["dsRecTypeStandard:" + kind],
        "Native account record type differs from its exact namespace.",
    )
    result = {}
    for key, entries in values.items():
        require(
            isinstance(key, str)
            and isinstance(entries, list)
            and len(entries) == 1
            and isinstance(entries[0], str),
            "Native account attributes must have one exact string value.",
        )
        value = entries[0]
        if _presentation_metadata(kind, path.rsplit("/", 1)[1], key, value):
            continue
        if key == "dsAttrTypeStandard:RecordType":
            continue
        if key == "dsAttrTypeNative:record_daemon_version":
            require(
                bool(re.fullmatch(r"[0-9]+", value)),
                "Native record daemon metadata is unsupported.",
            )
            continue
        if key == "dsAttrTypeNative:accountPolicyData":
            # Observed macOS creation telemetry is intrinsic metadata, never a
            # replacement for the explicit disabled authentication authority.
            try:
                policy = plistlib.loads(value.encode())
            except (ValueError, TypeError, UnicodeError, OverflowError, ExpatError):
                raise Failure("Native account policy metadata is malformed.") from None
            require(
                kind == "Users"
                and isinstance(policy, dict)
                and set(policy) == {"creationTime"}
                and (
                    type(policy["creationTime"]) is int
                    or type(policy["creationTime"]) is float
                    and math.isfinite(policy["creationTime"])
                )
                and policy["creationTime"] >= 0,
                "Native account policy metadata is unsupported; preserve it.",
            )
            continue
        if key == "dsAttrTypeNative:IsHidden":
            require(
                kind == "Users",
                "Native hidden-account metadata belongs only to a user.",
            )
            normalized = "IsHidden"
        else:
            require(
                key.startswith("dsAttrTypeStandard:"),
                "Native account attribute namespace is unsupported.",
            )
            normalized = key.removeprefix("dsAttrTypeStandard:")
            require(
                normalized != "IsHidden",
                "Hidden-account metadata has an unexpected namespace.",
            )
        require(
            normalized not in result,
            "Native account attributes contain conflicting namespaces.",
        )
        result[normalized] = value
    return result


def _matches(key, actual, expected):
    return (
        actual == expected
        or key == "Password"
        and actual in ("*", "********")
        and expected == "*"
    )


def _attributes(actual, expected, name, *, complete=False):
    require(
        set(actual) <= set(expected) | {"RecordName", "AppleMetaNodeLocation"}
        and (not complete or set(expected) <= set(actual)),
        "Existing native account has unexpected or incomplete attributes; preserve it.",
    )
    for key, value in actual.items():
        wanted = (
            name
            if key == "RecordName"
            else "/Local/Default"
            if key == "AppleMetaNodeLocation"
            else expected[key]
        )
        require(
            _matches(key, value, wanted),
            "Existing native account attribute differs from its saved intent; preserve it.",
        )


def _apply(intent, inventory):
    names, _ = inventory
    user = intent["user"]
    groups = {
        "GeneratedUID": intent["group_uuid"],
        "Password": "*",
        "PrimaryGroupID": str(intent["gid"]),
    }
    users = {
        "GeneratedUID": intent["user_uuid"],
        "Password": "*",
        "AuthenticationAuthority": ";DisabledUser;",
        "UserShell": "/usr/bin/false",
        "UniqueID": str(intent["uid"]),
        "PrimaryGroupID": str(intent["gid"]),
        "NFSHomeDirectory": intent["home"],
        "RealName": "Runner Pools isolated host " + intent["profile_id"],
        "IsHidden": "1",
    }
    records = [("Groups", groups), ("Users", users)]
    # Validate both records before changing either of them on a retry.
    saved = {
        kind: _record("/" + kind + "/" + user) if user in names[kind] else {}
        for kind, _ in records
    }
    for kind, expected in records:
        _attributes(saved[kind], expected, user, complete=intent["state"] == "ready")
    for kind, expected in records:
        path = "/" + kind + "/" + user
        for key, value in expected.items():
            if key not in saved[kind]:
                _dscl("-create", path, key, value)
        _attributes(_record(path), expected, user, complete=True)


def _bind_home_identity(intent, receipt, fd, info):
    """Keep inode identity; device numbers are only observations of one mount."""
    saved = intent["home_inode"]
    if saved is not None:
        require(
            saved["ino"] == info.st_ino,
            "Account home inode changed (expected "
            + str(saved["ino"])
            + ", found "
            + str(info.st_ino)
            + "); preserve it without repair.",
        )
    volume = _volume_uuid(fd)
    if saved is not None and intent["schema_version"] == 2:
        require(
            saved["volume_uuid"] == volume,
            "Account home volume changed; preserve it without repair.",
        )
        return intent
    # Legacy receipts recorded st_dev, which macOS can renumber on remount.
    # Bind only the unchanged inode on the same volume as BOTH protected
    # /Users and the root-owned allocation receipt. Never adopt a foreign mount.
    for directory in (Path(intent["home"]).parent, receipt.parent):
        _protected_directory(directory)
        parent_fd = _open_directory(directory)
        try:
            require(
                _fd_info(parent_fd).st_dev == info.st_dev
                and _volume_uuid(parent_fd) == volume,
                "Account home is outside the protected allocation volume; preserve it without repair.",
            )
        finally:
            os.close(parent_fd)
    updated = dict(
        intent,
        schema_version=2,
        home_inode={"dev": info.st_dev, "ino": info.st_ino, "volume_uuid": volume},
    )
    _save(receipt, updated)
    return updated


def _home(intent, receipt, inventory_check):
    home, stage = Path(intent["home"]), Path(intent["stage"])
    _protected_directory(home.parent)
    # macOS inherits a new directory's group from its protected parent;
    # /Users is normally root:admin. Only accept that exact root allocation
    # or the completed dedicated ownership, never arbitrary/mixed owners.
    root_owner = (0, _metadata(home.parent).st_gid)
    home_exists, stage_exists = (
        home.exists() or home.is_symlink(),
        stage.exists() or stage.is_symlink(),
    )
    if home_exists:
        require(
            intent["home_inode"] is not None and not stage_exists,
            "Existing home lacks this allocation inode intent; preserve it.",
        )
        fd = _open_directory(home)
        try:
            info = _fd_info(fd)
            require(
                (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                == (intent["uid"], intent["gid"], 0o700),
                "Account home ownership or permissions changed; preserve it without repair.",
            )
            intent = _bind_home_identity(intent, receipt, fd, info)
        finally:
            os.close(fd)
        return intent
    require(
        stage_exists or intent["home_inode"] is None,
        "Recorded account home disappeared; preserve its allocation for inspection.",
    )
    if not stage_exists:
        stage.mkdir(mode=0o700)
    fd = _open_directory(stage)
    try:
        info = _fd_info(fd)
        require(
            stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_uid, info.st_gid)
            in (root_owner, (intent["uid"], intent["gid"])),
            "Account home staging metadata differs; preserve it.",
        )
        if intent["home_inode"] is None:
            require(
                (info.st_uid, info.st_gid) == root_owner and not list(stage.iterdir()),
                "Unpublished home staging is not the empty protected allocation intent.",
            )
        intent = _bind_home_identity(intent, receipt, fd, info)
        inventory_check()
        if (info.st_uid, info.st_gid) != (intent["uid"], intent["gid"]):
            _assign(fd, intent["uid"], intent["gid"])
        require(
            not home.exists() and not home.is_symlink(),
            "Account home appeared during allocation; preserve both directories.",
        )
        os.rename(stage, home)
        parent = _open_directory(home.parent)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(fd)
    return intent


class _HomeACL:
    """Darwin sys/acl.h and membership.h descriptor APIs; never follow paths."""

    TYPE = 0x100  # ACL_TYPE_EXTENDED

    def __init__(self):
        try:
            self.library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            pointer = ctypes.c_void_p
            signatures = {
                "acl_get_fd_np": ([ctypes.c_int, ctypes.c_int], pointer),
                "acl_set_fd_np": ([ctypes.c_int, pointer, ctypes.c_int], ctypes.c_int),
                "acl_init": ([ctypes.c_int], pointer),
                "acl_dup": ([pointer], pointer),
                "acl_free": ([pointer], ctypes.c_int),
                "acl_to_text": ([pointer, pointer], pointer),
                "acl_create_entry_np": (
                    [ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.c_int],
                    ctypes.c_int,
                ),
                "acl_set_tag_type": ([pointer, ctypes.c_int], ctypes.c_int),
                "acl_set_qualifier": ([pointer, pointer], ctypes.c_int),
                "acl_set_permset_mask_np": ([pointer, ctypes.c_uint64], ctypes.c_int),
                "acl_get_flagset_np": (
                    [pointer, ctypes.POINTER(pointer)],
                    ctypes.c_int,
                ),
                "acl_clear_flags_np": ([pointer], ctypes.c_int),
                "mbr_uid_to_uuid": ([ctypes.c_uint32, pointer], ctypes.c_int),
                "mbr_uuid_to_id": (
                    [
                        pointer,
                        ctypes.POINTER(ctypes.c_uint32),
                        ctypes.POINTER(ctypes.c_int),
                    ],
                    ctypes.c_int,
                ),
            }
            for name, (arguments, result) in signatures.items():
                function = getattr(self.library, name)
                function.argtypes, function.restype = arguments, result
        except (AttributeError, OSError):
            raise Failure(
                "Native operator-home ACL API is unavailable; preserve host permissions."
            ) from None

    def checked(self, result):
        require(
            result == 0,
            "Native operator-home ACL operation failed (OS error "
            + str(ctypes.get_errno())
            + "); preserve host permissions and resume setup.",
        )

    def read(self, fd):
        value = self.library.acl_get_fd_np(fd, self.TYPE)
        if not value and ctypes.get_errno() == errno.ENOENT:
            value = self.library.acl_init(
                0
            )  # Darwin returns ENOENT for no extended ACL.
        require(
            bool(value), "Cannot inspect operator-home ACL; preserve host permissions."
        )
        return value

    def text(self, acl):
        value = self.library.acl_to_text(acl, None)
        require(
            bool(value), "Cannot verify operator-home ACL; preserve host permissions."
        )
        try:
            return ctypes.string_at(value)
        finally:
            self.library.acl_free(value)


def _home_metadata(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def _deny_home_access(fd, uid, *, expected_uuid=None):
    """Prepend one UID deny; retain every existing entry, ACL flag and mode."""
    try:
        before = os.fstat(fd)
    except OSError:
        raise Failure(
            "Cannot inspect operator-home descriptor; preserve host permissions."
        ) from None
    require(
        stat.S_ISDIR(before.st_mode), "Operator home descriptor is not a directory."
    )
    api = _HomeACL()
    library = api.library
    original = api.read(fd)
    candidate = ctypes.c_void_p()
    try:
        candidate.value = library.acl_dup(original)
        require(
            bool(candidate.value),
            "Cannot preserve operator-home ACL; no ACL change was made.",
        )
        identity = ctypes.create_string_buffer(16)
        api.checked(library.mbr_uid_to_uuid(uid, identity))
        require(
            expected_uuid is None
            or str(uuid.UUID(bytes=identity.raw)).upper() == expected_uuid,
            "Native membership UUID differs from the immutable account UUID; no operator ACL change permitted.",
        )
        resolved, kind = ctypes.c_uint32(), ctypes.c_int()
        api.checked(
            library.mbr_uuid_to_id(identity, ctypes.byref(resolved), ctypes.byref(kind))
        )
        require(
            (resolved.value, kind.value) == (uid, 0),
            "Operator-home ACL identity does not resolve to the managed UID.",
        )
        entry, flags = ctypes.c_void_p(), ctypes.c_void_p()
        # Index zero places deny before any existing allow. SDK: DENY=2,
        # LIST_DIRECTORY=1<<1, SEARCH=1<<3; no inheritance flags are added.
        api.checked(
            library.acl_create_entry_np(ctypes.byref(candidate), ctypes.byref(entry), 0)
        )
        api.checked(library.acl_set_tag_type(entry, 2))
        api.checked(library.acl_set_qualifier(entry, identity))
        api.checked(library.acl_set_permset_mask_np(entry, (1 << 1) | (1 << 3)))
        api.checked(library.acl_get_flagset_np(entry, ctypes.byref(flags)))
        api.checked(library.acl_clear_flags_np(flags))
        current = api.read(fd)
        try:
            require(
                api.text(current) == api.text(original),
                "Operator-home ACL changed during setup; preserve it and retry.",
            )
        finally:
            library.acl_free(current)
        require(
            _home_metadata(os.fstat(fd)) == _home_metadata(before),
            "Operator-home metadata changed during setup; preserve it.",
        )
        api.checked(library.acl_set_fd_np(fd, candidate, api.TYPE))
        actual = api.read(fd)
        try:
            require(
                api.text(actual) == api.text(candidate),
                "Operator-home ACL verification failed; preserve it and inspect.",
            )
        finally:
            library.acl_free(actual)
        require(
            _home_metadata(os.fstat(fd)) == _home_metadata(before),
            "Operator-home metadata changed during ACL enrollment; preserve it.",
        )
    finally:
        if candidate.value:
            library.acl_free(candidate)
        library.acl_free(original)


def _protected_operator_ancestor(fd):
    info = os.fstat(fd)
    require(
        stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
        "Operator-home ancestors must be protected root-owned directories; preserve host permissions.",
    )


def _open_operator_directory(path):
    """Walk from root with no-follow openat, binding every path component."""
    path = Path(path)
    require(
        path.is_absolute() and len(path.parts) > 1 and ".." not in path.parts,
        "Select the exact absolute operator login home.",
    )
    fd = _open_directory("/")
    try:
        for part in path.parts[1:]:
            _protected_operator_ancestor(fd)
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _operator_home_identity(fd, path, managed_uid):
    info = _fd_info(fd)
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid >= 500
        and info.st_uid != managed_uid,
        "Select the actual separate operator login home; preserve host permissions.",
    )
    try:
        operator = pwd.getpwuid(info.st_uid)
    except KeyError:
        raise Failure(
            "Operator home has no login owner; preserve host permissions."
        ) from None
    require(
        operator.pw_uid == info.st_uid
        and operator.pw_dir == str(path)
        and not operator.pw_name.startswith("ci-pools-")
        and operator.pw_shell.startswith("/")
        and Path(operator.pw_shell).name not in ("false", "nologin"),
        "Select the actual separate operator login home; preserve host permissions.",
    )
    return _home_metadata(info)


def _isolate_operator_home(intent, args, inventory_check):
    # Existing receipt, exact DSCL attributes, home and uniqueness have already
    # been checked. Also reject privileged group membership before ACL writes.
    user = macos_host.account_identity(args)
    require(
        user.pw_uid == intent["uid"] and user.pw_gid == intent["gid"],
        "Native account lookup differs from its immutable allocation; no operator ACL change permitted.",
    )
    path = Path(args.owner_home)
    fd = _open_operator_directory(path)
    try:
        before = _operator_home_identity(fd, path, intent["uid"])

        def bound():
            current = _open_operator_directory(path)
            try:
                require(
                    _operator_home_identity(current, path, intent["uid"]) == before
                    and _home_metadata(_fd_info(fd)) == before,
                    "Operator-home path or metadata changed; preserve host permissions and retry.",
                )
            finally:
                os.close(current)

        def denied():
            results = [
                _native(
                    [
                        "/usr/bin/sudo",
                        "-n",
                        "-H",
                        "-u",
                        intent["user"],
                        "--",
                        "/bin/test",
                        flag,
                        str(path),
                    ],
                    "Verify operator-home isolation",
                    allowed=(0, 1),
                )[1]
                for flag in ("-r", "-x")
            ]
            require(
                all(code in (0, 1) for code in results),
                "Operator-home kernel access probe failed.",
            )
            return results == [1, 1]

        isolated = denied()
        bound()
        if not isolated:
            inventory_check()
            _deny_home_access(fd, intent["uid"], expected_uuid=intent["user_uuid"])
            bound()
            require(
                denied(),
                "Managed runner still has operator-home access; preserve state and inspect host isolation.",
            )
            bound()
    finally:
        os.close(fd)


def prepare(profile, owner_home):
    _administrator()
    profile = validate(profile)
    p = paths(profile)
    for directory in (p["install"].parent, p["state"].parent, p["state"]):
        _protected_directory(directory)
    receipt = p["state"] / "account.json"
    try:
        with (
            _ALLOCATION_MUTEX,
            control.file_lock(p["install"].parent / ".accounts.lock"),
        ):
            reserved = _reservations(p["state"].parent, p["home"].parent)
            inventory = _inventory()
            if receipt.exists() or receipt.is_symlink():
                intent = _read(receipt, profile["id"], p["home"].parent)
                require(
                    intent["owner"] == profile["owner"],
                    "Account intent belongs to another immutable organization owner.",
                )
            else:
                user = username(profile)
                require(
                    all(
                        user.lower() not in {name.lower() for name in names}
                        for names in inventory[0].values()
                    )
                    and not p["home"].exists()
                    and not p["home"].is_symlink(),
                    "An unrecorded user, group or home already has this organization name; preserve it.",
                )
                occupied = set(reserved) | {
                    number
                    for values in inventory[1].values()
                    for number in values.values()
                }
                available = next(
                    (value for value in range(550, 1000) if value not in occupied), None
                )
                require(
                    available is not None,
                    "No unreserved dedicated native UID/GID remains in 550..999.",
                )
                intent = dict(
                    schema_version=2,
                    profile_id=profile["id"],
                    owner=profile["owner"],
                    user=user,
                    uid=available,
                    gid=available,
                    user_uuid=str(uuid.uuid4()).upper(),
                    group_uuid=str(uuid.uuid4()).upper(),
                    home=str(p["home"]),
                    stage=str(
                        p["home"].parent
                        / (
                            ".runner-pools-home-"
                            + profile["id"]
                            + "-"
                            + uuid.uuid4().hex
                        )
                    ),
                    home_inode=None,
                    state="allocating",
                )
                _save(
                    receipt, intent
                )  # Native attributes may change only after this durable intent.

            def unique():
                _unique(
                    intent,
                    _inventory(),
                    _reservations(p["state"].parent, p["home"].parent),
                )

            _unique(intent, inventory, reserved)
            _apply(intent, inventory)
            unique()
            intent = _home(intent, receipt, unique)
            args = SimpleNamespace(
                user=intent["user"],
                owner_home=str(owner_home),
                label="com.github.runner-pools." + profile["id"],
                marker="Runner Pools isolated host " + profile["id"],
            )
            try:
                _isolate_operator_home(intent, args, unique)
                user = macos_host.account(args)
            except macos_host.Failure as error:
                raise Failure(str(error)) from None
            require(
                user.pw_uid == intent["uid"] and user.pw_gid == intent["gid"],
                "Native account lookup differs from its immutable allocation.",
            )
            unique()
            if intent["state"] != "ready":
                _save(receipt, dict(intent, state="ready"))
            return user
    except (OSError, control.StateError):
        raise Failure(
            "Native account allocation or its lock is unavailable; preserve state and resume the same setup."
        ) from None
