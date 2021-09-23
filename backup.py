#!/usr/bin/env python3
"""Backup script for media volumes"""
# database:
#  file size/date mount-dev inode storage volume md5sum
# for each file:
#   * detect if already in database
#   * detect if file will fit on disk and exit if not
#   * copy and compute sha1 of file (using dc3dd)
#   * create par2 file

# Symlinks
# Treat symlinks as file with contents being link destination

# Detection rules:
# 1: Exact item is in db: no action
# 2: Same inode/dev/size is in db:
# 2.a: Original path no longer exists:
# 2.a.1: Destination path does not exist
# 2.a.1.a: Storage Id is same as current: rename in db, rename on storage disk
# 2.a.1.b: Storage Id is different: rename in db, add Rename action
# 2.a.2: Destination path does exist
# 2.a.2.a: Destination and source have matching SHA1: update inode in db for new_path,
#                                                     remove old path from db
# 2.a.2.b: Mismatch sha1, storage Id is same as current: remove storage file, rename in db,
#                                                        rename on storage disk
# 2.a.2.c: Mismatch sha1, storage Id is different: add remove action, rename in db,
#                                                  add rename action
# 2.b: Original path still exists:
# 2.b.1: Destination path does not exist
# 2.b.1.a: Storage Id is same as current: add entry in db, hardlink on storage disk
# 2.b.1.b: Storage Id is different: add entry in db, add hardlink action
# 2.b.2: Destination path does exist
# 2.b.2.a: Destination and source have matching SHA1: update inode in db
# 2.b.2.b: Mismatch sha1, storage Id is same as current: remove storage file,  add entry in db,
#                                                        hardlink on storage disk
# 2.b.2.c: Mismatch sha1, storage Id is different: add remove action, add in db,
#                                                  add hardlink action
# 3: Same path is in db (but different inode/dev), size matches
# 3.a: Hash matches: update inode/dev in db
# 3.b: Hash doesn't match:
# 3.b.1: Storage Id is same as current: update in db, replace on storage disk
# 3.b.2: Storage Id is different: update in db, copy to storage disk, add delete action
# 4: Same path is in db size mismatch
# 4.a: Storage Id is same as current: update in db, replace on storage disk
# 4.b: Storage Id is different: update in db, copy to storage disk, add delete action
# 5: Path is not in db: add to db, copy to storage disk
# 5.a: hash/size is in db:
# 5.a.1: Storage Id is same as current: remove on disk, add hardlink on disk
# 5.a.2: Storage Id is different: remove on disk, add hardlink action

# Cleanup rules
# 1: Path only in db:
# 1.a: Storage Id is same as current: remove in db, remove from disk
# 1.b: Storage Id is different: remove in db, add delete action
# FUTURE:
#  * cleanup actions on current storage
import argparse
import fnmatch
import glob
import hashlib
import logging
import os
import re
import sqlite3
import stat
import subprocess
import uuid

from collections import namedtuple

# pylint: disable=broad-except
# pylint: disable=unspecified-encoding
SCHEMA = 1
FileObj = namedtuple("FileObj", ["path", "inode", "sha1", "time", "size", "storage_id"])
CHANGED = {
    'skipped': 0,
    'added': 0,
    'removed': 0,
    'modified': 0,
    }

STORAGE_ID = None
STORAGE_MOUNT = None
DATA_MOUNT = None
DC3DD = "dc3dd"
DC3DD_HLOG = f"/tmp/dc3dd.log.{ os.getpid() }"
PAR2 = "par2"

def get_schema(cur):
    """Fetch current DB schema"""
    cur.execute("CREATE TABLE IF NOT EXISTS settings (key PRIMARY KEY, value)")
    cur.execute("SELECT value FROM settings WHERE key = 'schema'")
    schema = cur.fetchone()
    return schema[0] if schema else 0

def upgrade_schema(cur, old_schema):
    """Create/upgrade DB schema"""
    if old_schema == 0:
        cur.execute("CREATE TABLE files "
                    "(path TEXT PRIMARY KEY, inode INT, sha1, time INT, size INT, storage_id)")
        cur.execute("CREATE TABLE actions "
                    "(id INTEGER PRIMARY KEY AUTOINCREMENT, storage_id, action, path, target_path)")
    else:
        raise Exception(f"Unsupported old schema: {old_schema}")
    cur.execute(f"REPLACE INTO settings (key, value) VALUES('schema', { SCHEMA })")

def update_db(cur, dbobj, path, lstat, sha1=None, storage_id=None):
    """Update a file entry in the db"""
    # pylint: disable=too-many-arguments
    cur.execute("UPDATE files SET "
                "inode = ?, sha1 = ?, time = ?, size = ?, storage_id = ? "
                "WHERE path = ?",
                (lstat.st_ino, sha1 or dbobj.sha1, lstat.st_mtime,
                 lstat.st_size, storage_id or dbobj.storage_id, path))

def add_db(cur, path, lstat, sha1):
    """Add a new file entry in the DB"""
    try:
        cur.execute("INSERT INTO files (path, inode, sha1, time, size, storage_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (path, lstat.st_ino, sha1, lstat.st_mtime, lstat.st_size, STORAGE_ID))
    except Exception as _e:
        logging.error("Failed to add entry (path=%s, inode=%s, sha1=%s, time=%s, size=%s, "
                      "storage_id=%s): %s",
                      path, lstat.st_ino, sha1, lstat.st_mtime, lstat.st_size, STORAGE_ID, _e)
        raise

def remove_db(cur, path):
    """Remove a file entry from the DB"""
    cur.execute("DELETE FROM files WHERE path = ?", (path,))

def append_action(cur, action, storage_id, path1, path2=None):
    """Add a new action for a non-present archive disk to the action table"""
    if action not in ('RENAME', 'LINK', 'DELETE'):
        logging.error("Unknown action: (%s, %s, %s)", action, path1, path2)
        raise Exception(f"unsupported action: { action }")
    cur.execute("INSERT INTO actions (storage_id, action, path, target_path) VALUES (?, ?, ?, ?)",
                (storage_id, action, path1, f"'{ path2 }'" if path2 else "NULL"))

def set_storage_id():
    """Read existing storage id, or generate a new one"""
    global STORAGE_ID  # pylint: disable=global-statement
    id_file = os.path.join(STORAGE_MOUNT, ".backup_id")
    if os.path.exists(id_file):
        with open(id_file) as _fh:
            STORAGE_ID = _fh.readline().strip()
    else:
        with open(id_file, "w") as _fh:
            STORAGE_ID = str(uuid.uuid4())
            _fh.write(STORAGE_ID)

def set_data_mount(path):
    """Set global DATA_MOUNT path to the mount-point of the data-disk"""
    while not os.path.ismount(path):
        path = os.path.dirname(path)
    global DATA_MOUNT  # pylint: disable=global-statement
    DATA_MOUNT = path

def sync_storage_db(cur):
    """Apply any actions to storage_db, and sync files between dbs"""
    storage_db = os.path.join(STORAGE_MOUNT, ".backup_db.sqlite3")
    if not os.path.exists(storage_db):
        return
    sqldb = sqlite3.connect(storage_db)
    s_cur = sqldb.cursor()
    old_schema = get_schema(s_cur)
    if old_schema != SCHEMA:
        upgrade_schema(s_cur, old_schema)

    for action, path, target in cur.execute(
            "SELECT action, path, target_path FROM actions WHERE storage_id = ?", (STORAGE_ID,)):
        # Note actions can fail if there are multiple copies of the same storage_id on different
        # disks.  That is ok, as we'll sync the file-state anyway
        # Since actions are ordered, as soon as one fails, we're done processing them
        if action == 'RENAME':
            try:
                path_rename(path, target)
                s_cur.execute("UPDATE files SET path = ? WHERE path = ?", (path, target))
            except Exception as _e:
                logging.warning("Failed to apply rename action %s => %s: %s", path, target, _e)
                break
        elif action == 'LINK':
            try:
                path_hardlink(path, target)
                s_cur.execute(
                    "INSERT INTO files (path, inode, sha1, time, size, storage_id) "
                    "SELECT ?, inode, sha1, time, size, storage_id FROM files WHERE path = ?",
                    (target, path))
            except Exception as _e:
                logging.warning("Failed to apply hardlink action %s => %s: %s", path, target, _e)
                break
        elif action == 'DELETE':
            try:
                path_unlink(path)
                s_cur.execute("DELETE FROM files WHERE path = ?", (path,))
            except Exception as _e:
                logging.warning("Failed to apply delete action %s: %s", path, _e)
                break
        else:
            logging.error("Unknown action: (%s, %s, %s)", action, path, target)
    # What if we have 2 copies of a disk with the same storage id?  in that case the 2nd time
    # There are no actions...This is ok since we'll still sync the 'files' table, but it will be
    # slower
    cur.execute("DELETE FROM actions WHERE storage_id = ?", (STORAGE_ID,))

    sqldb.commit()
    sqldb.close()

    # Now handle files
    cur.execute("ATTACH ? AS storage_db", (storage_db,))
    cur.execute("DELETE FROM files WHERE storage_id = ?", (STORAGE_ID,))
    cur.execute("INSERT INTO files SELECT * FROM storage_db.files")
    cur.execute("DETACH storage_db")

def write_storage_db(cur):
    """Write the relevant files data for the current storage disk to the storage-local db"""
    storage_db = os.path.join(STORAGE_MOUNT, ".backup_db.sqlite3")
    if not os.path.exists(storage_db):
        sqldb = sqlite3.connect(storage_db)
        s_cur = sqldb.cursor()
        get_schema(s_cur)         # ensures 'settings' table exists
        upgrade_schema(s_cur, 0)
        sqldb.commit()
        sqldb.close()
    # If we get here, the db schema is synced (either done here, or in sync_storage_db())
    cur.execute("ATTACH ? AS storage_db", (storage_db,))
    cur.execute("DELETE FROM storage_db.files")
    cur.execute("INSERT INTO storage_db.files SELECT * FROM files WHERE storage_id = ?",
                (STORAGE_ID,))
    cur.connection.commit()
    cur.execute("DETACH storage_db")

def storage_path(path):
    """Determine the path on the storage disk for a given path"""
    if path[0] == os.path.sep:
        path = path[1:]
    return os.path.join(STORAGE_MOUNT, path)

def run_dc3dd(src, dest):
    """Use dc3dd to do a copy + calc SHA1"""
    try:
        os.unlink(DC3DD_HLOG)
    except FileNotFoundError:
        pass
    subprocess.run([DC3DD, f"if={ src }", f"of={ dest }", "hash=sha1", "nwspc=on",
                    f"hlog={ DC3DD_HLOG }"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    with open(DC3DD_HLOG) as _fh:
        for line in _fh:
            line = line.strip()
            if line.endswith(' (sha1)'):
                sha1 = line.replace(' (sha1)', '')
                break
    return sha1

def calc_hash(path):
    """Calculate the SHA1 for a file"""
    return run_dc3dd(path, "/dev/null")

def calc_symlink_hash(path):
    """Calculate the SHA1 for a symlink"""
    return hashlib.sha1(os.path.abspath(os.readlink(path.encode('utf8')))).hexdigest()

def path_rename(origpath, newpath):
    """Rename path on storage disks (and update par2 files)"""
    origpath = storage_path(origpath)
    newpath = storage_path(newpath)
    os.rename(origpath, newpath)
    if os.path.exists(origpath + ".par2"):
        os.rename(origpath + ".par2", newpath + ".par2")
        for path in glob.glob(f"{ origpath }.vol*.par2"):
            npath = newpath + path[len(origpath):]
            os.rename(path, npath)

def path_hardlink(origpath, newpath):
    """Hardlink path on storage disks (and update par2 files)"""
    origpath = storage_path(origpath)
    newpath = storage_path(newpath)
    os.makedirs(os.path.dirname(newpath), exist_ok=True)
    os.link(origpath, newpath)
    if os.path.exists(origpath + ".par2"):
        os.link(origpath + ".par2", newpath + ".par2")
        for path in glob.glob(f"{ origpath }.vol*.par2"):
            npath = newpath + path[len(origpath):]
            os.link(path, npath)

def path_unlink(path):
    """Remove path on storage disks (and remove par2 files)"""
    path = storage_path(path)
    os.unlink(path)
    if os.path.exists(path + ".par2"):
        os.unlink(path + ".par2")
    for par2path in glob.glob(f"{ path }.vol*.par2"):
        os.unlink(par2path)


def path_copy(path):
    """Copy path from original location to storage disk and calculate sha1
       (but don't calculate par2)"""
    dest = storage_path(path)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    try:
        if os.path.islink(path):
            link = os.path.abspath(os.readlink(path))
            os.symlink(storage_path(link), dest)
            sha1 = calc_symlink_hash(path)
        else:
            sha1 = run_dc3dd(path, dest)
    except Exception as _e:
        logging.error("Failed to copy %s -> %s: %s", path, dest, _e)
        return None
    return sha1

def calculate_par2(path):
    """Run PAR2 on path to generate extra parity"""
    path = storage_path(path)
    try:
        subprocess.run([PAR2, 'c', path],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except Exception as _e:
        logging.error("Failed to create par2 files for %s: %s", path, _e)


def handle_path(cur, path):
    """Take needed action for a given file path"""
    # pylint: disable=too-many-statements too-many-branches too-many-return-statements
    # return True if par2 calc is needed
    lstat = os.lstat(path)
    if stat.S_ISLNK(lstat.st_mode):
        is_symlink = True
        sha1 = sha1 = calc_symlink_hash(path)
        needs_par2 = False
    else:
        is_symlink = False
        sha1 = None
        needs_par2 = lstat.st_size != 0
    if is_symlink:
        cur.execute(f"SELECT { ', '.join(FileObj._fields) } FROM files WHERE sha1 = ?", (sha1,))
    else:
        cur.execute(f"SELECT { ', '.join(FileObj._fields) } FROM files "
                    "WHERE inode = ? AND path LIKE ?", (lstat.st_ino, DATA_MOUNT + '%'))
    matches = [FileObj(*_) for _ in cur.fetchall()]
    if is_symlink:
        if any(_.path == path for _ in matches):
            #1: Exact match
            CHANGED['skipped'] += 1
            return False
        match = next((_ for _ in matches if sha1 == _.sha1), None)
    else:
        if any(_.path == path and _.size == lstat.st_size for _ in matches):
            #1: Exact match
            CHANGED['skipped'] += 1
            return False
        match = next((_ for _ in matches if _.size == lstat.st_size), None)

    cur.execute(f"SELECT { ', '.join(FileObj._fields) } FROM files WHERE path = ?", (path,))
    item = cur.fetchone()
    if item:
       item = FileObj(*item)

    if match:
        if not os.path.exists(match.path):
            if not item:
                # 2.a.1: Destination does not exist in db
                if match.storage_id == STORAGE_ID:
                    # 2.a.1.a: Rename on disk
                    path_rename(match.path, path)
                    update_db(cur, match, path, lstat)
                else:
                    # 2.a.1.b: Rename in db
                    append_action(cur, "RENAME", match.storage_id, match.path, path)
                    update_db(cur, match, path, lstat)
            else:
                # 2.a.2: Destination already exists in db
                if match.sha1 == item.sha1:
                    # 2.a.2.a: inode changed, but no data change
                    update_db(cur, item, path, lstat)
                    remove_db(cur, path)
                else:
                    if item.storage_id == STORAGE_ID:
                        # 2.a.2.b: sha1 mismatch, same storage device
                        path_unlink(path)
                        path_rename(match.path, path)
                        remove_db(cur, path)
                        update_db(cur, item, path, lstat)
                    else:
                        # 2.a.2.c: sha1 mismatch, different storage device
                        append_action(cur, "DELETE", item.storage_id, path)
                        remove_db(cur, path)
                        update_db(cur, match, path, lstat)
                        append_action(cur, "RENAME", item.storage_id, path)
            CHANGED['modified'] += 1
            return False
        # original path still exists
        if not item:
            # 2.b.1: Destination path does not exist
            if match.storage_id == STORAGE_ID:
                # 2.b.1.a: hardlink on disk
                path_hardlink(match.path, path)
                add_db(cur, path, lstat, match.sha1)
            else:
                # 2.b.1.b: hardlink in db
                append_action(cur, "LINK", match.storage_id, match.path, path)
                add_db(cur, path, lstat, match.sha1)
        else:
            # 2.b.2: Destination path does exist
            if match.sha1 == item.sha1:
                # 2.b.2.a: inode changed, but no data change
                update_db(cur, item, path, lstat)
            else:
                if match.storage_id == STORAGE_ID:
                    # 2.b.2.b: Mismatch sha1, storage Id is same as current
                    path.remove(path)
                    path_hardlink(match.path, path)
                    update_db(cur, item, path, lstat)
                else:
                    # 2.b.2.c: Mismatch sha1, storage Id is different
                    append_action(cur, "DELETE", item.storage_id, path)
                    update_db(cur, match, path, lstat)
                    append_action(cur, "LINK", item.storage_id, path)
        CHANGED['modified'] += 1
        return False
    if item:
        if not is_symlink:
            if item.size == lstat.st_size:
                sha1 = calc_hash(path)
                if sha1 == item.sha1:
                    # 3.a: hash match
                    update_db(cur, item, path, lstat)
                    CHANGED['modified'] += 1
                    return False
        # if item.size != lstat.st_size or item.sha1 != sha1
        if item.storage_id == STORAGE_ID:
            # 3.b.1 or 4.a: Modified file
            sha1 = path_copy(path)
            update_db(cur, item, path, lstat, sha1, STORAGE_ID)
        else:
            # 3.b.2 or 4.b: Modified file
            sha1 = path_copy(path)
            update_db(cur, item, path, lstat, sha1, STORAGE_ID)
            append_action(cur, "DELETE", item.storage_id, path)
        CHANGED['modified'] += 1
        return needs_par2
    # 5: Path is not in db
    sha1 = path_copy(path)
    add_db(cur, path, lstat, sha1)
    cur.execute(f"SELECT { ', '.join(FileObj._fields) } FROM files "
                "WHERE sha1 = ? and size = ? and path != ?", (sha1, lstat.st_size, path))
    matches = [FileObj(*_) for _ in cur.fetchall()]
    if matches:
        match = next((_ for _ in matches if _.storage_id == STORAGE_ID), None)
        if match:
            # 5.a.1:
            os.unlink(storage_path(path))
            path_hardlink(match.path, path)
        else:
            # 5.a.2:
            os.unlink(storage_path(path))
            append_action(cur, "LINK", match.storage_id, match.path, path)
        CHANGED['modified'] += 1
        return False
    CHANGED['added'] += 1
    return needs_par2

def clean_storage(cur, seen):
    """Delete any files on current storage that are no longer present"""
    remove = set()
    for obj in cur.execute(f"SELECT { ', '.join(FileObj._fields) } FROM files"):
        item = FileObj(*obj)
        if item.path in seen:
            continue
        CHANGED['skipped'] += 1
        if item.storage_id == STORAGE_ID:
            path_unlink(item.path)
            remove.add(item.path)
        else:
            append_action(cur, "DELETE", item.storage_id, item.path)
            remove.add(item.path)

    for path in remove:
        remove_db(cur, path)

def parse_exclude(args):
    """Generate exclusion list in RE format"""
    exclude = []
    if args.config:
        with open(args.config) as _fh:
            for line in _fh.readlines():
                if line.startswith("exclude"):
                    res = fnmatch.translate(line.strip().split(None, 1)[-1])
                    exclude.append(re.compile(res))
    return exclude

def parse_cmdline():
    """Parse cmdline args"""
    parser = argparse.ArgumentParser()
    parser.add_argument('paths', metavar='PATH', nargs='+', help='Paths to archive')
    parser.add_argument("--config", help="Snapraid config file")
    parser.add_argument("--database", "--db", required=True, help="Snapraid config file")
    parser.add_argument("--dest", required=True, help="Directory to write files to")
    parser.add_argument("--verbose", action='store_true', help="Increate logging level")
    parser.add_argument("--no-clean", dest='clean', action='store_false',
                        help="Increate logging level")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    return args

def main():
    """Entrypoint"""
    args = parse_cmdline()
    global STORAGE_MOUNT  # pylint: disable=global-statement
    STORAGE_MOUNT = args.dest

    set_storage_id()
    exclude = parse_exclude(args)
    sqldb = sqlite3.connect(args.database)
    cur = sqldb.cursor()
    try:
        schema = get_schema(cur)
        if schema != SCHEMA:
            upgrade_schema(cur, schema)
        sync_storage_db(cur)
        seen = set()
        for basepath in args.paths:
            set_data_mount(basepath)
            for root, dirs, files in os.walk(basepath):
                filtered_dirs = []
                for dirname in dirs:
                    path = os.path.join(root, dirname)
                    if any(_exc.search(path) for _exc in exclude):
                        logging.debug("Excluding %s", path)
                        continue
                    filtered_dirs.append(path)
                for fname in files:
                    path = os.path.join(root, fname)
                    if any(_exc.search(path) for _exc in exclude):
                        logging.debug("Excluding %s", path)
                        continue
                    if args.clean:
                        seen.add(path)
                    if handle_path(cur, path):
                        calculate_par2(path)
        if args.clean:
            clean_storage(cur, seen)
        write_storage_db(cur)
    finally:
        sqldb.commit()
        sqldb.close()
    logging.info("Unchanged files: %d", CHANGED['skipped'])
    logging.info("Added files:     %d", CHANGED['added'])
    logging.info("Modified files:  %d", CHANGED['modified'])
    logging.info("Removed files:   %d", CHANGED['removed'])

if __name__ == "__main__":  # pragma: no cover
    main()
