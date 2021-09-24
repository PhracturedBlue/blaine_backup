#!/usr/bin/env python3
"""Backup script for media volumes"""
# database:
#  file size/date mount-dev inode storage volume md5sum
# for each file:
#   * detect if already in database
#   * detect if file will fit on disk and exit if not
#   * copy and compute sha1 of file (using dc3dd)
#   * create par2 file
#   * for symlinks, the symlink is copied unmodified.  This means it may be broken for
#     absolute links

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
PAR2 = "par2"
DC3DD = "dc3dd"
DC3DD_HLOG = f"/tmp/dc3dd.log.{ os.getpid() }"

FileObj = namedtuple("FileObj", ["path", "inode", "sha1", "time", "size", "storage_id"])

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
    return hashlib.sha1(os.readlink(path.encode('utf8'))).hexdigest()


def _set_storage_id(storage_root):
    """Read existing storage id, or generate a new one"""
    id_file = os.path.join(storage_root, ".backup_id")
    if os.path.exists(id_file):
        with open(id_file) as _fh:
            return _fh.readline().strip()
    else:
        with open(id_file, "w") as _fh:
            storage_id = str(uuid.uuid4())
            _fh.write(storage_id)
        return storage_id

class Backup:
    """Execute a backup"""
    # pylint: disable = too-many-instance-attributes
    def __init__(self, cur, storage_dir):
        """Initialize"""
        self.skipped = 0
        self.added = 0
        self.removed = 0
        self.modified = 0
        self.cur = cur
        self.storage_root = storage_dir
        self.storage_id = _set_storage_id(storage_dir)
        self.data_mount = None

    def set_data_mount(self, path):
        """Set data_mount path to the mount-point of the data-disk"""
        while not os.path.ismount(path):
            path = os.path.dirname(path)
        self.data_mount = path

    def show_summary(self):
        """Display activity summary"""
        logging.info("Unchanged files: %d", self.skipped)
        logging.info("Added files:     %d", self.added)
        logging.info("Modified files:  %d", self.modified)
        logging.info("Removed files:   %d", self.removed)

    def storage_path(self, path):
        """Determine the path on the storage disk for a given path"""
        if path[0] == os.path.sep:
            path = path[1:]
        return os.path.join(self.storage_root, path)

    def path_rename(self, origpath, newpath):
        """Rename path on storage disks (and update par2 files)"""
        origpath = self.storage_path(origpath)
        newpath = self.storage_path(newpath)
        os.rename(origpath, newpath)
        if os.path.exists(origpath + ".par2"):
            os.rename(origpath + ".par2", newpath + ".par2")
            for path in glob.glob(f"{ origpath }.vol*.par2"):
                npath = newpath + path[len(origpath):]
                os.rename(path, npath)

    def path_hardlink(self, origpath, newpath):
        """Hardlink path on storage disks (and update par2 files)"""
        origpath = self.storage_path(origpath)
        newpath = self.storage_path(newpath)
        os.makedirs(os.path.dirname(newpath), exist_ok=True)
        os.link(origpath, newpath)
        if os.path.exists(origpath + ".par2"):
            os.link(origpath + ".par2", newpath + ".par2")
            for path in glob.glob(f"{ origpath }.vol*.par2"):
                npath = newpath + path[len(origpath):]
                os.link(path, npath)

    def path_unlink(self, path):
        """Remove path on storage disks (and remove par2 files)"""
        path = self.storage_path(path)
        if not os.path.lexists(path):
            return
        os.unlink(path)
        if os.path.exists(path + ".par2"):
            os.unlink(path + ".par2")
        for par2path in glob.glob(f"{ path }.vol*.par2"):
            os.unlink(par2path)


    def path_copy(self, path):
        """Copy path from original location to storage disk and calculate sha1
           (but don't calculate par2)"""
        dest = self.storage_path(path)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            if os.path.islink(path):
                link = os.readlink(path)
                os.symlink(link, dest)
                sha1 = calc_symlink_hash(path)
            else:
                sha1 = run_dc3dd(path, dest)
        except Exception as _e:
            logging.error("Failed to copy %s -> %s: %s", path, dest, _e)
            return None
        return sha1

    def calculate_par2(self, path):
        """Run PAR2 on path to generate extra parity"""
        path = self.storage_path(path)
        try:
            subprocess.run([PAR2, 'c', path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except Exception as _e:
            logging.error("Failed to create par2 files for %s: %s", path, _e)

    def update_db(self, dbobj, path, lstat, sha1=None, storage_id=None, newpath=None):
        """Update a file entry in the db"""
        # pylint: disable=too-many-arguments
        self.cur.execute("UPDATE files SET "
                         "path = ?, inode = ?, sha1 = ?, time = ?, size = ?, storage_id = ? "
                         "WHERE path = ?",
                         (newpath or path, lstat.st_ino, sha1 or dbobj.sha1, lstat.st_mtime,
                          lstat.st_size, storage_id or dbobj.storage_id, path))

    def add_db(self, path, lstat, sha1, storage_id=None):
        """Add a new file entry in the DB"""
        try:
            self.cur.execute(
                "INSERT INTO files (path, inode, sha1, time, size, storage_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (path, lstat.st_ino, sha1, lstat.st_mtime, lstat.st_size,
                 storage_id or  self.storage_id))
        except Exception as _e:
            logging.error(
                "Failed to add entry (path=%s, inode=%s, sha1=%s, time=%s, size=%s, "
                "storage_id=%s): %s",
                path, lstat.st_ino, sha1, lstat.st_mtime, lstat.st_size,
                storage_id or self.storage_id, _e)
            raise

    def remove_db(self, path):
        """Remove a file entry from the DB"""
        self.cur.execute("DELETE FROM files WHERE path = ?", (path,))

    def append_action(self, action, storage_id, path1, path2=None):
        """Add a new action for a non-present archive disk to the action table"""
        if action not in ('RENAME', 'LINK', 'DELETE'):
            logging.error("Unknown action: (%s, %s, %s)", action, path1, path2)
            raise Exception(f"unsupported action: { action }")
        if not path2 and action != 'DELETE':
            logging.error("No destination for action %s %s", action, path1)
            raise Exception(f"No destination for action { action } { path1 }")
        self.cur.execute(
            "INSERT INTO actions (storage_id, action, path, target_path) VALUES (?, ?, ?, ?)",
            (storage_id, action, path1, f"{ path2 }" if path2 else "NULL"))

    def sync_storage_db(self):
        """Apply any actions to storage_db, and sync files between dbs"""
        storage_db = os.path.join(self.storage_root, ".backup_db.sqlite3")
        if not os.path.exists(storage_db):
            return
        sqldb = sqlite3.connect(storage_db)
        s_cur = sqldb.cursor()
        old_schema = get_schema(s_cur)
        if old_schema != SCHEMA:
            upgrade_schema(s_cur, old_schema)

        for action, path, target in self.cur.execute(
                "SELECT action, path, target_path FROM actions "
                "WHERE storage_id = ?", (self.storage_id,)):
            # Note actions can fail if there are multiple copies of the same storage_id on different
            # disks.  That is ok, as we'll sync the file-state anyway
            # Since actions are ordered, as soon as one fails, we're done processing them
            if action == 'RENAME':
                try:
                    self.path_rename(path, target)
                    s_cur.execute("UPDATE files SET path = ? WHERE path = ?", (target, path))
                except Exception as _e:
                    logging.warning("Failed to apply rename action %s => %s: %s", path, target, _e)
                    break
            elif action == 'LINK':
                try:
                    self.path_hardlink(path, target)
                    s_cur.execute(
                        "INSERT INTO files (path, inode, sha1, time, size, storage_id) "
                        "SELECT ?, inode, sha1, time, size, storage_id FROM files WHERE path = ?",
                        (target, path))
                except Exception as _e:
                    logging.warning("Failed to apply hardlink action %s => %s: %s",
                                    path, target, _e)
                    break
            elif action == 'DELETE':
                try:
                    self.path_unlink(path)
                    s_cur.execute("DELETE FROM files WHERE path = ?", (path,))
                except Exception as _e:
                    logging.warning("Failed to apply delete action %s: %s", path, _e)
                    break
            else:
                logging.error("Unknown action: (%s, %s, %s)", action, path, target)
        # What if we have 2 copies of a disk with the same storage id?  in that case the 2nd time
        # There are no actions...This is ok since we'll still sync the 'files' table, but it will be
        # slower
        self.cur.execute("DELETE FROM actions WHERE storage_id = ?", (self.storage_id,))

        sqldb.commit()
        sqldb.close()

        # Now handle files
        self.cur.execute("ATTACH ? AS storage_db", (storage_db,))
        self.cur.execute("DELETE FROM files WHERE storage_id = ?", (self.storage_id,))
        self.cur.execute("SELECT files.path, files.storage_id, a.storage_id FROM files "
                         "LEFT JOIN storage_db.files AS a ON files.path = a.path "
                         "WHERE a.path IS NOT NULL")
        duplicates = self.cur.fetchall()
        for dup in duplicates:
            logging.warning("Found conflicting path %s: %s <=> %s", *dup)
        self.cur.execute("INSERT OR IGNORE INTO files SELECT * FROM storage_db.files")
        self.cur.connection.commit()
        self.cur.execute("DETACH storage_db")

    def write_storage_db(self):
        """Write the relevant files data for the current storage disk to the storage-local db"""
        storage_db = os.path.join(self.storage_root, ".backup_db.sqlite3")
        if not os.path.exists(storage_db):
            sqldb = sqlite3.connect(storage_db)
            s_cur = sqldb.cursor()
            get_schema(s_cur)         # ensures 'settings' table exists
            upgrade_schema(s_cur, 0)
            sqldb.commit()
            sqldb.close()
        # If we get here, the db schema is synced (either done here, or in sync_storage_db())
        self.cur.execute("ATTACH ? AS storage_db", (storage_db,))
        self.cur.execute("DELETE FROM storage_db.files")
        self.cur.execute("INSERT INTO storage_db.files SELECT * FROM files WHERE storage_id = ?",
                         (self.storage_id,))
        self.cur.connection.commit()
        self.cur.execute("DETACH storage_db")

    def handle_path(self, path):
        """Take needed action for a given file path"""
        # pylint: disable=too-many-statements too-many-branches too-many-return-statements
        # return True if par2 calc is needed
        lstat = os.lstat(path)
        if stat.S_ISLNK(lstat.st_mode):
            is_symlink = True
            sha1 = calc_symlink_hash(path)
            needs_par2 = False
        else:
            is_symlink = False
            sha1 = None
            needs_par2 = lstat.st_size != 0
        if is_symlink:
            self.cur.execute(
                f"SELECT { ', '.join(FileObj._fields) } FROM files WHERE sha1 = ?", (sha1,))
        else:
            self.cur.execute(
                f"SELECT { ', '.join(FileObj._fields) } FROM files "
                "WHERE inode = ? AND path LIKE ?", (lstat.st_ino, self.data_mount + '%'))
        matches = [FileObj(*_) for _ in self.cur.fetchall()]
        if is_symlink:
            if any(_.path == path for _ in matches):
                #1: Exact match
                self.skipped += 1
                return False
            match = next((_ for _ in matches if sha1 == _.sha1 and _.size == lstat.st_size), None)
        else:
            if any(_.path == path and _.size == lstat.st_size for _ in matches):
                #1: Exact match
                self.skipped += 1
                return False
            # prefer path-match
            match = next((_ for _ in matches if _.size == lstat.st_size), None)

        self.cur.execute(
            f"SELECT { ', '.join(FileObj._fields) } FROM files WHERE path = ?", (path,))
        item = self.cur.fetchone()
        if item:
            item = FileObj(*item)
        if match:
            if not os.path.lexists(match.path):
                # 2.a rename
                if not item:
                    # 2.a.1: Destination does not exist in db
                    if match.storage_id == self.storage_id:
                        # 2.a.1.a: Rename on disk
                        self.path_rename(match.path, path)
                        self.update_db(match, match.path, lstat, newpath=path)
                    else:
                        # 2.a.1.b: Rename in db
                        self.append_action("RENAME", match.storage_id, match.path, path)
                        self.update_db(match, match.path, lstat, newpath=path)
                else:
                    # 2.a.2: Destination already exists in db
                    if match.sha1 == item.sha1:
                        # 2.a.2.a: inode changed, but no data change
                        self.update_db(item, path, lstat)
                        self.remove_db(match.path)
                        if match.storage_id != self.storage_id:
                            self.append_action("DELETE", match.storage_id, match.path)
                    else:
                        if item.storage_id == self.storage_id:
                            # 2.a.2.b: sha1 mismatch, same storage device
                            self.path_unlink(path)
                            self.path_rename(match.path, path)
                            self.remove_db(path)
                            self.update_db(match, match.path, lstat, newpath=path)
                        else:
                            # 2.a.2.c: sha1 mismatch, different storage device
                            self.append_action("DELETE", item.storage_id, path)
                            self.remove_db(path)
                            self.update_db(match, match.path, lstat, newpath=path)
                            self.append_action("RENAME", item.storage_id, match.path, path)
                self.modified += 1
                return False
            # original path still exists
            if not item:
                # 2.b.1: Destination path does not exist
                if match.storage_id == self.storage_id:
                    # 2.b.1.a: hardlink on disk
                    self.path_hardlink(match.path, path)
                    self.add_db(path, lstat, match.sha1)
                else:
                    # 2.b.1.b: hardlink in db
                    self.append_action("LINK", match.storage_id, match.path, path)
                    self.add_db(path, lstat, match.sha1, match.storage_id)
            else:
                # 2.b.2: Destination path DOES exist
                if match.sha1 == item.sha1:
                    # 2.b.2.a: inode changed, but no data change
                    self.update_db(item, path, lstat)
                else:
                    if match.storage_id == self.storage_id:
                        # 2.b.2.b: Mismatch sha1, storage Id is same as current
                        if item.storage_id != self.storage_id:
                            self.append_action("DELETE", item.storage_id, path)
                        self.path_unlink(path)
                        self.path_hardlink(match.path, path)
                        self.update_db(match, path, lstat)
                    else:
                        # 2.b.2.c: Mismatch sha1, storage Id is different
                        self.append_action("DELETE", item.storage_id, path)
                        self.update_db(match, path, lstat)
                        self.append_action("LINK", item.storage_id, match.path, path)
            self.modified += 1
            return False
        # match is none
        if item:
            if not is_symlink:
                if item.size == lstat.st_size:
                    sha1 = calc_hash(path)
                    if sha1 == item.sha1:
                        # 3.a: hash match
                        self.update_db(item, path, lstat)
                        self.modified += 1
                        return False
            # if item.size != lstat.st_size or item.sha1 != sha1
            if item.storage_id == self.storage_id:
                # 3.b.1 or 4.a: Modified file
                sha1 = self.path_copy(path)
                self.update_db(item, path, lstat, sha1, self.storage_id)
            else:
                # 3.b.2 or 4.b: Modified file
                sha1 = self.path_copy(path)
                self.update_db(item, path, lstat, sha1, self.storage_id)
                self.append_action("DELETE", item.storage_id, path)
            self.modified += 1
            return needs_par2
        # 5: Path is not in db
        sha1 = self.path_copy(path)
        self.add_db(path, lstat, sha1)
        self.cur.execute(f"SELECT { ', '.join(FileObj._fields) } FROM files "
                         "WHERE sha1 = ? and size = ? and path != ?", (sha1, lstat.st_size, path))
        matches = [FileObj(*_) for _ in self.cur.fetchall()]
        if matches:
            match = next((_ for _ in matches if _.storage_id == self.storage_id), None)
            if match:
                # 5.a.1:
                os.unlink(self.storage_path(path))
                self.path_hardlink(match.path, path)
                self.update_db(match, path, lstat)
            else:
                # 5.a.2:
                os.unlink(self.storage_path(path))
                self.update_db(matches[0], path, lstat)
                self.append_action("LINK", matches[0].storage_id, matches[0].path, path)
            self.modified += 1
            return False
        self.added += 1
        return needs_par2

    def clean_storage(self, seen):
        """Delete any files on current storage that are no longer present"""
        remove = set()
        actions = []
        # Do not run any sql queries while iterating!
        for obj in self.cur.execute(f"SELECT { ', '.join(FileObj._fields) } FROM files"):
            item = FileObj(*obj)
            if item.path in seen:
                continue
            self.removed += 1
            if item.storage_id == self.storage_id:
                self.path_unlink(item.path)
                remove.add(item.path)
            else:
                actions.append(["DELETE", item.storage_id, item.path])
                remove.add(item.path)

        for path in remove:
            self.remove_db(path)
        for action in actions:
            self.append_action(*action)

def parse_exclude(exclusion_file):
    """Generate exclusion list in RE format"""
    exclude = []
    if exclusion_file:
        with open(exclusion_file) as _fh:
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
    exclude = parse_exclude(args.config)
    sqldb = sqlite3.connect(args.database)
    cur = sqldb.cursor()
    backup = Backup(cur, args.dest)
    try:
        schema = get_schema(cur)
        if schema != SCHEMA:
            upgrade_schema(cur, schema)
        backup.sync_storage_db()
        seen = set()
        for basepath in args.paths:
            backup.set_data_mount(basepath)
            for root, dirs, files in os.walk(basepath):
                filtered_dirs = []
                for dirname in dirs:
                    path = os.path.join(root, dirname)
                    if any(_exc.search(path) for _exc in exclude):
                        logging.debug("Excluding %s", path)
                        continue
                    filtered_dirs.append(path)
                dirs = filtered_dirs
                for fname in files:
                    path = os.path.join(root, fname)
                    if any(_exc.search(path) for _exc in exclude):
                        logging.debug("Excluding %s", path)
                        continue
                    if args.clean:
                        seen.add(path)
                    if backup.handle_path(path):
                        backup.calculate_par2(path)
        if args.clean:
            backup.clean_storage(seen)
        backup.write_storage_db()
    finally:
        sqldb.commit()
        sqldb.close()
    backup.show_summary()

if __name__ == "__main__":  # pragma: no cover
    main()
