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
import ctypes
import fnmatch
import glob
import hashlib
import json
import logging
import os
import re
import sqlite3
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid
import signal
import time
import multiprocessing

from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime

# pylint: disable=broad-except
# pylint: disable=unspecified-encoding
SCHEMA = 1

class Config:
    # PAR2_CREATE = "par2 c -r:PERCENT: -t:THREADS: :FILENAME:"
    PAR2_CREATE = ("parpar -s :BLOCKSIZE:b -r :PERCENT:% --slice-dist=pow2 -t:THREADS: "
                   "-o :FILENAME:.par2 :FILENAME:")
    DC3DD = "dc3dd"
    DC3DD_HLOG = f"/tmp/dc3dd.log.{ os.getpid() }"
    # ENCRYPT_CREATE = "securefs create --keyfile :KEYFILE: :ENCRYPT_DIR:"
    # ENCRYPT_MOUNT = ("securefs mount --keyfile :KEYFILE: "
    #                  ":ENCRYPT_DIR: :STORAGE_ROOT:")
    ENCRYPT_CREATE = "gocryptfs -init --passfile :KEYFILE: :ENCRYPT_DIR:"
    ENCRYPT_MOUNT = ("gocryptfs -fg --passfile :KEYFILE: :ENCRYPT_DIR: :STORAGE_ROOT:")
    ENCRYPT_MOUNT_RO = ("gocryptfs -fg -ro --passfile :KEYFILE: :ENCRYPT_DIR: :STORAGE_ROOT:")
    ENCRYPT_UNMOUNT = "fusermount -u :STORAGE_ROOT:"
    STORAGE_BACKUP_DB = ".backup_db.sqlite3"
    STORAGE_BACKUP_ID = ".backup_id"
    STORAGE_BACKUP_ENC = ".encrypt"
    STORAGE_BACKUP_DEC = "data"

FileObj = namedtuple("FileObj", ["path", "inode", "sha1", "time", "size", "storage_id"])
LStat = namedtuple("LStat", ["st_mode", "st_ino", "st_dev", "st_nlink", "st_uid", "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime"])

# Convert unsigned 64bit inodes to signed for sqlite3
#sqlite3.register_adapter(int, lambda i: (i + 2**63) % 2**64 - 2**63)
#sqlite3.register_converter('integer', lambda i: int(i) % 2**64)

class BackupException(Exception):
    """Base Exception"""

class DiskFullException(Exception):
    """Disk-Full Exception"""

class EncryptionException(Exception):
    """Encryption Exception"""

### Encryption handler
class Encrypt:
    """Manage encryption"""

    def __init__(self, storage_root, encryption_key, read_only=False):
        self.enc_proc = None
        self.storage_root = storage_root
        self.encryption_key = encryption_key
        self.read_only = read_only

        def signal_handler(_num, _stack):
            """Trigger an exception if the encryption process fails"""
            if self.enc_proc:
                logging.debug("Detected unexpected encryption termination")
                raise EncryptionException("Encryption process failed")

        signal.signal(signal.SIGURG, signal_handler)

    def __del__(self):
        """Cleanup"""
        self.stop()

    def stop(self):
        """Shutdown encryption process"""
        if self.enc_proc:
            encrypt_dir = os.path.join(self.storage_root, Config.STORAGE_BACKUP_ENC)
            decrypt_dir = os.path.join(self.storage_root, Config.STORAGE_BACKUP_DEC)
            cmd = self.apply_enc_vars(Config.ENCRYPT_UNMOUNT, "None", encrypt_dir, decrypt_dir)
            logging.debug("Running encryption unmount: %s", " ".join(cmd))
            try:
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception:
                pass
            try:
                logging.debug("Sending kill signal to encryption")
                self.enc_proc.terminate()
            except Exception:
                pass
            try:
                logging.debug("Waiting for encryption termination")
                self.enc_proc.join()
            except Exception:
                pass
            logging.debug("Encryption stopped")
            self.enc_proc = None

    @staticmethod
    def _start_encryption(pid, command):
        """Execute encryption in a background process"""
        try:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except Exception:
            os.kill(pid, signal.SIGURG)

    @contextmanager
    def create_keyfile(self):
        """Context manager with keyfile created"""
        with tempfile.TemporaryDirectory() as _td:
            keyfile = os.path.join(_td, "keyfile")
            with open(keyfile, "w") as _fh:
                _fh.write(self.encryption_key)
            yield keyfile

    @staticmethod
    def apply_enc_vars(command, keyfile, encrypt_dir, decrypt_dir):
        """Encryption variable replacement"""
        return (command.replace(':KEYFILE:', keyfile)
                .replace(':ENCRYPT_DIR:', encrypt_dir)
                .replace(':STORAGE_ROOT:', decrypt_dir).split())

    def setup_encryption(self):
        """Setup encryption (if requested)"""
        encrypt_dir = os.path.join(self.storage_root, Config.STORAGE_BACKUP_ENC)
        decrypt_dir = os.path.join(self.storage_root, Config.STORAGE_BACKUP_DEC)
        storage_db = os.path.join(self.storage_root, Config.STORAGE_BACKUP_DB)
        if not os.path.lexists(encrypt_dir):
            if not self.encryption_key:
                return self.storage_root
            if os.path.lexists(storage_db) or glob.glob(os.path.join(self.storage_root,"*")):
                raise BackupException(f"Volume {self.storage_root} already contains "
                                      "unencrypted data, but encryption was requested")
            with self.create_keyfile() as keyfile:
                create_cmd = self.apply_enc_vars(Config.ENCRYPT_CREATE,
                                                 keyfile, encrypt_dir, decrypt_dir)
                logging.debug("Creating encrypted mount: %s", " ".join(create_cmd))
                try:
                    os.mkdir(encrypt_dir)
                    subprocess.run(create_cmd, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
                    os.mkdir(decrypt_dir)
                except Exception as _e:
                    raise EncryptionException(
                        f"Failed to create encrypted mount: {str(_e)}") from _e

        # if os.path.lexists(encrypt_dir)
        if not self.encryption_key:
            raise BackupException(f"Volume {self.storage_root} is an encrypted volume, "
                                  "but no encryption key specified")
        if os.path.ismount(decrypt_dir):
            raise BackupException(f"Encrypted volume {decrypt_dir} is already mounted. "
                                  "Unmount before rerunning")
        # This isn't secure, but it isn't meant to be
        with self.create_keyfile() as keyfile:
            encrypt_mount = Config.ENCRYPT_MOUNT_RO if self.read_only else Config.ENCRYPT_MOUNT
            mount_cmd = self.apply_enc_vars(encrypt_mount, keyfile, encrypt_dir, decrypt_dir)
            logging.debug("Mounting encrypted dir: %s", " ".join(mount_cmd))
            self.enc_proc = multiprocessing.Process(
                target=self._start_encryption,
                args=(os.getpid(), mount_cmd))
            self.enc_proc.daemon = True
            self.enc_proc.start()
            retry = 30
            while retry and not os.path.ismount(decrypt_dir):
                time.sleep(0.2)
                retry -= 1
            if not retry:
                self.enc_proc.terminate()
                raise EncryptionException("Failed to mount encrypted dir {encrypt_dir}")
            logging.debug("Encrypted mount complete")
        return decrypt_dir

class Par2Queue:
    """Run Par2 threads"""

    def __init__(self, threads, threshold):
        """Initialize"""
        self.fast_count = threads
        self.slow_threads = threads
        self.threshold = threshold
        self.desired_block_count = 2000  # From par2cmdline
        self.percent = 10
        self.jobs = {}
        self.jobs_by_fname = {}
        self.fast_jobs = set()
        self.slow_job = None

    def _wait_finish(self, pid, waitcode):
        size = 0
        if pid not in self.jobs:
            return 0
        retcode = os.waitstatus_to_exitcode(waitcode)
        if retcode:
            raise BackupException(f"Failed PAR2 Run: {self.jobs[pid][0]}")
        if pid == self.slow_job:
            self.slow_job = None
        elif pid in self.fast_jobs:
            self.fast_jobs.remove(pid)
        else:
            breakpoint()
            raise BackupException(f"Got invalid PAR2 pid '{pid}")
        logging.debug("Completed PAR2 Job: %s", self.jobs[pid][0])
        path = self.jobs[pid][1]
        if os.path.exists(path + ".par2"):
            lstat_p = blaine_lstat(path + ".par2")
            size += lstat_p.st_size
            for par2path in glob.glob(f"{ path }.vol*.par2"):
                lstat_p = blaine_lstat(par2path)
                size += lstat_p.st_size
        del self.jobs[pid]
        del self.jobs_by_fname[path]
        return size

    def _wait(self, fast):
        """Wait if too many jobs are running"""
        size = 0
        while (fast and len(self.fast_jobs) >= self.fast_count) or self.slow_job:
            pid, waitcode = os.wait()
            size += self._wait_finish(pid, waitcode)
        return size

    def _run(self, cmd, fname):
        """Run Par2 in its own thread"""
        pid = os.fork()
        if pid:
            # Original process
            self.jobs[pid] = (" ".join(cmd), fname)
            return pid
        # New process
        os.closerange(0, 10)
        os.open(os.devnull, os.O_RDWR) # standard input (0)
        os.open(os.devnull, os.O_WRONLY|os.O_TRUNC|os.O_CREAT) # standard output (1)
        os.open(os.devnull, os.O_WRONLY|os.O_TRUNC|os.O_CREAT) # standard error (2)

        os.execlp(cmd[0], *cmd)
        os._exit(1)  # pylint: disable=protected-access
        return None

    def _calc_blocks(self, size):
        return (((size // self.desired_block_count) + 3) & (~3)) or 4

    def create(self, fname):
        """Run par2 create"""
        try:
            lstat = blaine_lstat(fname)
            size = lstat.st_size
        except Exception:
            return 0
        block_size = self._calc_blocks(size)
        threads = self.slow_threads if size > self.threshold else 1
        cmdline = [_
                   .replace(':FILENAME:', fname) \
                   .replace(':PERCENT:', str(self.percent)) \
                   .replace(':BLOCKSIZE:', str(block_size))
                   .replace(':THREADS:', str(threads))
                   for _ in Config.PAR2_CREATE.split()]
        if size > self.threshold:
            completed_bytes = self._wait(fast=False)
            pid = self._run(cmdline, fname)
            self.jobs_by_fname[fname] = pid
            self.slow_job = pid
        else:
            completed_bytes = self._wait(fast=True)
            pid = self._run(cmdline, fname)
            self.jobs_by_fname[fname] = pid
            self.fast_jobs.add(pid)
        return completed_bytes

    def wait_file(self, fname):
        """Wait for a specific job to complete"""
        if fname in self.jobs_by_fname:
            pid, waitcode = os.waitpid(self.jobs_by_fname[fname], 0)
            return self._wait_finish(pid, waitcode)
        return 0

    def join(self):
        """Wait for all par2 jobs to complete"""
        size = 0
        self.fast_count = 1
        while self.jobs:
            try:
                size += self._wait(fast=True)
            except BackupException as _e:
                breakpoint()
                logging.error(_e)
                break
        return size

def blaine_lstat(path):
    _l = os.lstat(path)
    return LStat(
        st_mode=_l.st_mode,
        st_ino=ctypes.c_int64(_l.st_ino).value,
        st_dev=_l.st_dev,
        st_nlink=_l.st_nlink,
        st_uid=_l.st_uid,
        st_gid=_l.st_gid,
        st_size=_l.st_size,
        st_atime=_l.st_atime,
        st_mtime=_l.st_mtime,
        st_ctime=_l.st_ctime)

def get_schema(cur):
    """Fetch current DB schema"""
    cur.execute("CREATE TABLE IF NOT EXISTS settings (key PRIMARY KEY, value)")
    cur.execute("SELECT value FROM settings WHERE key = 'schema'")
    schema = cur.fetchone()
    return schema[0] if schema else 0

def upgrade_schema(cur, old_schema):
    """Create/upgrade DB schema"""
    cur.execute("SELECT file FROM pragma_database_list WHERE name='main'")
    logging.debug("Upgrading schema of %s from %d to %d", cur.fetchone()[0], old_schema, SCHEMA)
    if old_schema == 0:
        cur.execute("CREATE TABLE files "
                    "(path TEXT PRIMARY KEY, inode INT, sha1, time INT, size INT, storage_id)")
        cur.execute("CREATE TABLE actions "
                    "(id INTEGER PRIMARY KEY AUTOINCREMENT, storage_id, action, path, target_path)")
    else:
        raise BackupException(f"Unsupported old schema: {old_schema}")
    cur.execute(f"REPLACE INTO settings (key, value) VALUES('schema', { SCHEMA })")

def run_dc3dd(src, dest):
    """Use dc3dd to do a copy + calc SHA1"""
    try:
        os.unlink(Config.DC3DD_HLOG)
    except FileNotFoundError:
        pass
    subprocess.run([Config.DC3DD, f"if={ src }", f"of={ dest }", "hash=sha1", "nwspc=on",
                    f"hlog={ Config.DC3DD_HLOG }"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    with open(Config.DC3DD_HLOG) as _fh:
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


def _set_storage_id(storage_root, create=False):
    """Read existing storage id, or generate a new one"""
    id_file = os.path.join(storage_root, Config.STORAGE_BACKUP_ID)
    if os.path.exists(id_file):
        with open(id_file) as _fh:
            return _fh.readline().strip()
    elif create:
        with open(id_file, "w") as _fh:
            storage_id = str(uuid.uuid4())
            _fh.write(storage_id)
        return storage_id
    raise BackupException("Storage area is not initialized")

def get_storage_free(storage_root):
    """Determine free space of the archive disk"""
    stvfs = os.statvfs(storage_root)
    free  = (stvfs.f_bavail * stvfs.f_frsize)
    free_inode = stvfs.f_ffree
    return free, free_inode


class Blaine:
    """Execute a backup"""
    # pylint: disable = too-many-instance-attributes too-many-arguments
    def __init__(self, cur, storage_dir, init=False, reserved_space=None, parity_pct=None, encrypt=None,
                 par2_threads=None, par2_threshold=10_000_000, dry_run=False, logger=None):
        """Initialize"""
        self.skipped = 0
        self.added = 0
        self.removed = 0
        self.modified = 0
        self.cur = cur
        self.dry_run = dry_run
        self.log = logger or self.logger
        self.encrypt = Encrypt(storage_dir, encrypt, read_only=dry_run)
        self.par2q = Par2Queue(par2_threads, par2_threshold)
        self.storage_root = self.encrypt.setup_encryption()
        self.storage_id = _set_storage_id(storage_dir, init)
        self.storage_added = 0
        self.storage_reserved = 10_000_000_000 if reserved_space is None else reserved_space
        self.inodes_reserved = 1000
        self.parity_ratio = 1 + (10 if parity_pct is None else parity_pct) / 100
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
        logging.info("Space consumed:  %d bytes", self.storage_added)

    @staticmethod
    def logger(action, path1, path2=None):
        action_map = {
            "DELETE": "Deleting",
            "RENAME": "Renaming",
            "HARDLINK": "Hardlinking",
            "COPY": "Copying",
            "SYMLINK": "Symlinking",
            "PAR2": "Creating par files for",
            }
        if path2:
            logging.debug("%s %s to %s", action_map.get(action, action), path1, path2)
        else:
            logging.debug("%s %s", action_map.get(action, action), path1)

    def storage_path(self, path):
        """Determine the path on the storage disk for a given path"""
        if path[0] == os.path.sep:
            path = path[1:]
        return os.path.join(self.storage_root, path)

    def path_rename(self, origpath, newpath):
        """Rename path on storage disks (and update par2 files)"""
        origpath = self.storage_path(origpath)
        newpath = self.storage_path(newpath)
        self.log("RENAME", origpath, newpath)
        if self.dry_run:
            return
        try:
            os.rename(origpath, newpath)
            if os.path.exists(origpath + ".par2"):
                os.rename(origpath + ".par2", newpath + ".par2")
                for path in glob.glob(f"{ origpath }.vol*.par2"):
                    npath = newpath + path[len(origpath):]
                    os.rename(path, npath)
        except Exception as _e:
            raise BackupException(f"Failed to rename {origpath} -> {newpath}: {str(_e)}") from _e

    def path_hardlink(self, origpath, newpath):
        """Hardlink path on storage disks (and update par2 files)"""
        _free, free_inodes = get_storage_free(self.storage_root)
        if free_inodes < self.inodes_reserved:
            raise DiskFullException(f"Disk {self.storage_root}  has run out of inodes")
        origpath = self.storage_path(origpath)
        newpath = self.storage_path(newpath)
        self.storage_added += self.par2q.wait_file(origpath)
        self.log("HARDLINK", origpath, newpath)
        if self.dry_run:
            return
        try:
            os.makedirs(os.path.dirname(newpath), exist_ok=True)
            os.link(origpath, newpath)
            if os.path.exists(origpath + ".par2"):
                os.link(origpath + ".par2", newpath + ".par2")
                for path in glob.glob(f"{ origpath }.vol*.par2"):
                    npath = newpath + path[len(origpath):]
                    os.link(path, npath)
        except Exception as _e:
            for _p in newpath, newpath + ".par2", glob.glob(f"{ newpath }.vol*.par2"):
                try:
                    os.unlink(newpath)
                except Exception:
                    pass
            raise BackupException(f"Failed to hardlink {origpath} -> {newpath}: {str(_e)}") from _e

    def path_unlink(self, path, lstat=None):
        """Remove path on storage disks (and remove par2 files)"""
        path = self.storage_path(path)
        if not os.path.lexists(path):
            return
        self.log("DELETE", path)
        if self.dry_run:
            return
        if not lstat:
            lstat = blaine_lstat(path)
        try:
            os.unlink(path)
            self.storage_added -= lstat.st_size
            self.rm_par2(path)
        except Exception as _e:
            raise BackupException(f"Failed to delete {path}: {str(_e)}") from _e

    def path_copy(self, path, lstat):
        """Copy path from original location to storage disk and calculate sha1
           (but don't calculate par2)"""
        free, free_inodes = get_storage_free(self.storage_root)
        if free < lstat.st_size * self.parity_ratio + self.storage_reserved:
            raise DiskFullException(f"File {path} won't fit on storage disk {self.storage_root}")
        if free_inodes < self.inodes_reserved:
            raise DiskFullException(f"Disk {self.storage_root}  has run out of inodes")
        dest = self.storage_path(path)
        self.log("COPY", path, dest)
        if self.dry_run:
            if os.path.islink(path):
                sha1 = calc_symlink_hash(path)
            else:
                sha1 = calc_hash(path)
            self.storage_added += lstat.st_size
            return sha1
        try:
            if os.path.exists(dest):
                self.path_unlink(path)
            else:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
            if os.path.islink(path):
                link = os.readlink(path)
                os.symlink(link, dest)
                sha1 = calc_symlink_hash(path)
            else:
                sha1 = run_dc3dd(path, dest)
                # Python doesn't provide 'lutime' function, so no easy way to update symlinks
                try:
                    os.chown(dest, lstat.st_uid, lstat.st_gid,
                             follow_symlinks=False)
                except Exception:
                    pass
                os.utime(dest, (lstat.st_atime, lstat.st_mtime))
            self.storage_added += lstat.st_size
        except Exception as _e:
            try:
                os.unlink(dest)
            except Exception:
                pass
            breakpoint()
            raise BackupException(f"Failed to copy {path} -> {dest}: {str(_e)}") from _e
        return sha1

    def rm_par2(self, storage_path):
        """Remove par2 files, and update stats"""
        if self.dry_run:
            return
        if os.path.exists(storage_path + ".par2"):
            lstat_p = blaine_lstat(storage_path + ".par2")
            os.unlink(storage_path + ".par2")
            self.storage_added -= lstat_p.st_size
        for par2path in glob.glob(f"{ storage_path }.vol*.par2"):
            lstat_p = blaine_lstat(par2path)
            os.unlink(par2path)
            self.storage_added -= lstat_p.st_size

    def calculate_par2(self, path):
        """Run PAR2 on path to generate extra parity"""
        path = self.storage_path(path)
        self.log("PAR2", path)
        if self.dry_run:
            return
        try:
            self.rm_par2(path)
            self.storage_added += self.par2q.create(path)
        except Exception as _e:
            raise BackupException(f"Failed to create par2 files for {path}: {str(_e)}") from _e

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
        logging.debug("Applying deferred action to %s: %s %s%s",
                      storage_id, action, path1, (f" to {path2}" if path2 else ""))
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
        storage_db = os.path.join(self.storage_root, Config.STORAGE_BACKUP_DB)
        if not os.path.exists(storage_db):
            return
        sqldb = sqlite3.connect(storage_db,
                                detect_types=sqlite3.PARSE_DECLTYPES)
        s_cur = sqldb.cursor()
        old_schema = get_schema(s_cur)
        if old_schema != SCHEMA:
            upgrade_schema(s_cur, old_schema)
        logging.debug("Syncing storage for %s (%s)", self.storage_id, storage_db)
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

    def get_storage_db_file(self):
        """Get path to starage db file"""
        return os.path.join(self.storage_root, Config.STORAGE_BACKUP_DB)

    def write_storage_db(self):
        """Write the relevant files data for the current storage disk to the storage-local db"""
        storage_db = self.get_storage_db_file()
        logging.debug("Writing updated storage for %s (%s)", self.storage_id, storage_db)
        if not os.path.exists(storage_db):
            sqldb = sqlite3.connect(storage_db,
                                    detect_types=sqlite3.PARSE_DECLTYPES)
            s_cur = sqldb.cursor()
            get_schema(s_cur)         # ensures 'settings' table exists
            upgrade_schema(s_cur, 0)
            sqldb.commit()
            sqldb.close()
        else:
            backup_db(storage_db)
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
        lstat = blaine_lstat(path)
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
            try:
                self.cur.execute(
                    f"SELECT { ', '.join(FileObj._fields) } FROM files "
                    "WHERE inode = ? AND path LIKE ?", (lstat.st_ino, self.data_mount + '%'))
            except:
                breakpoint()
                raise
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
        if match:  # 'match' contains an item wth a different name but same inode & size
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
                            self.path_unlink(path, lstat)
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
                        self.path_unlink(path, lstat)
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
                sha1 = self.path_copy(path, lstat)
                self.update_db(item, path, lstat, sha1, self.storage_id)
            else:
                # 3.b.2 or 4.b: Modified file
                sha1 = self.path_copy(path, lstat)
                self.update_db(item, path, lstat, sha1, self.storage_id)
                self.append_action("DELETE", item.storage_id, path)
            self.modified += 1
            return needs_par2
        # 5: Path is not in db
        sha1 = self.path_copy(path, lstat)
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

    def clean_storage(self, seen, paths):
        """Delete any files on current storage that are no longer present"""
        remove = set()
        actions = []
        logging.debug("Deleting unseen items from database")
        # Do not run any sql queries while iterating!
        for obj in self.cur.execute(f"SELECT { ', '.join(FileObj._fields) } FROM files"):
            item = FileObj(*obj)
            if item.path in seen or not any(item.path.startswith(_) for _ in paths):
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

def simple_table(data, header=None):
    if not data:
        return
    if header:
        col_len = [len(_) for _ in header]
    else:
        col_len = [0 for _ in data[0]]
    max_len = len(col_len)
    for item in data:
        col_len = [max(_, len(str(item[i]))) for i, _ in enumerate(col_len)]
    row_fmt = "".join([f"%{_+4 if i > 0 else -(_+4)}s" for i, _ in enumerate(col_len)])
    if header:
        print(row_fmt % tuple(header))
    for item in data:
        print(row_fmt % tuple(item[:max_len]))

def backup_db(db_file):
    """Create a backup of db_file"""
    if not os.path.exists(db_file):
        return
    basedir, fname = os.path.split(db_file)
    backup_dir = os.path.join(basedir, ".backup_db.old")
    mtime = os.stat(db_file).st_mtime
    outfile = os.path.join(backup_dir, f"{fname}.{datetime.fromtimestamp(mtime).isoformat()}")
    if os.path.exists(outfile):
        return
    if not os.path.exists(backup_dir):
        os.mkdir(backup_dir)
    shutil.copyfile(db_file, outfile)

def connect_db(db_file, read_only=False):
    """Connect to the database and return a cursor"""
    uri = f'file:{db_file}'
    if read_only:
        uri += "?mode=ro"
    sqldb = sqlite3.connect(uri, uri=True,
                            detect_types=sqlite3.PARSE_DECLTYPES)
    return sqldb.cursor()

def parse_exclude(exclusion_file):
    """Generate exclusion list in RE format"""
    exclude_dirs = []
    exclude_files = []
    if exclusion_file:
        with open(exclusion_file) as _fh:
            for line in _fh.readlines():
                if line.startswith("exclude"):
                    pattern = line.strip().split(None, 1)[-1]
                    if pattern[-1] == '/':
                        res = fnmatch.translate(pattern[:-1])
                        logging.debug("Adding exclusion for: %s", res)
                        exclude_dirs.append(re.compile(res))
                    else:
                        res = fnmatch.translate(pattern)
                        logging.debug("Adding exclusion for: %s", res)
                        exclude_files.append(re.compile(res))
    return (exclude_dirs, exclude_files)

def parse_config(configfile, remaining_argv, parser):
    """Parse config file"""
    parser_args = {}
    defaults = {}
    for cmd_parser in [parser] + list(parser._subparsers._group_actions[0].choices.values()):
        parser_args[cmd_parser] = [_.dest for _ in cmd_parser._actions]
        defaults[cmd_parser] = {}
    with open(configfile, "rb") as _fh:
        config = tomllib.load(_fh)
    for key in config:
        try:
            if getattr(Config, key.upper()):
                setattr(Config, key.upper(), config[key])
        except AttributeError:
            seen = False
            for cmd_parser, args in parser_args.items():
                if key in args:
                    defaults[cmd_parser][key] = config[key]
                    seen = True
            if not seen:
                logging.warning("Ignoring invalid config key: %s", key)
    for cmd_parser, items in defaults.items():
        cmd_parser.set_defaults(**items)
        for action in cmd_parser._actions:
            if action.dest in items:
                action.required = False


def parse_cmdline():
    """Parse cmdline args"""
    # From https://stackoverflow.com/questions/3609852/
    #      which-is-the-best-way-to-allow-configuration-options-be-overridden-at-the-comman
    conf_parser = argparse.ArgumentParser(
        description=__doc__, # printed with -h/--help
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Turn off help, so we print all options in response to -h
        add_help=False
        )
    conf_parser.add_argument("-c", "--config_file",
                        help="Specify config file", metavar="FILE")
    common = argparse.ArgumentParser(add_help=False, parents=[conf_parser])
    common.add_argument("--verbose", action='store_true', help="Increate logging level")
    common.add_argument("--encrypt", metavar='KEY', help="Enable encryption, using specificed key")
    common.add_argument("--logfile", help="Write to logfile")
    parser = argparse.ArgumentParser(
        # Inherit options from config_parser
        parents=[common]
        )
    subparsers = parser.add_subparsers(required=True)
    for subparser in (Backup, List):
        subparser.add_parser(subparsers, common)
    args, remaining_argv = conf_parser.parse_known_args()
    if args.config_file:
        parse_config(args.config_file, remaining_argv, parser)
    args = parser.parse_args(remaining_argv)
    handlers = [logging.StreamHandler()]
    if args.logfile:
        handlers.append(logging.FileHandler(args.logfile))
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.DEBUG,
        handlers=handlers)
    if not args.verbose:
        logging.getLogger().handlers[0].level = logging.INFO
    logging.debug("Running: %s", " ".join(_ if ' ' not in _ else f"'{_}'" for _ in sys.argv))

    return args

class Backup:
    """backup subcommand"""
    @classmethod
    def add_parser(cls, parser, common):
        p_backup = parser.add_parser("backup", parents=[common], help="Run backup")
        p_backup.set_defaults(func=cls.run)
        p_backup.add_argument('paths', metavar='PATH', nargs='+', help='Paths to archive')
        p_backup.add_argument("--snapraid_conf", help="Snapraid config file (used for automatic file exclusions)")
        p_backup.add_argument("--database", "--db", required=True, help="path to database")
        p_backup.add_argument("--blaine_dir", "--dest_dir", required=True, help="Directory to write files to")
        p_backup.add_argument("--init", action="store_true", help="Initialize new storage disk")
        p_backup.add_argument("--dry_run", action="store_true", help="Don't apply any changes")
        p_backup.add_argument("--par2_threads", "--threads", default=multiprocessing.cpu_count(),
                        type=int,  help="Enable encryption, using specificed key")
        p_backup.add_argument("--par2_threshold", default=10_000_000, type=int,
                            help="Files larger than this use a single multi-threaded par2 call instead"
                                 " of using multiple single-threaded par2 calls")
        p_backup.add_argument("--clean", dest='clean', action='store_true',
                            help="Remove files from backup-storage that no longer exist in the data-set")

    @classmethod
    def run(cls, args):
        exclude = parse_exclude(args.snapraid_conf)
        cur = None
        tmpdir = None
        if args.dry_run:
            tmpdir = tempfile.TemporaryDirectory()
            tmpdb = f"{tmpdir.name}/database.sqlite"
        if os.path.exists(args.database):
            if args.dry_run:
                shutils.copyfile(args.database, tmpdb)
                cur = connect_db(tmpdb)
            else:
                backup_db(args.database)
                cur = connect_db(args.database)
        backup = None
        ok_ = False
        try:
            backup = Blaine(cur, args.blaine_dir, init=args.init, encrypt=args.encrypt,
                            par2_threads=args.par2_threads, par2_threshold=args.par2_threshold,
                            dry_run=args.dry_run)
            if not cur:
                dbfile = backup.get_storage_db_file()
                if os.path.exists(dbfile):
                    logging.warning("Did not find database %s.  Using database from backup", args.database)
                    if args.dry_run:
                        shutil.copyfile(dbfile, tmpdb)
                    else:
                        shutil.copyfile(dbfile, args.database)
                if not args.dry_run:
                    backup_db(args.database)
                    backup.cur = cur = connect_db(args.database)
                else:
                    backup.cur = cur = connect_db(tmpdb)
            schema = get_schema(cur)
            if schema != SCHEMA:
                upgrade_schema(cur, schema)
            backup.sync_storage_db()
            seen = set()
            args.paths = [os.path.abspath(_) for _ in args.paths]
            for basepath in args.paths:
                cls.backup_path(backup, basepath, exclude, seen)
            if args.clean:
                backup.clean_storage(seen, args.paths)
            else:
                for path in sorted(seen):
                    logging.warning("File %s no longer exists, but was not removed from the database", path)
            backup.write_storage_db()
            ok_ = True
        except KeyboardInterrupt:
            backup.write_storage_db()
        except DiskFullException as _e:
            logging.error(_e)
        except (BackupException, EncryptionException) as _e:
            logging.error(_e)
            raise
        finally:
            if cur:
                cur.connection.commit()
                cur.connection.close()
            if backup:
                backup.storage_added += backup.par2q.join()
                backup.encrypt.stop()
        if backup:
            backup.show_summary()
        return ok_

    @staticmethod
    def backup_path(backup, basepath, exclude, seen):
        """Run backup on a directory"""
        backup.set_data_mount(basepath)
        exclude_dirs, exclude_files = exclude
        for root, dirs, files in os.walk(basepath):
            filtered_dirs = []
            for dirname in sorted(dirs):
                path = os.path.join(root, dirname)
                if any(_exc.search(path) for _exc in exclude_dirs):
                    logging.debug("Excluding %s", path)
                    continue
                filtered_dirs.append(path)
            dirs[:] = filtered_dirs
            for fname in sorted(files):
                path = os.path.join(root, fname)
                if any(_exc.search(path) for _exc in exclude_files):
                    logging.debug("Excluding %s", path)
                    continue
                seen.add(path)
                if backup.handle_path(path):
                    backup.calculate_par2(path)


class List:
    """List subcommand"""
    @classmethod
    def add_parser(cls, parser, common):
        p_list = parser.add_parser("list", parents=[common], help="List backed-up files")
        p_list.set_defaults(func=cls.run)
        p_list.add_argument('filter', metavar='PATH', nargs='*', help="Paths to list (use glob syntax.  Note that '*' will match '/' too)")
        p_list.add_argument("--database", "--db", help="path to database")
        p_list.add_argument("--blaine_dir", help="Path to archive")
        p_list.add_argument("--local", action="store_true", help="Show only files available on mounted storage")
        p_list.add_argument("--volumes", nargs="+", default=[], help="Show only files from specified volumes")
        p_list.add_argument("--iso8601", action="store_true", help="Print file date in ISO8601 format")
        p_list.add_argument("--no-vol", dest="vol", action="store_false", default=True,
                            help="Don't print the volume containing each file")
        p_list.add_argument("-1", dest="path_only", action="store_true", help="Only print filename")
        p_list.add_argument("--sort", choices=["path", "mtime", "size", "vol"], help="Sort output")
        p_list.add_argument("--reverse", action="store_true", help="Reverse sort order")
        p_list.add_argument("--json", action="store_true", help="Output in JSON format")

    @staticmethod
    def run(args):
        cur = None
        backup = None
        if not args.database and not args.blaine_dir:
            logging.error("Must specify one of --database or --blaine_dir")
            return False
        if args.database and os.path.exists(args.database):
            cur = connect_db(args.database, read_only=True)
        try:
            backup = Blaine(cur, args.blaine_dir, encrypt=args.encrypt, dry_run=True)
            if not cur:
                dbfile = backup.get_storage_db_file()
                if not os.path.exists(dbfile):
                    logging.error("No database specified, and no database found in backup area")
                    return False
                backup.cur = cur = connect_db(dbfile, read_only=True)
            sql = "SELECT path, size, time, storage_id FROM files"
            where = []
            sqlvars = []
            if args.local and backup:
                where.append("storage_id = ?")
                sqlvars.append(backup.storage_id)
            if args.filter:
                where.append("(" + " OR ".join(f"(path GLOB ?)" for _ in args.filter) + ")")
                sqlvars.extend(args.filter)
            if args.volumes:
                where.append("(" + " OR ".join(f"(storage_id LIKE ?)" for _ in args.volumes) + ")")
                sqlvars.extend(f"{_}%" for _ in args.volumes)
            if where:
                sql += " WHERE " + " AND ".join(where)
            if args.sort:
                sort_map = {"path": "path", "size": "size", "mtime": "time", "volume": "storage_id"}
                sort = sort_map[args.sort]
            else:
                sort = "path"
            sql += f" ORDER BY {sort}"
            if args.reverse:
                sql += " DESC"
            cur.execute(sql, sqlvars)
            items = []
            year = datetime.now().year
            for path, size, mtime, vol in cur.fetchall():
                if args.json:
                    items.append({
                        'path': path,
                        'size': size,
                        'mtime': datetime.fromtimestamp(mtime).isoformat(),
                        'volume': vol})
                    continue
                if args.path_only:
                    items.append((path,))
                    continue
                mtime = datetime.fromtimestamp(int(mtime))
                if args.iso8601:
                    mtime = mtime.isoformat()
                elif mtime.year == year:
                    mtime = mtime.strftime("%b %d %H:%M")
                else:
                    mtime = mtime.strftime("%b %d %Y")
                items.append((path, size, mtime, vol))
            if args.json:
                print(json.dumps(items))
            else:
                if  args.path_only:
                    for _ in items:
                        print(_)
                else:
                    header = ["path", "size", "modified"] + (["volume"] if args.vol else [])
                    simple_table(items, header=header)
        except BackupException as _e:
            logging.error(str(_e))
            return False
        finally:
            if cur:
                cur.connection.close()
            if backup:
                backup.encrypt.stop()


def main():
    """Entrypoint"""
    args = parse_cmdline()
    return args.func(args)

if __name__ == "__main__":  # pragma: no cover
    sys.exit(0 if main() else 1)
