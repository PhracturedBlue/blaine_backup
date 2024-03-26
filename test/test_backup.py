import logging
import os
import sys
import hashlib
import json
import shutil
import tempfile
import uuid
import sqlite3
import subprocess
from contextlib import contextmanager
from collections import namedtuple

import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import blaine

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
EXCLUDE_FILE = os.path.join(DATA_DIR, "snapraid.conf")
STORAGE_DIRS = [
  {'ID': None, 'PATH': None},   # Used for common storage
  {'ID': "archive1-e35d-45ee-a085-d9eddf7152ca", 'PATH': None},
  {'ID': "archive2-3dcc-49e9-a70e-8f6499426986", 'PATH': None},
  # These are gocryptfs/parpar copies of the above
  {'ID': "archive1-e35d-45ee-a085-d9eddf7152ca", 'PATH': None},
  {'ID': "archive2-3dcc-49e9-a70e-8f6499426986", 'PATH': None},
  # These are securefs/par2 copies of the above
  {'ID': "archive1-e35d-45ee-a085-d9eddf7152ca", 'PATH': None},
  {'ID': "archive2-3dcc-49e9-a70e-8f6499426986", 'PATH': None},
]
INODE_MAP = {'last': 1000}
    
@pytest.fixture(scope='function', autouse=True)
def setup_archive():
    for storage in STORAGE_DIRS:
        if storage['PATH'] == None:
            storage['TDOBJ'] = tempfile.TemporaryDirectory()
            storage['PATH'] = storage['TDOBJ'].name
        if storage['ID']:
            with open(os.path.join(storage['PATH'], ".backup_id"), "w") as _fh:
                _fh.write(storage['ID'])
    yield
    for obj in STORAGE_DIRS:
        del obj['TDOBJ']
        obj['PATH'] = None

def prepare_stage(stage_num, clean=False):
    """Ensure hardlinks are created since git can't store them"""
    orig_dir = os.path.join(DATA_DIR, f'stage{ stage_num }')
    dest_dir = os.path.join(STORAGE_DIRS[0]['PATH'], "archive")
    if clean:
        INODE_MAP.clear()
        INODE_MAP['last'] = 1000
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        try:
            os.unlink(os.path.join(STORAGE_DIRS[0]['PATH'], "archive.sqlite3"))
        except:
            pass
    if not os.path.exists(dest_dir):
        shutil.copytree(orig_dir, dest_dir, symlinks=True, ignore_dangling_symlinks=True)
    else:
        os.rename(dest_dir, dest_dir + ".tmp")
        shutil.copytree(orig_dir, dest_dir, symlinks=True, ignore_dangling_symlinks=True)
        # check for unchanged files and create hardlinks such that same-files
        # maintain the same inode
        for root, dirs, files in os.walk(dest_dir):
            for fname in files:
                if ".hardlink." in fname:
                    continue
                path = os.path.join(root, fname)
                if ".rename_from." in fname:
                    # create a hardlink from the original name in the previous stage to the new-name in the current stage
                    prev_path = os.path.join(root, fname.split('.rename_from.')[-1])
                    prev_path = prev_path.replace(dest_dir, dest_dir + ".tmp")
                    rename_to = os.path.join(root, fname.split('.rename_from.')[0])
                    os.unlink(path)
                    os.link(prev_path, rename_to)
                    continue
                prev_path = path.replace(dest_dir, dest_dir + ".tmp")
                if (not path.endswith('.nolink') and os.path.exists(prev_path) and 
                        os.system(f"diff -q { prev_path } { path } > /dev/null") == 0):
                    # previous stage and current stage have the same file with the same contents, so replace with a hardlink
                    os.unlink(path)
                    os.link(prev_path, path)
        shutil.rmtree(dest_dir + ".tmp")
    # replace '+' with '.', replace : with '/'
    for root, _dirs, files in os.walk(dest_dir):
        for fname in files:
            if ".hardlink." not in fname:
                continue
            base_name, link_path = fname.split('.hardlink.')
            link_path = link_path.replace('+', '.').replace(':', '/')
            orig_path = os.path.abspath(os.path.join(root, link_path))
            new_path = os.path.join(root, base_name)
            path = os.path.join(root, fname)
            os.unlink(path)
            os.link(orig_path, new_path)

@contextmanager
def do_encrypt(encryption_key, storage_dir):
    if not encryption_key:
        yield storage_dir
        return
    enc = blaine.Encrypt(storage_dir, encryption_key)
    try:
        yield enc.setup_encryption()
    finally:
        enc.stop()

def verify_db(db_file, expected_file, storage_id=None):
    """Verify that the database matches the expected state"""
    def dict_factory(cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            val = row[idx]
            if col[0] == 'time':
                continue  # Don't compare time, since it is not persistent
            if col[0] == 'inode':
                if val not in INODE_MAP:
                    INODE_MAP[val] = INODE_MAP['last']
                    INODE_MAP['last'] += 1
                val = INODE_MAP[val]
            elif col[0] in ('path', 'target_path'):
                val = val.replace(STORAGE_DIRS[0]['PATH'], '')
            d[col[0]] = val
        return d

    con = sqlite3.connect(db_file)
    con.row_factory = dict_factory
    cur = con.cursor()
    cur.execute("SELECT * from files ORDER BY path ASC")
    files = cur.fetchall()
    cur.execute("SELECT * from actions")
    actions = cur.fetchall()
    con.close()
    data = {'files': files, 'actions': actions}
    if not os.path.exists(expected_file):
        data['orig_data_dir'] = DATA_DIR
        with open(expected_file, "w") as _fh:
            _fh.write(json.dumps(data, indent=2))
    
    with open(expected_file) as _fh:
        expected = json.load(_fh)
        if storage_id:
            exp_files = []
            for obj in expected['files']:
                if obj['storage_id'] == storage_id:
                    exp_files.append(obj)
            expected['files'] = exp_files
            expected['actions'] = []  # clear actions when using a subset db

    assert files == expected['files']
    assert actions == expected['actions']

def verify_archive(archive_dir, expected_file, storage_id, encrypt=None):
    """Verify the archive files match the expected state"""
    with open(expected_file) as _fh:
        expected = json.load(_fh)
    orig_data_dir = expected['orig_data_dir']
    fileobjs = [_ for _ in expected['files'] if _['storage_id'] == storage_id]
    seen = set()
    shamap = {}
    for root, dirs, files in os.walk(archive_dir):
        dirs[:] = [_ for _ in dirs if _ != '.backup_db.old']
        for fname in files:
            if root == archive_dir and fname in (".backup_id", ".backup_db.sqlite3"):
                continue
            if fname.endswith('.par2'):
                continue
            arc_path = os.path.join(root, fname)
            data_path = arc_path.replace(archive_dir, '').replace(STORAGE_DIRS[0]['PATH'], '')
            assert data_path not in seen
            seen.add(data_path)
            val = next((_ for _ in fileobjs if _['path'] == data_path), None)
            if not val:
                breakpoint()
            assert val
            if os.path.islink(arc_path):
                orig_symlink = os.readlink(arc_path)
                sha1 = hashlib.sha1(orig_symlink.encode('utf8')).hexdigest()
            else:
                if os.path.getsize(arc_path) != 0:
                    assert(os.path.exists(arc_path + ".par2"))
                with open(arc_path, "rb") as _fh:
                    sha1 = hashlib.sha1(_fh.read()).hexdigest()
            assert val['sha1'] == sha1, f"Archive has wrong SHA for {data_path}"
            if not encrypt:
                # encryption masks hardlinks
                if sha1 in shamap:
                    if blaine.blaine_lstat(arc_path).st_ino != shamap[sha1]:
                        breakpoint()
                    assert blaine.blaine_lstat(arc_path).st_ino == shamap[sha1]
                else:
                    shamap[sha1] = blaine.blaine_lstat(arc_path).st_ino
    for obj in fileobjs:
        if obj['path'] not in seen:
            breakpoint()
        assert obj['path'] in seen, f"{obj['path']} is in DB but not in archive"

def verify_data(data_dir, db_file, exclude_file):
    """Verify the database matches the data directory"""
    con = sqlite3.connect(db_file)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * from files ORDER BY path ASC")
    fileobjs = cur.fetchall()
    con.close()
    args_nt = namedtuple("Args", ["snapraid_conf", "exclude", "re_exclude"])
    args = args_nt(exclude_file, [], [])
    exclude_dirs, exclude_files = blaine.parse_exclude(args)
    seen = set()
    for root, dirs, files in os.walk(data_dir):
        filtered_dirs = []
        for dirname in sorted(dirs):
            path = os.path.join(root, dirname)
            if any(_exc.search(path) for _exc in exclude_dirs):
                continue
            filtered_dirs.append(path)
        dirs[:] = filtered_dirs
        for fname in files:
            path = os.path.join(root, fname)
            if any(_exc.search(path) for _exc in exclude_files):
                continue
            seen.add(path)
            val = next((_ for _ in fileobjs if _['path'] == path), None)
            if not val:
                breakpoint()
            assert val
            if os.path.islink(path):
                orig_symlink = os.readlink(path)
                sha1 = hashlib.sha1(orig_symlink.encode('utf8')).hexdigest()
            else:
                with open(path, "rb") as _fh:
                    sha1 = hashlib.sha1(_fh.read()).hexdigest()
            assert val['sha1'] == sha1, f"{path} SHA1 mismatch"
            assert blaine.blaine_lstat(path).st_ino == val['inode']
    for obj in fileobjs:
        assert obj['path'] in seen

def dump_dir_stats(dirname):
    for root, dirs, files in os.walk(dirname):
        for fname in files:
            path = os.path.join(root, fname)
            lstat = blaine.blaine_lstat(path)
            with open(path, "rb") as _fh:
                sha1 = hashlib.sha1(_fh.read()).hexdigest()
            print(f"{path}: {lstat.st_ino} {lstat.st_size} {sha1}")

#def test_1():
#    prepare_stage(1)
#    breakpoint()
#    dump_dir_stats(STORAGE_DIRS[0]['PATH'])
#    prepare_stage(2)
#    dump_dir_stats(STORAGE_DIRS[0]['PATH'])
#    assert True

def run_stage(monkeypatch, caplog, stage, archive, encrypt=None, config=None, prepare=True, expected_file=None):
    class Config(blaine.Config):
         pass

    history = []
    def logger(self, cmd, *path):
        history.append((cmd, *path))

    if prepare:
        prepare_stage(stage, clean=(stage==1))
    archive_dir = STORAGE_DIRS[archive]['PATH']
    db_file = os.path.join(STORAGE_DIRS[0]['PATH'], "archive.sqlite3")
    data_dir = os.path.join(STORAGE_DIRS[0]['PATH'], "archive")
    if not expected_file:
        expected_file = os.path.join(DATA_DIR, f"stage{ stage }_db.json")
    monkeypatch.setattr("blaine.Config", Config)  # Don't overwrite defaults
    monkeypatch.setattr("blaine.Blaine.logger", logger)
    monkeypatch.setattr("sys.argv", ["app", "backup", "--db", db_file,
                                     "--dest", archive_dir,
                                     "--snapraid", EXCLUDE_FILE,
                                     "--clean",
                                     data_dir] + 
                                     (["--enc", encrypt] if encrypt else []) +
                                     (["--conf", config] if config else []))
    blaine.main()
    warn_or_above = [_ for _ in caplog.record_tuples if _[1] > logging.INFO]
    assert not warn_or_above
    verify_db(db_file, expected_file)
    verify_data(data_dir, db_file, EXCLUDE_FILE)
    with do_encrypt(encrypt, archive_dir) as storage_dir:
        verify_archive(storage_dir, expected_file, STORAGE_DIRS[archive]['ID'], encrypt)
        verify_db(os.path.join(storage_dir, ".backup_db.sqlite3"),
              expected_file, STORAGE_DIRS[archive]['ID'])
    return history

def test_stage123_archive(monkeypatch, caplog):
    run_stage(monkeypatch, caplog, 1, 1)
    run_stage(monkeypatch, caplog, 2, 2)
    run_stage(monkeypatch, caplog, 3, 1)

def test_dupdisk(monkeypatch, caplog):
    run_stage(monkeypatch, caplog, 1, 1)
    # need rsync instead of shutil.copytree to preserve hardlinks
    subprocess.run(["rsync", "-aH", STORAGE_DIRS[1]['PATH'] + "/", STORAGE_DIRS[3]['PATH']], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    h1 = run_stage(monkeypatch, caplog, 2, 1, expected_file=f"{DATA_DIR}/stage2_dup1_db.json")
    h2 = run_stage(monkeypatch, caplog, 2, 3, prepare=False, expected_file=f"{DATA_DIR}/stage2_dup2_db.json")
    res = subprocess.run(["diff", "-r", STORAGE_DIRS[1]['PATH'], STORAGE_DIRS[3]['PATH']], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert not res.returncode

def test_stage123_encrypted(monkeypatch, caplog):
    run_stage(monkeypatch, caplog, 1, 3, encrypt="abcd1234")
    run_stage(monkeypatch, caplog, 2, 4, encrypt="abcd1234")
    run_stage(monkeypatch, caplog, 3, 3, encrypt="abcd1234")

def test_stage123_par2_secfs(monkeypatch, caplog):
    config = os.path.join(DATA_DIR, "securefs_par2.toml")
    run_stage(monkeypatch, caplog, 1, 5, encrypt="abcd1234", config=config)
    run_stage(monkeypatch, caplog, 2, 6, encrypt="abcd1234", config=config)
    run_stage(monkeypatch, caplog, 3, 5, encrypt="abcd1234", config=config)

def test_write_storage_id():
    with tempfile.TemporaryDirectory() as _td:
        storage_id = blaine._set_storage_id(_td, create=True)
        assert os.path.exists(os.path.join(_td, ".backup_id"))
        storage_id2 = blaine._set_storage_id(_td)
        assert storage_id == storage_id2

def test_invalid_action():
    try:
        blaine.Blaine.append_action(None, "INVALID", "storage_id", "path1", "path2")
        assert False, "Expected exception fom append_action"
    except Exception as _e:
        assert str(_e) == "unsupported action: INVALID"
    try:
        blaine.Blaine.append_action(None, "RENAME", "storage_id", "path1", None)
        assert False, "Expected exception fom append_action"
    except Exception as _e:
        assert str(_e) == "No destination for action RENAME path1"
