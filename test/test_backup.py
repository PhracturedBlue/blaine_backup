import logging
import os
import sys
import hashlib
import json
import tempfile
import uuid
import sqlite3

import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import backup

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
STORAGE_DIRS = [
  {'ID': None, 'PATH': None},   # Used for common storage
  {'ID': "de6912cf-e35d-45ee-a085-d9eddf7152ca", 'PATH': None},
  {'ID': "8edfffa9-3dcc-49e9-a70e-8f6499426986", 'PATH': None},
]
    
@pytest.fixture(scope='module', autouse=True)
def setup_archive():
    prepare_stage(1)
    prepare_stage(2)
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

def prepare_stage(stage_num):
    """Ensure hardlinks are created since git can't store them"""
    stage_dir = os.path.join(DATA_DIR, f'stage{ stage_num }')
    prev_stage_dir = os.path.join(DATA_DIR, f'stage{ stage_num -1 }')
    # replace '+' with '.', replace : with '/'
    for root, _dirs, files in os.walk(stage_dir):
        for fname in files:
            if not fname.endswith(".hardlink"):
                path = os.path.join(root, fname)
                prev_path = path.replace(stage_dir, prev_stage_dir)
                if os.path.exists(prev_path) and os.system(f"diff -q { prev_path } { path }"):
                    os.unlink(path)
                    os.link(prev_path, path)
                continue
            orig_path = os.path.abspath(os.path.join(
                root, fname.replace('+', '.').replace(':', '/').replace(".hardlink", "")))
            path = os.path.join(root, fname)
            os.unlink(path)
            os.link(orig_path, path)

def verify_db(db_file, expected_file, storage_id=None):
    seen_inodes = {}
    cur_inode = 1000
    def dict_factory(cursor, row):
        nonlocal cur_inode
        d = {}
        for idx, col in enumerate(cursor.description):
            val = row[idx]
            if col[0] == 'time':
                continue  # Don't compare time, since it is not persistent
            if col[0] == 'inode':
                if val not in seen_inodes:
                    seen_inodes[val] = cur_inode
                    cur_inode += 1
                val = seen_inodes[val]
            elif col[0] in ('path', 'target_path'):
                val = val.replace(DATA_DIR, '')
            d[col[0]] = val
        return d

    con = sqlite3.connect(db_file)
    con.row_factory = dict_factory
    cur = con.cursor()
    if storage_id:
        cur.execute("SELECT * from files WHERE storage_id = ? ORDER BY path ASC", (storage_id,))
    else:
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

    assert files == expected['files']
    assert actions == expected['actions']

def verify_archive(archive_dir, expected_file, storage_id):
    with open(expected_file) as _fh:
        expected = json.load(_fh)
    orig_data_dir = expected['orig_data_dir']
    fileobjs = [_ for _ in expected['files'] if _['storage_id'] == storage_id]
    seen = set()
    shamap = {}
    for root, dirs, files in os.walk(archive_dir):
        for fname in files:
            if root == archive_dir and fname in (".backup_id", ".backup_db.sqlite3"):
                continue
            if fname.endswith('.par2'):
                continue
            arc_path = os.path.join(root, fname)
            data_path = arc_path.replace(archive_dir, '').replace(DATA_DIR, '')
            assert data_path not in seen
            seen.add(data_path)
            val = next((_ for _ in fileobjs if _['path'] == data_path), None)
            if not val:
                breakpoint()
            assert val
            if os.path.islink(arc_path):
                orig_symlink = os.readlink(arc_path).replace(archive_dir, '').replace(DATA_DIR, orig_data_dir)
                sha1 = hashlib.sha1(orig_symlink.encode('utf8')).hexdigest()
            else:
                if os.path.getsize(arc_path) != 0:
                    assert(os.path.exists(arc_path + ".par2"))
                with open(arc_path, "rb") as _fh:
                    sha1 = hashlib.sha1(_fh.read()).hexdigest()
            assert val['sha1'] == sha1
            if sha1 in shamap:
                assert os.lstat(arc_path).st_ino == shamap[sha1]
            else:
                shamap[sha1] = os.lstat(arc_path).st_ino
    for obj in fileobjs:
        assert obj['path'] in seen


def test_stage1_archive(monkeypatch, caplog):
    archive_dir = STORAGE_DIRS[1]['PATH']
    db_file = os.path.join(STORAGE_DIRS[0]['PATH'], "archive.sqlite3")
    monkeypatch.setattr("sys.argv", ["app", "--db", db_file,
                                     "--dest", archive_dir,
                                     "--conf", os.path.join(DATA_DIR, "snapraid.conf"),
                                     os.path.join(DATA_DIR, "stage1")])
    backup.main()
    warn_or_above = [_ for _ in caplog.record_tuples if _[1] > logging.INFO]
    assert not warn_or_above
    verify_db(db_file, os.path.join(DATA_DIR, "stage1_db.json"))
    verify_archive(archive_dir, os.path.join(DATA_DIR, "stage1_db.json"), STORAGE_DIRS[1]['ID'])
    verify_db(os.path.join(archive_dir, ".backup_db.sqlite3"),
              os.path.join(DATA_DIR, "stage1_db.json"), STORAGE_DIRS[1]['ID'])

def test_stage2_archive(monkeypatch, caplog):
    archive_dir = STORAGE_DIRS[2]['PATH']
    db_file = os.path.join(STORAGE_DIRS[0]['PATH'], "archive.sqlite3")
    monkeypatch.setattr("sys.argv", ["app", "--db", db_file,
                                     "--dest", archive_dir,
                                     "--conf", os.path.join(DATA_DIR, "snapraid.conf"),
                                     os.path.join(DATA_DIR, "stage1")])
    backup.main()
    warn_or_above = [_ for _ in caplog.record_tuples if _[1] > logging.INFO]
    assert not warn_or_above
    verify_db(db_file, os.path.join(DATA_DIR, "stage2_db.json"))
    verify_archive(archive_dir, os.path.join(DATA_DIR, "stage2_db.json"), STORAGE_DIRS[1]['ID'])
    verify_db(os.path.join(archive_dir, ".backup_db.sqlite3"),
              os.path.join(DATA_DIR, "stage2_db.json"), STORAGE_DIRS[2]['ID'])

