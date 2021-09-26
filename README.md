# Blaine Backup

**NOTE:  Blaine Backup is still in early development.  Use at your own risk**

Blaine Backup is a disk backup solution designed specifcially to backup media disks incrementally.
It can backup onto multiple disks and does not require that they all be online during the backup
process.  It is targetted at disks which mostly grow in size, without significant numbers of
delete operations.  Conceptually, it is a hybrid between tape-like storage and traditional backup
solutions.  Additionally PAR2 parity is supported to provide additional resiliency.

Blaine is NOT designed to provide rapid recovery.  It is more focused on catastrophic failure when
as much data as possible can be recovered, but it is acceptable to wait for offline storage to
become available.

## Key Functionality
  * Support incremental archiving even when previous archives are offline
  * Provide file-level deduplication and file validation via SHA1 hashing
  * Provide file corruption resiliance via PAR2 files
  * Prevent snooping of archive disks via encryption

The archive process consists of the following parts:
  * Actions applied to the current storage disk:
    These are generaly file copy/move/delete/hardlink operations to copy data/changes
    from the data disk to the archive disk
  * Deferred actions to apply to unmounted archive disks
    These are commands to execute in the future once an unmounted archive disk is mounted.
    These will never involve creating new data, but may be rename, hardlink, or delete commands
  * A SQLITE3 database maintaing the current state of the archive as well as all of the 
    deferred actions
  * A SQLITE3 database on each archive disk maintaining the files contained within

## Use case
Blaine Backup was specifcially designed to be used with Snapraid and MergerFS although there are
no limitations that it be used with thse technologies.  The concept is to initially backup very
large data sets onto multiple disks, and then store those off premises.  Future backups can be done
onto new archive disks without access to previously archived disks.  There can be multiple copies
of the current archive disk such that one is off premises and the other is available, and these
can be periodically swapped.  For example:

  1. Initial 20TB dataset is backed up onto 3 8TB disks (DiskA, DiskB, DiskC).  DiskA and DiskB are
     full.  DiskC is ~ 1/2 full.
  2. DiskC is cloned onto a new 8TB DiskC' disk (DiskC' can also be created directly by Blaine)
  3. DiskA, DiskB, and DiskC are moved offsite to a secure storage location
  4. DiskC' is left on-site (or mounted)
  5. Each day 100GB is added to the dataset and archived onto DiskC'
  6. Each week DiskC and DiskC' are swapped (one going offline the other coming online)
  7. After a disk swap, Blaine will copy all changes between DiskC and DiskC' to DiskC
     (now DiskC and DiskC' are identical) and the process 
  8. Steps 5-7 repeat until DiskC/DiskC' are full
  9. A new 8TB disk is procured as DiskD, DiskC' is wiped and re-initialized as DiskD', and DiskC
     remains in offsite storage.
  10. Repeat from step 5

With the above process, at any given time, the maximum amount of data lost is the 1-week difference between DiskC and DiskC'

## Performance
Blaine Backup is slow.  PAR2 calculation is very CPU intensive, and using disk-encryption also slows the process down.  That said, Blaine uses several methods to improve performance as much as possible:
  * Use gocryptfs vs securefs (or encfs) for more CPU efficient encryption
  * Use parpar instaed of par2cmdline For 2-3x performance improvement in PAR2 calculation
  * Use parallel par2 runs to improve throughput for small files

## Encryption
Blaine Backup can use encryption to secure offline disks.  SecureFS is the only tested encryption system, though any system
that has mount/unmount commands and can take a password on the command-line or via keyfile should be usable).

Using encryption is intended to prevent unauthorized snooping of offline disks that are stored in un-trusted locations.
It is NOT intended to provide any security when mounted in the host system or during
the backup process.  When using encryption, the encryption key should be redundantly stored (separately from the
archive disks.  **If the encryption key is lost, the backups cannot be restored**.
If SecureFS is used for encryption and the underlying filesystem is NTFS (as of Linux 5.15, the Paragon NTFS driver should
provide similar performance to other native filesystems), then data can (theoretically) be restored onto a Windows system.

## Archive process
 * Apply any deferred actions that are needed to the current archive disk
 * Iterate over each file in the path to archive
   * If the file has been previously archived and is unchanged, skip
   * If the file has not been seen before, archive onto storage disk
   * If the file has been modified since last archive
     * If the file was originally archived onto the current archive disk: update the archive, and
       Compute PAR2 parity for the archived file
     * If the file was originally archived onto an offline archive disk: store the file, create
       PAR2 parity for the archived file, and create a deferred action to remove the file from
       the offline archive disk
   * If the file has been renamed or deleted since the last archive
     * If the file was originally archived onto the current archive disk: apply the change
     * If the file was originally archived onto an offline archive disk: create a deferred action
       to remove the file from the offline archive disk
 * Store a sqlite file containing all files stored on the current archive disk 
   onto the archive disk
 * Save the database containing the complete state of the archive as well as all deferred actions
   onto the host system

## Requirements
  * linux OS: The code should be portable to MacOS/Windows, but no work has been done on this yet
  * python >= 3.6
  * dc3dd : Fast copy & checksum in a single step
  * parpar or par2 (optional): Calculate parity to avoid bitrot (parpar is ~3x faster than par2).  **NOTE: par2 0.8.1 has a bug which prevents creating PAR2 files for filenames that are a single character.**
  * gocryptfs pr securefs(optional): Provide encryption (gocryptfs is significnatly faster than securefs)

## Usage
The easiest way to use Blaine is via Docker.  The included Dockerfile will build an image containingall needed dependencies (gocrypt, parpar, dc3dd) as well as alternate options (a patched version of par2 allowing single-character filenames, securefs).

To run in Docker:
    docker build --tag blainebackup .
    docker run --rm -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined -v <path to data>:<path to data>:ro -v <backup_dir>:/mnt/backup -u 0 blainebackup:latest
    ./backup.py --enc <encryption password> --db <<path to data>/blainebackup.db --dest /mnt/backup <path to data>

## Testing
Tests are designed to be run in a Docker container for reproducibility:
    docker build --tag blainebackup:test --build-arg TEST=1 .
    docker run --rm -it --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined -v $PWD:/work pytest --cov=backup --cov-report term-missing -vv test

## Other considerations

There are enterprise level archive solutions that can do most of what Blaine can do such as Amanda
or Bacula.  However, they tend to be complicated to setup and maintain, and none offer all the
features of Blaine Backup.
