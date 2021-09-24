= Blaine Backup

** NOTE:  Blaine Backup is still in early development.  Use at your own risk **

Blaine Backup is a disk backup solution designed specifcially to backup media disks incrementally.
It can backup onto multiple disks and does not require that they all be online during the backup
process.  It is targetted at disks which mostly grow in size, without significant numbers of
delete operations.  Conceptually, it is a hybrid between tape-like storage and traditional backup
solutions.  Additionally PAR2 parity is supported to provide additional resiliency.

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

== Use case
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
  9. A new 8TB disk is procured as DiskD, DiskC' is wiwped and re-initialized as DiskD', and DiskC
     remoains in offsite storage.
  10. Repeat from step 5

With the above process, at any given time, the maximum amount of data lost is the 1-week difference between DiskC and DiskC'

== Archive process
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

== Requirements
  * python >= 3.6
  * dc3dd : Fast copy & checksum in a single step
  * par2 : Calculate parity to avoid bitrot

== Other considertations

There are enterprise level archive solutions that can do most of what Blaine can do such as Amanda
or Bacula.  However, they tend to be complicated to setup and maintain, and none offer all the
features of Blaine Backup.
