DigitalOcean Debian to Arch
===========================
DigitalOcean deprecated Arch Linux a while back because it was relatively
difficult to support due to the rolling updates. I wrote this script to
bring it back! This script downloads all the packages necessary for a base
Arch Linux VPS, extracts them, configures them, and installs the fully
configured system on the root of the filesystem. This script also configures
the system to run *kexec* on startup to ensure that the latest installed
kernel version is running.

Warning
-------
This script may cause your VPS to become unbootable. I only recommend
running this script on newly created droplets with no important data.

Installation
------------
1. Create a new Debian 7.0 x64 droplet.
2. In the droplet (either SSH or console access works),
   run the following as root:
    ```wget https://raw.githubusercontent.com/gh2o/digitalocean-debian-to-arch/master/install.sh && bash install.sh```
3. Answer the questions as prompted.
    * If the script asks to remove a failed installation,
      there is a failed installation at `/archroot` that is
      unlikely to contain important data. It is safe and
      recommended to answer **yes** here.
    * Because the random number generator, required to
      generate keys for pacman, is painstakingly slow,
      the script will offer to install the package `haveged`
      which will speed it up. Again it is recommended to
      answer **yes** here.
4. Sit back and relax! The system will automatically reboot once complete,
   and you should have a fully updated Arch Linux system in within minutes.
5. You will be able to log in with your original root password. The replaced
   Debian files are located in `/oldroot`, which may be safely deleted to
   free up space.

Advanced Configuration
----------------------
* You may set `archlinux_mirror` in the script to a mirror closer to your
  droplet's datacenter for a faster installation.

Known Issues
------------
* IPv6 settings are not migrated.
* Private networking settings are not migrated.
* Hostname is reset to `localhost`.
