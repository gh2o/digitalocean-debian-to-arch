DigitalOcean Debian to Arch
===========================
DigitalOcean deprecated Arch Linux a while back because it was relatively
difficult to support due to the rolling updates. I wrote this script to
bring it back! This script downloads a bootstrap Arch Linux image, updates it
to the latest version, then overwrites the host operating system with it.
Unlike Debian 7.x, Debian 8.x on DigitalOcean boots traditionally (through the
MBR and Grub), so no dirty *kexec* magic is needed.

Warning / Disclaimer
--------------------
This script may cause your VPS to become unbootable. If the script crashes
during the overwrite phase, you will **DEFINITELY** lose all data on the VPS.
I only recommend running this script on newly created droplets with no
important data.

Installation
------------
1. Create a new Debian 8.x droplet (either 32-bit or 64-bit works).
2. In the droplet (either SSH or console access works),
   run the following as root:
    ```wget https://raw.githubusercontent.com/gh2o/digitalocean-debian-to-arch/debian8/install.sh && bash install.sh```
3. Sit back and relax! The system will automatically reboot once complete,
   and you should have a fully updated Arch Linux system in within minutes.
