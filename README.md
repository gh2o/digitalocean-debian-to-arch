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
<h3>ALL DATA ON THE DROPLET WILL BE UNCONDITIONALLY DESTROYED.</h3>
This script may cause your VPS to become unbootable.
I only recommend running this script on newly created droplets with no
important data.

Installation
------------
1. Create a new Debian 8.x droplet (either 32-bit or 64-bit is fine).
2. In the droplet, run the following as root:
        `wget https://raw.githubusercontent.com/Moshifan100/digitalocean-debian-to-arch/debian8/install.sh && bash install.sh`
3. Follow the instructions when prompted.
4. Sit back and relax! The system will automatically reboot once complete,
   and you should have a fully updated Arch Linux system in within minutes.

Advanced Configuration
----------------------
This script supports several flags, all of which are optional.

* `--archlinux_mirror`  
  The Arch Linux mirror from which the bootstrap image and packages should be
  downloaded. Defaults to http://mirrors.kernel.org/archlinux
* `--extra_packages`
  Installs any extra packages to the Arch installation. This works with `base-devel` as well. To   
  add multiple packages use quotation   
  marks example `--extra_packages "git wget"`
* `--kernel_package`  
  The kernel package to install. Defaults to the vanilla `linux` package.
  Other options include `linux-lts` for long term support and `linux-grsec` for
  a kernel with grsecurity/PaX patches.
* `--target_architecture`  
  The architecture of the new Arch Linux installation. Defaults to the
  architecture of the original Debian image as provided by `uname -m`.
  A 64-bit Debian image may convert to either `x86_64` or `i686`.
  A 32-bit Debian image may only convert to `i686`.
* `--target_disklabel`  
  The type of partition table to use. Defaults to `gpt` (GUID partition table
  as used by EFI). The alternative is `dos` (traditional MBR).
* `--target_filesystem`  
  The filesystem on which the Arch Linux installation should be installed.
  Defaults to `ext4`. The alternative is `btrfs`.
  
How it Works
------------
1. A sparse disk image is created with the same size of the droplet's disk.
2. Three partitions are made and formatted.
   * **DORoot**: A "dummy" partition to keep DigitalOcean happy. When snapshots
       are restored, new passwords are written here.
   * **BIOSBoot**: The virtual machine BIOS cannot boot from GPT partitions
       directly, so a small partition is placed here for bootloader code.
   * **ArchRoot**: The main root filesystem for Arch Linux.
3. The Arch Linux bootstrap image is downloaded and unpacked onto ArchRoot.
4. `pacman -Syu` is called inside the image to pull in all the base packages
   along with OpenSSH and any other packages put in the --extra_packages option.
5. The root password and SSH host keys are copied into the image.
6. A special script called `digitalocean-synchronize` is installed into
   the image. This script is run at every startup to autodetect the network
   settings from the metadata service. It also detects if the droplet
   was just restored, and if so, it resets the root password and regenerates
   the host SSH keys.
7. The image is now ready. The script then generates a "blockplan". It is
   essentially a list of instructions to image the virtual disk with the
   sparse disk image without requiring any extra space.
8. A minimal root filesystem is generated on RAM so that the disk can
   be unmounted.
9. The script calls `systemctl switch-root` to enter the minimal
   root filesystem.
10. The disk is unmounted.
11. The blockplan is executed.
12. The bootloader (Grub) is installed.
13. Reboot!
14. Done!
