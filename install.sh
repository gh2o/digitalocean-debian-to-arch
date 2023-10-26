#!/bin/bash

################################################################################
### INSTRUCTIONS AT https://github.com/gh2o/digitalocean-debian-to-arch/     ###
################################################################################

# Copyright (c) 2017 Gavin Li.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

run_from_file() {
	local f t
	for f in /dev/fd/*; do
		[ -h $f ] || continue
		[ $f -ef "$0" ] && return
	done
	t=$(mktemp)
	cat >$t
	if [ "$(head -n 1 $t)" = '#!/bin/bash' ]; then
		chmod +x $t
		exec /bin/bash $t "$@" </dev/fd/2
	else
		rm -f $t
		echo "Direct execution not supported with this shell ($_)." >&2
		echo "Please try bash instead." >&2
		exit 1
	fi
}

# do not modify the two lines below
[ -h /dev/fd/0 ] && run_from_file
#!/bin/bash

########################################
### DEFAULT CONFIGURATION            ###
########################################

# mirror from which to download archlinux packages
archlinux_mirror="http://mirrors.kernel.org/archlinux"

# extra packages
extra_packages=""

# grub timeout
grub_timeout=5

# package to use as kernel (linux or linux-lts)
kernel_package=linux

# extra mkfs options
mkfs_options=""

# migrated machine architecture (x86_64/i686)
target_architecture="$(uname -m)"

# new disklabel type (gpt/dos)
target_disklabel="gpt"

# new filesystem type (ext4/btrfs)
target_filesystem="ext4"

# NOT EXPOSED NORMALLY: don't prompt
continue_without_prompting=0

# NOT EXPOSED NORMALLY: path to metadata service
# DigitalOcean metadata API
# https://developers.digitalocean.com/documentation/metadata/
meta_base=http://169.254.169.254/metadata/v1/

########################################
### END OF CONFIGURATION             ###
########################################

if [ -n "${POSIXLY_CORRECT}" ] || [ -z "${DEBIAN_TO_ARCH_ENV_CLEARED}" ]; then
	exec /usr/bin/env -i \
		TERM="$TERM" \
		PATH=/usr/sbin:/sbin:/usr/bin:/bin \
		DEBIAN_TO_ARCH_ENV_CLEARED=1 \
		/bin/bash "$0" "$@"
fi

set -eu
set -o pipefail
shopt -s nullglob
shopt -s dotglob
umask 022

sector_size=512

flag_variables=(
	archlinux_mirror
	extra_packages
	grub_timeout
	kernel_package
	mkfs_options
	target_architecture
	target_disklabel
	target_filesystem
)

host_packages=(
	busybox
	haveged
	parted
	psmisc
)

arch_packages=(
	fakeroot # for makepkg
	grub
	openssh
	python3 # for python system-wide
)

gpt1_size_MiB=1
doroot_size_MiB=6
biosboot_size_MiB=1
archroot_size_MiB=
gpt2_size_MiB=1

doroot_offset_MiB=$((gpt1_size_MiB))
biosboot_offset_MiB=$((doroot_offset_MiB + doroot_size_MiB))
archroot_offset_MiB=$((biosboot_offset_MiB + biosboot_size_MiB))

log() {
	local color_on=$'\e[0;32m'
	local color_off=$'\e[0m'
	echo "${color_on}[$(date)]${color_off} $@" >&2
}

fatal() {
	log "$@"
	log "Exiting."
	exit 1
}

extract_digitalocean_synchronize() {
	local outdir="$1"
	mkdir -p "${outdir}"
	awk 'x {print} $0 == "### digitalocean-synchronize ###" {x=1}' "$0" |
		base64 -d | tar -zxC "${outdir}"
}

parse_flags() {
	local c conf_key conf_val
	while [ $# -gt 0 ]; do
		conf_key=
		conf_val=
		for c in ${flag_variables[@]}; do
			case "$1" in
			--$c)
				shift
				[ $# -gt 0 ] || fatal "Option $c requires a value."
				conf_key="$c"
				conf_val="$1"
				shift
				break
				;;
			--$c=*)
				conf_key="$c"
				conf_val="${1#*=}"
				shift
				break
				;;
			--i_understand_that_this_droplet_will_be_completely_wiped)
				continue_without_prompting=1
				conf_key=option_acknowledged
				shift
				break
				;;
			--help)
				print_help_and_exit
				;;
			esac
		done
		[ "${conf_key}" = option_acknowledged ] && continue
		[ -n "${conf_key}" ] || fatal "Unknown option: $1"
		[ -n "${conf_val}" ] || fatal "Empty value for option ${conf_key}."
		local -n conf_ref=${conf_key}
		conf_ref="${conf_val}"
	done
	log "Configuration:"
	for conf_key in ${flag_variables[@]}; do
		local -n conf_ref=${conf_key}
		log "- ${conf_key} = ${conf_ref}"
	done
}

print_help_and_exit() {
	local conf_key
	echo "Available options: (see script for details)" >&2
	for conf_key in ${flag_variables[@]}; do
		local -n conf_ref=${conf_key}
		echo "  --${conf_key}=[${conf_ref}]" >&2
	done
	exit 1
}

validate_flags_and_augment_globals() {
	arch_packages+=(${kernel_package})
	case "${target_disklabel}" in
	gpt) ;;
	dos) ;;
	*)
		fatal "Unknown disklabel type: ${target_disklabel}"
		;;
	esac
	case "${target_filesystem}" in
	ext4) ;;
	btrfs)
		host_packages+=(btrfs-tools)
		arch_packages+=(btrfs-progs)
		;;
	*)
		fatal "Unknown filesystem type: ${target_filesystem}"
		;;
	esac
	local disk_MiB=$(($(cat /sys/block/vda/size) >> 11))
	archroot_size_MiB=$((disk_MiB - gpt2_size_MiB - archroot_offset_MiB))
}

read_flags() {
	local filename=$1
	source ${filename}
}

write_flags() {
	local filename=$1
	{
		local conf_key
		for conf_key in ${flag_variables[@]}; do
			local -n conf_ref=${conf_key}
			printf "%s=%q\n" "${conf_key}" "${conf_ref}"
		done
	} >${filename}
}

sanity_checks() {
	[ ${EUID} -eq 0 ] || fatal "Script must be run as root."
	[ ${UID} -eq 0 ] || fatal "Script must be run as root."
	[ -e /dev/vda ] || fatal "Script must be run on a KVM machine."
	[[ "$(cat /etc/debian_version)" =~ ^([89]|10).+$ ]] ||
		fatal "This script only supports Debian 8.x/9.x."
}

prompt_for_destruction() {
	((continue_without_prompting)) && return 0
	log "*** ALL DATA ON THIS DROPLET WILL BE WIPED. ***"
	log "Please backup all important data on this droplet before continuing."
	log 'Type "wipe this droplet" to continue or anything else to cancel.'
	local response
	read -p '> ' response
	if [ "${response}" = "wipe this droplet" ]; then
		return 0
	else
		log "Cancelled."
		exit 0
	fi
}

download_and_verify() {
	local file_url="$1"
	local local_path="$2"
	local expected_sha256="$3"
	for try in {0..3}; do
		if [ ${try} -eq 0 ]; then
			[ -e "${local_path}" ] || continue
		else
			wget -O "${local_path}" "${file_url}"
		fi
		set -- $(sha256sum "${local_path}")
		if [ $1 = "${expected_sha256}" ]; then
			return 0
		else
			rm -f "${local_path}"
		fi
	done
	return 1
}

build_parted_cmdline() {
	local cmdline=
	local biosboot_name=BIOSBoot
	local doroot_name=DORoot
	local archroot_name=ArchRoot
	if [ ${target_disklabel} = dos ]; then
		cmdline="mklabel msdos"
		biosboot_name=primary
		doroot_name=primary
		archroot_name=primary
	else
		cmdline="mklabel ${target_disklabel}"
	fi
	local archroot_end_MiB=$((archroot_offset_MiB + archroot_size_MiB))
	cmdline+=" mkpart ${doroot_name} ${doroot_offset_MiB}MiB ${biosboot_offset_MiB}MiB"
	cmdline+=" mkpart ${biosboot_name} ${biosboot_offset_MiB}MiB ${archroot_offset_MiB}MiB"
	cmdline+=" mkpart ${archroot_name} ${archroot_offset_MiB}MiB ${archroot_end_MiB}MiB"
	if [ ${target_disklabel} = gpt ]; then
		cmdline+=" set 2 bios_grub on"
	fi
	echo "${cmdline}"
}

setup_loop_device() {
	local offset_MiB=$1
	local size_MiB=$2
	losetup --find --show --offset ${offset_MiB}MiB --size ${size_MiB}MiB /d2a/work/image
}

kill_processes_in_mountpoint() {
	if mountpoint -q $1; then
		fuser -kms $1 || true
		find /proc -maxdepth 2 -name root -lname $1 |
			grep -o '[0-9]*' | xargs -r kill || true
	fi
}

quietly_umount() {
	if mountpoint -q $1; then
		umount -d $1
	fi
}

cleanup_work_directory() {
	kill_processes_in_mountpoint /d2a/work/doroot
	kill_processes_in_mountpoint /d2a/work/archroot
	quietly_umount /d2a/work/doroot
	quietly_umount /d2a/work/archroot/var/cache/pacman/pkg
	quietly_umount /d2a/work/archroot/dev/pts
	quietly_umount /d2a/work/archroot/dev
	quietly_umount /d2a/work/archroot/sys
	quietly_umount /d2a/work/archroot/proc
	quietly_umount /d2a/work/archroot
	rm -rf --one-file-system /d2a/work
}

stage1_install_exit() {
	set +e
	cleanup_work_directory
}

stage1_install() {
	trap stage1_install_exit EXIT
	cleanup_work_directory
	mkdir -p /d2a/work

	log "Installing required packages ..."
	DEBIAN_FRONTEND=noninteractive apt-get update -y
	DEBIAN_FRONTEND=noninteractive apt-get install -y ${host_packages[@]}

	log "Partitioning image ..."
	local disk_sectors=$(cat /sys/block/vda/size)
	rm -f /d2a/work/image
	truncate -s $((disk_sectors * sector_size)) /d2a/work/image
	parted /d2a/work/image $(build_parted_cmdline)

	log "Formatting image ..."
	local doroot_loop=$(setup_loop_device ${doroot_offset_MiB} ${doroot_size_MiB})
	# Work around losetup errors by sleeping a bit
	sleep 5
	local archroot_loop=$(setup_loop_device ${archroot_offset_MiB} ${archroot_size_MiB})
	mkfs.ext4 -L DOROOT ${doroot_loop}
	mkfs.${target_filesystem} -L ArchRoot ${mkfs_options} ${archroot_loop}

	log "Mounting image ..."
	mkdir -p /d2a/work/{doroot,archroot}
	mount ${doroot_loop} /d2a/work/doroot
	mount ${archroot_loop} /d2a/work/archroot

	log "Setting up DOROOT ..."
	mkdir -p /d2a/work/doroot/etc/network
	mkdir -p /d2a/work/doroot/etc/udev/{rules,hwdb}.d
	touch /d2a/work/doroot/etc/network/interfaces
	cat >/d2a/work/doroot/README <<-EOF
		DO NOT TOUCH FILES ON THIS PARTITION.

		The DOROOT partition is where DigitalOcean writes passwords and other data
		when a droplet is rebuilt from an image or restored from a snapshot.
		If certain files are missing, restores/rebuilds will not work and you will
		end up with an unusable image.

		The digitalocean-synchronize script also watches this partition.
		If this partition (particularly etc/shadow) is written to, the script will
		reset the root password to the one provided by DigitalOcean and wipe all
		SSH host keys for security.
	EOF
	chmod 0444 /d2a/work/doroot/README

	log "Downloading bootstrap tarball ..."
	set -- $(wget -qO- ${archlinux_mirror}/iso/latest/sha256sums.txt |
		grep "archlinux-bootstrap-[^-]*-${target_architecture}.tar.gz")
	local expected_sha256=$1
	local bootstrap_filename=$2
	download_and_verify \
		${archlinux_mirror}/iso/latest/${bootstrap_filename} \
		/d2a/bootstrap.tar.gz \
		${expected_sha256}

	log "Extracting bootstrap tarball ..."
	tar -xzf /d2a/bootstrap.tar.gz \
		--directory=/d2a/work/archroot \
		--strip-components=1

	log "Mounting virtual filesystems ..."
	mount -t proc proc /d2a/work/archroot/proc
	mount -t sysfs sys /d2a/work/archroot/sys
	mount -t devtmpfs dev /d2a/work/archroot/dev
	mkdir -p /d2a/work/archroot/dev/pts
	mount -t devpts pts /d2a/work/archroot/dev/pts

	log "Binding packages directory ..."
	mkdir -p /d2a/packages
	mount --bind /d2a/packages /d2a/work/archroot/var/cache/pacman/pkg

	log "Preparing bootstrap filesystem ..."
	echo "Server = ${archlinux_mirror}/\$repo/os/\$arch" >/d2a/work/archroot/etc/pacman.d/mirrorlist
	echo 'nameserver 8.8.8.8' >/d2a/work/archroot/etc/resolv.conf

	log "Installing base system ..."
	chroot /d2a/work/archroot pacman-key --init
	chroot /d2a/work/archroot pacman-key --populate archlinux
	local chroot_pacman="chroot /d2a/work/archroot pacman --arch ${target_architecture}"
	${chroot_pacman} -Sy
	${chroot_pacman} -Su --noconfirm --needed \
		base ${arch_packages[@]} ${extra_packages}

	log "Configuring base system ..."
	hostname >/d2a/work/archroot/etc/hostname
	cp /etc/ssh/ssh_host_* /d2a/work/archroot/etc/ssh/
	local encrypted_password=$(awk -F: '$1 == "root" { print $2 }' /etc/shadow)
	chroot /d2a/work/archroot usermod -p "${encrypted_password}" root
	chroot /d2a/work/archroot systemctl enable systemd-networkd.service
	chroot /d2a/work/archroot systemctl enable sshd.service

	log "Forcing fallback kernel ..." # cannot trust autodetect when running on Debian kernel
	cp /d2a/work/archroot/boot/initramfs-${kernel_package}{-fallback,}.img

	log "Installing digitalocean-synchronize ..."
	extract_digitalocean_synchronize /d2a/work/archroot/dosync
	chroot /d2a/work/archroot bash -c 'cd /dosync && env EUID=1 makepkg --install --noconfirm'
	rm -rf /d2a/work/archroot/dosync

	local authkeys
	if authkeys="$(wget -qO- ${meta_base}public-keys)" && test -z "${authkeys}"; then
		log "*** WARNING ***"
		log "SSH public keys are not configured for this droplet."
		log "PermitRootLogin will be enabled in sshd_config to permit root logins over SSH."
		log "This is a security risk, as passwords are not as secure as public keys."
		log "To set up public keys, visit the following URL: https://goo.gl/iEgFRs"
		log "Remember to remove the PermitRootLogin option from sshd_config after doing so."
		cat >>/d2a/work/archroot/etc/ssh/sshd_config <<-EOF

			# This enables password logins to root over SSH.
			# This is insecure; see https://goo.gl/iEgFRs to set up public keys.
			PermitRootLogin yes

		EOF
	fi

	log "Finishing up image generation ..."
	ln -f /d2a/work/image /d2a/image
	cleanup_work_directory
	trap - EXIT
}

bisect_left_on_allocation() {
	# more or less copied from Python's bisect.py
	local alloc_start_sector=$1
	local alloc_end_sector=$2
	local -n bisection_output=$3
	local -n allocation_map=$4
	local lo=0 hi=${#allocation_map[@]}
	while ((lo < hi)); do
		local mid=$(((lo + hi) / 2))
		set -- ${allocation_map[$mid]}
		if (($# == 0)) || (($1 < alloc_start_sector)); then
			lo=$((mid + 1))
		else
			hi=$((mid))
		fi
	done
	bisection_output=$lo
}

check_for_allocation_overlap() {
	local check_start_sector=$1
	local check_end_sector=$2
	local -n cfao_overlap_start_sector=$3
	local -n cfao_overlap_end_sector=$4
	shift 4
	local allocation_maps="$*"

	# cfao_overlap_end_sector = 0 if no overlap
	cfao_overlap_start_sector=0
	cfao_overlap_end_sector=0

	local map_name
	for map_name in ${allocation_maps}; do
		local -n allocation_map=${map_name}
		local map_length=${#allocation_map[@]}
		((${map_length})) || continue
		local bisection_index
		bisect_left_on_allocation ${check_start_sector} ${check_end_sector} \
			bisection_index ${map_name}
		local check_index
		for check_index in $((bisection_index - 1)) $((bisection_index)); do
			((check_index < 0 || check_index >= map_length)) && continue
			set -- ${allocation_map[${check_index}]}
			(($# == 0)) && continue
			local alloc_start_sector=$1
			local alloc_end_sector=$2
			((check_start_sector >= alloc_end_sector || alloc_start_sector >= check_end_sector)) && continue
			# overlap detected
			cfao_overlap_start_sector=$((alloc_start_sector > check_start_sector ? \
				alloc_start_sector : check_start_sector))
			cfao_overlap_end_sector=$((alloc_end_sector < check_end_sector ? \
				alloc_end_sector : check_end_sector))
			return
		done
	done
}

insert_into_allocation_map() {
	local -n allocation_map=$1
	shift
	local alloc_start_sector=$1
	local alloc_end_sector=$2
	if ((${#allocation_map[@]} == 0)); then
		allocation_map=("$*")
	else
		local bisection_index
		bisect_left_on_allocation ${alloc_start_sector} ${alloc_end_sector} \
			bisection_index ${!allocation_map}
		allocation_map=(
			"${allocation_map[@]:0:${bisection_index}}"
			"$*"
			"${allocation_map[@]:${bisection_index}}")
	fi
}

stage2_arrange() {
	local disk_sectors=$(cat /sys/block/vda/size)
	local root_device=$(awk '$2 == "/" { root = $1 } END { print root }' /proc/mounts)
	local root_offset_sectors=$(cat /sys/block/vda/${root_device#/dev/}/start)
	local srcdst_map=()  # original source to target map
	local unalloc_map=() # extents not used by either source or target (for tmpdst_map)
	local tmpdst_map=()  # extents on temporary redirection (allocated from unalloc_map)
	local source_start_sector source_end_sector target_start_sector target_end_sector

	log "Creating block rearrangement plan ..."

	# get and sort extents
	filefrag -e -s -v -b${sector_size} /d2a/image |
		sed '/^ *[0-9]*:/!d;s/[:.]/ /g' |
		sort -nk4 >/d2a/imagemap
	while read line; do
		set -- ${line}
		source_start_sector=$(($4 + root_offset_sectors))
		source_end_sector=$((source_start_sector + $6))
		target_start_sector=$2
		target_end_sector=$((target_start_sector + $6))
		echo ${source_start_sector} ${source_end_sector}
		echo ${target_start_sector} ${target_end_sector}
		srcdst_map+=("${source_start_sector} ${source_end_sector} ${target_start_sector}")
	done </d2a/imagemap >/d2a/unsortedallocs
	sort -n </d2a/unsortedallocs >/d2a/sortedallocs

	# build map of unallocated sectors
	local unalloc_start_sector=0 unalloc_end_sector=${disk_sectors}
	while read source_start_sector source_end_sector; do
		if ((source_end_sector <= unalloc_start_sector)); then
			# does not overlap unallocated part
			continue
		elif ((source_start_sector > unalloc_start_sector)); then
			# full overlap with unallocated part
			unalloc_map+=("${unalloc_start_sector} ${source_start_sector}")
			unalloc_start_sector=${source_end_sector}
		else
			# partial overlap
			unalloc_start_sector=${source_end_sector}
		fi
	done </d2a/sortedallocs
	if ((unalloc_start_sector != unalloc_end_sector)); then
		unalloc_map+=("${unalloc_start_sector} ${unalloc_end_sector}")
	fi

	# open blockplan
	exec {blockplan_fd}>/d2a/blockplan

	# arrange sectors
	while ((${#srcdst_map[@]})); do
		set -- ${srcdst_map[-1]}
		source_start_sector=$1
		source_end_sector=$2
		target_start_sector=$3
		target_end_sector=$((target_start_sector + (source_end_sector - source_start_sector)))
		if ((source_start_sector == target_start_sector)); then
			# source data is already at target destination, no need to do anything
			unset 'srcdst_map[-1]'
			continue
		elif ((target_start_sector >= source_end_sector || \
			source_start_sector >= target_end_sector)); then
			# source and target extents don't overlap. just pop this entry off the list
			unset 'srcdst_map[-1]'
		else
			# source and target extents overlap.
			if ((source_start_sector > target_start_sector)); then
				# no problem: by the time source starts to get overwritten,
				# the overwritten data will no longer be needed.
				unset 'srcdst_map[-1]'
			else
				# we're gonna lose data as soon as we start copying, so copy it backwards.
				local new_extent_sectors=$((target_start_sector - source_start_sector))
				set -- \
					$((source_start_sector)) \
					$((source_end_sector - new_extent_sectors)) \
					$((target_start_sector))
				srcdst_map[-1]="$*"
				source_start_sector=$((source_end_sector - new_extent_sectors))
				target_start_sector=$((target_end_sector - new_extent_sectors))
			fi
		fi
		local overlap_start_sector overlap_end_sector
		check_for_allocation_overlap \
			${target_start_sector} ${target_end_sector} \
			overlap_start_sector overlap_end_sector \
			srcdst_map
		if ((overlap_end_sector)); then
			# insert non-overlapping parts back into srcdst_map
			if ((target_start_sector < overlap_start_sector)); then
				local nonoverlap_length_sectors=$((overlap_start_sector - target_start_sector))
				insert_into_allocation_map srcdst_map \
					${source_start_sector} \
					$((source_start_sector + nonoverlap_length_sectors)) \
					${target_start_sector}
			fi
			if ((target_end_sector > overlap_end_sector)); then
				local nonoverlap_length_sectors=$((target_end_sector - overlap_end_sector))
				insert_into_allocation_map srcdst_map \
					$((source_end_sector - nonoverlap_length_sectors)) \
					${source_end_sector} \
					${overlap_end_sector}
			fi
			# copy overlapping portion into tmpdst_map
			while ((overlap_start_sector < overlap_end_sector)); do
				set -- ${unalloc_map[-1]}
				unset 'unalloc_map[-1]' # or nullglob will eat it up
				local unalloc_start_sector=$1
				local unalloc_end_sector=$2
				local unalloc_length_sectors=$((unalloc_end_sector - unalloc_start_sector))
				local overlap_length_sectors=$((overlap_end_sector - overlap_start_sector))
				if ((overlap_length_sectors < unalloc_length_sectors)); then
					# return unused portion to unalloc_map
					unalloc_map+=("${unalloc_start_sector} $((unalloc_end_sector - overlap_length_sectors))")
					unalloc_start_sector=$((unalloc_end_sector - overlap_length_sectors))
					unalloc_length_sectors=${overlap_length_sectors}
				fi
				echo >&${blockplan_fd} \
					$((source_start_sector + (overlap_start_sector - target_start_sector))) \
					${unalloc_start_sector} \
					${unalloc_length_sectors}
				insert_into_allocation_map tmpdst_map \
					${unalloc_start_sector} \
					${unalloc_end_sector} \
					${overlap_start_sector}
				((overlap_start_sector += unalloc_length_sectors))
			done
		else
			echo >&${blockplan_fd} \
				${source_start_sector} \
				${target_start_sector} \
				$((source_end_sector - source_start_sector))
		fi
	done

	# restore overlapped sectors
	while ((${#tmpdst_map[@]})); do
		set -- ${tmpdst_map[-1]}
		unset 'tmpdst_map[-1]'
		source_start_sector=$1
		source_end_sector=$2
		target_start_sector=$3
		echo >&${blockplan_fd} \
			${source_start_sector} \
			${target_start_sector} \
			$((source_end_sector - source_start_sector))
	done

	# close blockplan
	exec {blockplan_fd}>&-
}

cleanup_mid_directory() {
	quietly_umount /d2a/mid
	rm -rf --one-file-system /d2a/mid
}

add_binary_to_mid() {
	mkdir -p $(dirname /d2a/mid/$1)
	cp $1 /d2a/mid/$1
	ldd $1 | grep -o '/[^ ]* (0x[0-9a-f]*)' |
		while read libpath ignored; do
			[ -e /d2a/mid/${libpath} ] && continue
			mkdir -p $(dirname /d2a/mid/${libpath})
			cp ${libpath} /d2a/mid/${libpath}
		done
}

stage3_prepare_exit() {
	set +e
	cleanup_mid_directory
}

stage3_prepare() {
	trap stage3_prepare_exit EXIT
	cleanup_mid_directory
	mkdir -p /d2a/mid

	# mount tmpfs
	mount -t tmpfs mid /d2a/mid

	# add binaries
	add_binary_to_mid /bin/busybox
	add_binary_to_mid /bin/bash

	# create symlinks
	local dir
	for dir in bin sbin usr/bin usr/sbin; do mkdir -p /d2a/mid/${dir}; done
	ln -s bash /d2a/mid/bin/sh
	chroot /d2a/mid /bin/busybox --install

	# create directories (will be filled by systemd)
	mkdir /d2a/mid/{proc,sys,dev}

	# copy in the blockplan
	cp /d2a/blockplan /d2a/mid/blockplan

	# write out flags
	write_flags /d2a/mid/flags

	# copy myself
	cat "$0" >/d2a/mid/init
	chmod 0755 /d2a/mid/init

	# detach all loop devices
	losetup -D || true

	# reboot!
	log "The machine will now reboot."
	log "Check the console for errors if the machine is still unaccessible after a few minutes."
	sleep 1
	trap - EXIT
	systemctl switch-root /d2a/mid /init
}

stage4_convert_exit() {
	log "Error occurred. You're on your own!"
	exec /bin/bash
}

stage4_convert() {
	# /dev/console doesn't work, log to /dev/tty0
	exec </dev/tty0
	exec >/dev/tty0
	exec 2>/dev/tty0

	# run stage4_convert_exit upon error
	trap stage4_convert_exit EXIT

	# ensure that all other processes are dead
	sysctl -w kernel.sysrq=1 >/dev/null
	echo i >/proc/sysrq-trigger

	# unmount old root
	local retry
	if [ -e /mnt ] && [ $(stat -c %d /mnt) -ne $(stat -c %d /) ]; then
		for retry in 1 2 3 4 5; do
			if umount /mnt; then
				retry=0
				break
			else
				sleep 1
			fi
		done
		if ((retry)); then
			umount -rl /mnt
		fi
	fi

	# get total number of sectors
	local processed_length=0
	local total_length=$(awk '{x+=$3}END{print+x}' /blockplan)
	local prev_percentage=-1
	local next_percentage=-1

	# execute the block plan
	local source_sector target_sector extent_length
	while read source_sector target_sector extent_length; do
		# increment processed length before extent length gets optimized
		((processed_length += extent_length)) || true
		# optimize extent length
		local transfer_size=${sector_size}
		until (((source_sector & 1) || (target_sector & 1) || (\
			extent_length & 1) || (transfer_size >= 0x100000))); do
			((source_sector >>= 1, target_sector >>= 1, extent_length >>= 1, \
			transfer_size *= 2)) || true
		done
		# do the actual transfer
		dd if=/dev/vda of=/dev/vda bs=${transfer_size} \
			skip=${source_sector} seek=${target_sector} \
			count=${extent_length} 2>/dev/null
		# print out the percentage
		next_percentage=$((100 * processed_length / total_length))
		if ((next_percentage != prev_percentage)); then
			printf "\rTransferring blocks ... %s%%" ${next_percentage}
			prev_percentage=${next_percentage}
		fi
	done </blockplan
	echo

	# reread partition table
	blockdev --rereadpt /dev/vda

	# install bootloader
	mkdir /archroot
	mount /dev/vda3 /archroot
	mount -t proc proc /archroot/proc
	mount -t sysfs sys /archroot/sys
	mount -t devtmpfs dev /archroot/dev
	chroot /archroot sed -i "s/GRUB_TIMEOUT=5/GRUB_TIMEOUT=${grub_timeout}/" /etc/default/grub
	chroot /archroot mkdir -p /boot/grub
	chroot /archroot grub-mkconfig -o /boot/grub/grub.cfg
	chroot /archroot grub-install /dev/vda
	chroot /archroot ln -sf /usr/share/zoneinfo/UTC /etc/localtime
	umount /archroot/dev
	umount /archroot/sys
	umount /archroot/proc
	umount /archroot

	# we're done!
	sync
	reboot -f
}

reinstall_digitalocean_synchronize() {
	local build_dir=$(mktemp -d)
	extract_digitalocean_synchronize ${build_dir}
	(cd ${build_dir} && env EUID=1 makepkg --install --noconfirm)
}

if [ -e /var/lib/pacman ]; then
	if [ $# -eq 0 ]; then
		reinstall_digitalocean_synchronize
	else
		log "Run this script to install/update the digitalocean-synchronize package."
	fi
	exit 0
fi

if [ $$ -ne 1 ]; then
	parse_flags "$@"
	sanity_checks
	validate_flags_and_augment_globals
	prompt_for_destruction
	stage1_install
	stage2_arrange
	stage3_prepare
else
	read_flags /flags
	validate_flags_and_augment_globals
	stage4_convert
fi

exit 0

# Line below delineates start of base64 data, DO NOT MODIFY.
### digitalocean-synchronize ###
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
UAAA
