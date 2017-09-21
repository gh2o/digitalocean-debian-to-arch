#!/bin/bash

################################################################################
### INSTRUCTIONS AT https://github.com/gh2o/digitalocean-debian-to-arch/     ###
################################################################################

run_from_file() {
	local f t
	for f in /dev/fd/*; do
		[ -h $f ] || continue
		[ $f -ef "$0" ] && return
	done
	t=$(mktemp)
	cat > $t
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
	target_architecture
	target_disklabel
	target_filesystem
	mkfs_options
)

host_packages=(
	haveged
	parted
	psmisc
	busybox
)

arch_packages=(
	grub
	openssh
	wget     # for digitalocean-synchronize
	fakeroot # for makepkg
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
	awk 'x {print} $0 == "### digitalocean-synchronize ###" {x=1}' "$0" | \
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
		gpt)
			;;
		dos)
			;;
		*)
			fatal "Unknown disklabel type: ${target_disklabel}"
			;;
	esac
	case "${target_filesystem}" in
		ext4)
			;;
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
	} > ${filename}
}

sanity_checks() {
	[ ${EUID} -eq 0 ] || fatal "Script must be run as root."
	[ ${UID} -eq 0 ] || fatal "Script must be run as root."
	[ -e /dev/vda ] || fatal "Script must be run on a KVM machine."
	[[ "$(cat /etc/debian_version)" == [89].? ]] || \
		fatal "This script only supports Debian 8.x/9.x."
}

prompt_for_destruction() {
	(( continue_without_prompting )) && return 0
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
	local expected_sha1="$3"
	for try in {0..3}; do
		if [ ${try} -eq 0 ]; then
			[ -e "${local_path}" ] || continue
		else
			wget -O "${local_path}" "${file_url}"
		fi
		set -- $(sha1sum "${local_path}")
		if [ $1 = "${expected_sha1}" ]; then
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
		find /proc -maxdepth 2 -name root -lname $1 | \
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
	cat > /d2a/work/doroot/README <<-EOF
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
	set -- $(wget -qO- ${archlinux_mirror}/iso/latest/sha1sums.txt |
		grep "archlinux-bootstrap-[^-]*-${target_architecture}.tar.gz")
	local expected_sha1=$1
	local bootstrap_filename=$2
	download_and_verify \
		${archlinux_mirror}/iso/latest/${bootstrap_filename} \
		/d2a/bootstrap.tar.gz \
		${expected_sha1}

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
	echo "Server = ${archlinux_mirror}/\$repo/os/\$arch" > /d2a/work/archroot/etc/pacman.d/mirrorlist
	echo 'nameserver 8.8.8.8' > /d2a/work/archroot/etc/resolv.conf

	log "Installing base system ..."
	chroot /d2a/work/archroot pacman-key --init
	chroot /d2a/work/archroot pacman-key --populate archlinux
	local chroot_pacman="chroot /d2a/work/archroot pacman --arch ${target_architecture} --force"
	${chroot_pacman} -Sy
	${chroot_pacman} -Su --noconfirm --needed \
		$(${chroot_pacman} -Sgq base | grep -v '^linux$') \
		${arch_packages[@]} ${extra_packages}

	log "Configuring base system ..."
	hostname > /d2a/work/archroot/etc/hostname
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
		cat >> /d2a/work/archroot/etc/ssh/sshd_config <<-EOF

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
	while (( lo < hi )); do
		local mid=$(((lo+hi)/2))
		set -- ${allocation_map[$mid]}
		if (( $# == 0 )) || (( $1 < alloc_start_sector )); then
			lo=$((mid+1))
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
		(( ${map_length} )) || continue
		local bisection_index
		bisect_left_on_allocation ${check_start_sector} ${check_end_sector} \
			bisection_index ${map_name}
		local check_index
		for check_index in $((bisection_index - 1)) $((bisection_index)); do
			(( check_index < 0 || check_index >= map_length )) && continue
			set -- ${allocation_map[${check_index}]}
			(( $# == 0 )) && continue
			local alloc_start_sector=$1
			local alloc_end_sector=$2
			(( check_start_sector >= alloc_end_sector || alloc_start_sector >= check_end_sector )) && continue
			# overlap detected
			cfao_overlap_start_sector=$((alloc_start_sector > check_start_sector ?
				alloc_start_sector : check_start_sector))
			cfao_overlap_end_sector=$((alloc_end_sector < check_end_sector ?
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
	if (( ${#allocation_map[@]} == 0 )); then
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
	local srcdst_map=()     # original source to target map
	local unalloc_map=()    # extents not used by either source or target (for tmpdst_map)
	local tmpdst_map=()     # extents on temporary redirection (allocated from unalloc_map)
	local source_start_sector source_end_sector target_start_sector target_end_sector

	log "Creating block rearrangement plan ..."

	# get and sort extents
	filefrag -e -s -v -b${sector_size} /d2a/image | \
		sed '/^ *[0-9]*:/!d;s/[:.]/ /g' | \
		sort -nk4 > /d2a/imagemap
	while read line; do
		set -- ${line}
		source_start_sector=$(($4 + root_offset_sectors))
		source_end_sector=$((source_start_sector + $6))
		target_start_sector=$2
		target_end_sector=$((target_start_sector + $6))
		echo ${source_start_sector} ${source_end_sector}
		echo ${target_start_sector} ${target_end_sector}
		srcdst_map+=("${source_start_sector} ${source_end_sector} ${target_start_sector}")
	done < /d2a/imagemap > /d2a/unsortedallocs
	sort -n < /d2a/unsortedallocs > /d2a/sortedallocs

	# build map of unallocated sectors
	local unalloc_start_sector=0 unalloc_end_sector=${disk_sectors}
	while read source_start_sector source_end_sector; do
		if (( source_end_sector <= unalloc_start_sector )); then
			# does not overlap unallocated part
			continue
		elif (( source_start_sector > unalloc_start_sector )); then
			# full overlap with unallocated part
			unalloc_map+=("${unalloc_start_sector} ${source_start_sector}")
			unalloc_start_sector=${source_end_sector}
		else
			# partial overlap
			unalloc_start_sector=${source_end_sector}
		fi
	done < /d2a/sortedallocs
	if (( unalloc_start_sector != unalloc_end_sector )); then
		unalloc_map+=("${unalloc_start_sector} ${unalloc_end_sector}")
	fi

	# open blockplan
	exec {blockplan_fd}>/d2a/blockplan

	# arrange sectors
	while (( ${#srcdst_map[@]} )); do
		set -- ${srcdst_map[-1]}
		source_start_sector=$1
		source_end_sector=$2
		target_start_sector=$3
		target_end_sector=$((target_start_sector + (source_end_sector - source_start_sector)))
		if (( source_start_sector == target_start_sector )); then
			# source data is already at target destination, no need to do anything
			unset 'srcdst_map[-1]'
			continue
		elif (( target_start_sector >= source_end_sector ||
				source_start_sector >= target_end_sector )); then
			# source and target extents don't overlap. just pop this entry off the list
			unset 'srcdst_map[-1]'
		else
			# source and target extents overlap.
			if (( source_start_sector > target_start_sector )); then
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
		if (( overlap_end_sector )); then
			# insert non-overlapping parts back into srcdst_map
			if (( target_start_sector < overlap_start_sector )); then
				local nonoverlap_length_sectors=$((overlap_start_sector - target_start_sector))
				insert_into_allocation_map srcdst_map \
					${source_start_sector} \
					$((source_start_sector + nonoverlap_length_sectors)) \
					${target_start_sector}
			fi
			if (( target_end_sector > overlap_end_sector )); then
				local nonoverlap_length_sectors=$((target_end_sector - overlap_end_sector))
				insert_into_allocation_map srcdst_map \
					$((source_end_sector - nonoverlap_length_sectors)) \
					${source_end_sector} \
					${overlap_end_sector}
			fi
			# copy overlapping portion into tmpdst_map
			while (( overlap_start_sector < overlap_end_sector )); do
				set -- ${unalloc_map[-1]}
				unset 'unalloc_map[-1]'  # or nullglob will eat it up
				local unalloc_start_sector=$1
				local unalloc_end_sector=$2
				local unalloc_length_sectors=$((unalloc_end_sector - unalloc_start_sector))
				local overlap_length_sectors=$((overlap_end_sector - overlap_start_sector))
				if (( overlap_length_sectors < unalloc_length_sectors )); then
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
				(( overlap_start_sector += unalloc_length_sectors ))
			done
		else
			echo >&${blockplan_fd} \
				${source_start_sector} \
				${target_start_sector} \
				$((source_end_sector - source_start_sector))
		fi
	done

	# restore overlapped sectors
	while (( ${#tmpdst_map[@]} )); do
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
	ldd $1 | grep -o '/[^ ]* (0x[0-9a-f]*)' | \
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
	cat "$0" > /d2a/mid/init
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
	exec /bin/bash </dev/console >/dev/console 2>&1
}

stage4_convert() {
	trap stage4_convert_exit EXIT

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
		if (( retry )); then
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
		(( processed_length += extent_length )) || true
		# optimize extent length
		local transfer_size=${sector_size}
		until (( (source_sector & 1) || (target_sector & 1) ||
				(extent_length & 1) || (transfer_size >= 0x100000) )); do
			(( source_sector >>= 1 , target_sector >>= 1 , extent_length >>= 1,
				transfer_size *= 2 )) || true
		done
		# do the actual transfer
		dd if=/dev/vda of=/dev/vda bs=${transfer_size} \
			skip=${source_sector} seek=${target_sector} \
			count=${extent_length} 2>/dev/null
		# print out the percentage
		next_percentage=$((100 * processed_length / total_length))
		if (( next_percentage != prev_percentage )); then
			printf "\rTransferring blocks ... %s%%" ${next_percentage}
			prev_percentage=${next_percentage}
		fi
	done < /blockplan
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
	chroot /archroot grub-mkconfig -o /boot/grub/grub.cfg
	chroot /archroot grub-install /dev/vda
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
	( cd ${build_dir} && env EUID=1 makepkg --install --noconfirm )
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
