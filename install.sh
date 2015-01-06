#!/bin/bash

################################################################################
### INSTRUCTIONS AT https://github.com/gh2o/digitalocean-debian-to-arch/     ###
################################################################################

run_from_file() {
	local f t
	for f in /dev/fd/*; do
		[ -h ${f} ] || continue
		[ ${f} -ef "${0}" ] && return
	done
	t=$(mktemp)
	cat >${t}
	if [ "$(head -n 1 ${t})" = '#!/bin/bash' ]; then
		chmod +x ${t}
		exec /bin/bash ${t} "$@" </dev/fd/2
	else
		rm -f ${t}
		echo "Direct execution not supported with this shell ($_)." >&2
		echo "Please try bash instead." >&2
		exit 1
	fi
}

# do not modify the two lines below
[ -h /dev/fd/0 ] && run_from_file
#!/bin/bash

########################################
### CONFIGURATION                    ###
########################################

# mirror from which to download packages
archlinux_mirror="https://mirrors.kernel.org/archlinux/"

# migrate over home directories
preserve_home_directories=true

# package to use as kernel (linux or linux-lts)
kernel_package=linux

# migrated machine architecture
target_architecture="$(uname -m)"

########################################
### END OF CONFIGURATION             ###
########################################

if [ -n "${POSIXLY_CORRECT}" ] || [ -z "${BASH_VERSION}" ]; then
	unset POSIXLY_CORRECT
	exec /bin/bash "${0}" "$@"
	exit 1
fi

set -eu
set -o pipefail
shopt -s nullglob
shopt -s dotglob
umask 022

export LC_ALL=C
export LANG=C
unset LANGUAGE

declare -a repositories
repositories=(core extra)
declare -A dependencies
dependencies[pacman]=x
dependencies[coreutils]=x
declare -A pkgdircache

log() {
	echo "[$(date)]" "$@" >&2
}

extract_embedded_file() {
	gawk -e '$0=="!!!!"{p=0};p;$0=="!!!!"n{p=1}' n="${1}" "${script_path}"
}

install_compat_package() {

	local workdir=$(mktemp -d)
	local unitdir=${workdir}/usr/lib/systemd/system
	local kexeccmd

	set -- /sbin/kexec \
		/boot/vmlinuz-${kernel_package} \
		--initrd=/boot/initramfs-${kernel_package}.img \
		--reuse-cmdline \
		--command-line=archkernel
	kexeccmd="$*"

	cat > ${workdir}/.PKGINFO <<-'EOF'
		pkgname = digitalocean-debian-compat
		pkgver = 1.0-1
		pkgdesc = Compatibility files to run Arch Linux as a Debian distro on DigitalOcean
		url = https://github.com/gh2o/digitalocean-debian-to-arch
		arch = any
		license = GPL
	EOF

	mkdir -p ${unitdir}/sysinit.target.wants/
	ln -s ../arch-kernel.service ${unitdir}/sysinit.target.wants/
	cat > ${unitdir}/arch-kernel.service <<-EOF
		[Unit]
		Description=Reboots into Arch kernel
		ConditionKernelCommandLine=!archkernel
		DefaultDependencies=no
		Before=local-fs-pre.target systemd-remount-fs.service

		[Service]
		Type=oneshot
		ExecStart=${kexeccmd}
	EOF

	mkdir -p ${unitdir}/multi-user.target.wants/
	ln -s ../debian-interfaces.service ${unitdir}/multi-user.target.wants/
	cat > ${unitdir}/debian-interfaces.service <<-EOF
		[Unit]
		Description=Parses /etc/network/interfaces into .network files for systemd-networkd
		DefaultDependencies=no
		Before=systemd-networkd.service

		[Service]
		Type=oneshot
		ExecStart=/usr/sbin/parse-debian-interfaces
	EOF

	mkdir -p ${workdir}/usr/bin/
	extract_embedded_file parse-debian-interfaces > \
		${workdir}/usr/bin/parse-debian-interfaces
	chmod 0755 ${workdir}/usr/bin/parse-debian-interfaces

	( cd ${workdir} && bsdtar -cf compat.pkg.tar * )
	pacman -U --noconfirm ${workdir}/compat.pkg.tar
	rm -rf ${workdir}

}

clean_archroot() {
	local file
	local prompted=false
	local lsfd
	while read file <&${lsfd}; do
		if [ "${file}" = "installer" ] || [ "${file}" = "packages" ]; then
			continue
		fi
		if ! $prompted; then
			log "Your /archroot directory contains a stale installation or other data."
			log "Remove it?"
			local response
			read -p '([yes] or no) ' response
			if [[ "yes" == "${response}"* ]]; then
				prompted=true
			else
				break
			fi
		fi
		rm -rf "/archroot/${file}"
	done {lsfd}< <(ls /archroot)
}

install_haveged() {
	if which haveged >/dev/null 2>&1; then
		return
	fi
	log "Creating keys for pacman will be very slow because"
	log "KVM lacks true sources of ramdomness. Install haveged"
	log "to speed it up?"
	local response
	read -p '([yes] or no) ' response
	if [[ "yes" == "${response}"* ]]; then
		apt-get -y install haveged
	fi
}

remove_version() {
	echo "${1}" | grep -o '^[A-Za-z0-9_-]*'
}

initialize_databases() {
	local repo dir pkg
	for repo in "${repositories[@]}"; do
		log "Downloading package database '${repo}' ..."
		wget "${archlinux_mirror}/${repo}/os/${target_architecture}/${repo}.db"
		log "Unpacking package database '${repo}' ..."
		mkdir ${repo}
		tar -zxf ${repo}.db -C ${repo}
	done
}

get_package_directory() {

	local req="${1}"
	local repo dir pkg

	dir="${pkgdircache[${req}]:-}"
	if [ -n "${dir}" ]; then
		echo "${dir}"
		return
	fi

	for repo in "${repositories[@]}"; do
		for dir in ${repo}/${req}-*; do
			pkg="$(get_package_value ${dir}/desc NAME)" 
			pkgdircache[${pkg}]="${dir}"
			if [ "${pkg}" = "${req}" ]; then
				echo "${dir}"
				return
			fi
		done
	done

	for repo in "${repositories[@]}"; do
		for dir in ${repo}/*; do
			while read pkg; do
				pkg=$(remove_version "${pkg}")
				[ -z "${pkgdircache[${pkg}]:-}" ] &&
					pkgdircache[${pkg}]="${dir}"
				if [ "${pkg}" = "${req}" ]; then
					echo "${dir}"
					return
				fi
			done < <(get_package_array ${dir}/depends PROVIDES)
		done
	done

	log "Package '${req}' not found."
	false

}

get_package_value() {
	local infofile=${1}
	local infokey=${2}
	get_package_array ${infofile} ${infokey} | (
		local value
		read value
		echo "${value}"
	)
}

get_package_array() {
	local infofile=${1}
	local infokey=${2}
	local line
	while read line; do
		if [ "${line}" = "%${infokey}%" ]; then
			while read line; do
				if [ -z "${line}" ]; then
					return
				fi
				echo "${line}"
			done
		fi
	done < ${infofile}
}

calculate_dependencies() {
	log "Calculating dependencies ..."
	local dirty=true
	local pkg dir dep
	while $dirty; do
		dirty=false
		for pkg in "${!dependencies[@]}"; do
			dir=$(get_package_directory $pkg)
			while read line; do
				dep=$(remove_version "${line}")
				if [ -z "${dependencies[$dep]:-}" ]; then
					dependencies[$dep]=x
					dirty=true
				fi
			done < <(get_package_array ${dir}/depends DEPENDS)
		done
	done
}

download_packages() {
	log "Downloading packages ..."
	mkdir -p /archroot/packages
	local pkg dir filename sha256 localfn
	for pkg in "${!dependencies[@]}"; do
		dir=$(get_package_directory ${pkg})
		filename=$(get_package_value ${dir}/desc FILENAME)
		sha256=$(get_package_value ${dir}/desc SHA256SUM)
		localfn=/archroot/packages/${filename}
		if [ -e "${localfn}" ] && ( echo "${sha256}  ${localfn}" | sha256sum -c ); then
			continue
		fi
		wget "${archlinux_mirror}/pool/packages/${filename}" -O "${localfn}"
		if [ -e "${localfn}" ] && ( echo "${sha256}  ${localfn}" | sha256sum -c ); then
			continue
		fi
		log "Couldn't download package '${pkg}'."
		false
	done
}

extract_packages() {
	log "Extracting packages ..."
	local dir filename
	for pkg in "${!dependencies[@]}"; do
		dir=$(get_package_directory ${pkg})
		filename=$(get_package_value ${dir}/desc FILENAME)
		xz -dc /archroot/packages/${filename} | tar -C /archroot -xf -
	done
}

mount_virtuals() {
	log "Mounting virtual filesystems ..."
	mount -t proc proc /archroot/proc
	mount -t sysfs sys /archroot/sys
	mount --bind /dev /archroot/dev
	mount -t devpts pts /archroot/dev/pts
}

prebootstrap_configuration() {
	log "Doing pre-bootstrap configuration ..."
	rmdir /archroot/var/cache/pacman/pkg
	ln -s ../../../packages /archroot/var/cache/pacman/pkg
	chroot /archroot /sbin/trust extract-compat
}

bootstrap_system() {

	local shouldbootstrap=false isbootstrapped=false
	while ! $isbootstrapped; do
		if $shouldbootstrap; then
			log "Bootstrapping system ..."
			chroot /archroot pacman-key --init
			chroot /archroot pacman-key --populate archlinux
			chroot /archroot pacman -Sy
			chroot /archroot pacman -S --force --noconfirm \
				$(chroot /archroot pacman -Sgq base | grep -Fvx linux) \
				${kernel_package} openssh kexec-tools
			isbootstrapped=true
		else
			shouldbootstrap=true
		fi
		# config overwritten by pacman
		rm -f /archroot/etc/resolv.conf.pacorig
		cp /etc/resolv.conf /archroot/etc/resolv.conf
		rm -f /archroot/etc/pacman.d/mirrorlist.pacorig
		echo "Server = ${archlinux_mirror}"'/$repo/os/$arch' \
			>> /archroot/etc/pacman.d/mirrorlist
	done

}

postbootstrap_configuration() {

	log "Doing post-bootstrap configuration ..."

	# set up fstab
	echo "LABEL=DOROOT / ext4 defaults 0 1" >> /archroot/etc/fstab

	# set up hostname
	[ -e /etc/hostname ] && cp /etc/hostname /archroot/etc/hostname

	# set up shadow
	(
		umask 077
		{
			grep    '^root:' /etc/shadow
			grep -v '^root:' /archroot/etc/shadow
		} > /archroot/etc/shadow.new
		cat /archroot/etc/shadow.new > /archroot/etc/shadow
		rm /archroot/etc/shadow.new
	)

	# copy interfaces file
	mkdir -p /archroot/etc/network/
	cp /etc/network/interfaces /archroot/etc/network/interfaces

	# copy over ssh keys
	cp -p /etc/ssh/ssh_*_key{,.pub} /archroot/etc/ssh/

	# optionally preserve home directories
	if ${preserve_home_directories}; then
		rm -rf /archroot/{home,root}
		cp -al /{home,root} /archroot/
	fi

	# setup machine id
	chroot /archroot systemd-machine-id-setup

	# enable services
	chroot /archroot systemctl enable systemd-networkd
	chroot /archroot systemctl enable sshd

	# install services
	local unitdir=/archroot/etc/systemd/system

	mkdir -p ${unitdir}/basic.target.wants
	ln -s ../installer-finalize.service ${unitdir}/basic.target.wants/
	cat > ${unitdir}/installer-finalize.service <<EOF
[Unit]
Description=Post-install finalization
ConditionPathExists=/installer/script.sh

[Service]
Type=oneshot
ExecStart=/installer/script.sh
EOF

}

installer_error_occurred() {
	log "Error occurred. Exiting."
}

installer_exit_cleanup() {
	log "Cleaning up ..."
	set +e
	umount /archroot/dev/pts
	umount /archroot/dev
	umount /archroot/sys
	umount /archroot/proc
}

installer_main() {

	if [ "${EUID}" -ne 0 ] || [ "${UID}" -ne 0 ]; then
		log "Script must be run as root. Exiting."
		exit 1
	fi

	if ! grep -q '^7\.' /etc/debian_version; then
		log "This script only supports Debian 7.x. Exiting."
		exit 1
	fi

	trap installer_error_occurred ERR
	trap installer_exit_cleanup EXIT

	log "Ensuring correct permissions ..."
	chmod 0700 "${script_path}"

	rm -rf /archroot/installer
	mkdir -p /archroot/installer
	cd /archroot/installer

	clean_archroot
	install_haveged

	initialize_databases
	calculate_dependencies
	download_packages
	extract_packages

	mount_virtuals
	prebootstrap_configuration
	bootstrap_system
	postbootstrap_configuration

	# prepare for transtiory_main
	mv /sbin/init /sbin/init.original
	cp "${script_path}" /sbin/init
	reboot

}

transitory_exit_occurred() {
	# not normally called
	log "Error occurred! You're on your own."
	exec /bin/bash
}

transitory_main() {

	trap transitory_exit_occurred EXIT
	if [ "${script_path}" = "/sbin/init" ]; then
		# save script
		mount -o remount,rw /
		cp "${script_path}" /archroot/installer/script.sh
		# restore init in case anything goes wrong
		rm /sbin/init
		mv /sbin/init.original /sbin/init
		# unmount other filesystems
		if ! [ -e /proc/mounts ]; then
			mount -t proc proc /proc
		fi
		local device mountpoint fstype ignored
		while IFS=" " read device mountpoint fstype ignored; do
			if [ "${device}" == "${device/\//}" ] && [ "${fstype}" != "rootfs" ]; then
				umount -l "${mountpoint}"
			fi
		done < <(tac /proc/mounts)
		# mount real root
		mkdir /archroot/realroot
		mount --bind / /archroot/realroot
		# chroot into archroot
		exec chroot /archroot /installer/script.sh
	elif [ "${script_path}" = "/installer/script.sh" ]; then
		# now in archroot
		local oldroot=/realroot/archroot/oldroot
		mkdir ${oldroot}
		# move old files into oldroot
		log "Backing up old root ..."
		local entry
		for entry in /realroot/*; do
			if [ "${entry}" != "/realroot/archroot" ]; then
				mv "${entry}" ${oldroot}
			fi
		done
		# hardlink files into realroot
		log "Populating new root ..."
		cd /
		mv ${oldroot} /realroot
		for entry in /realroot/archroot/*; do
			if [ "${entry}" != "/realroot/archroot/realroot" ]; then
				cp -al "${entry}" /realroot
			fi
		done
		# done!
		log "Rebooting ..."
		mount -t proc proc /proc
		mount -o remount,ro /realroot
		sync
		umount /proc
		reboot -f
	else
		log "Unknown state! You're own your own."
		exec /bin/bash
	fi

}

finalize_main() {

	# install compatibility package
	install_compat_package

	# remove finalization service
	local unitdir=/etc/systemd/system
	rm -f ${unitdir}/installer-finalize.service
	rm -f ${unitdir}/basic.target.wants/installer-finalize.service
	rmdir ${unitdir}/basic.target.wants || true

	# cleanup filesystem
	rm -f /var/cache/pacman/pkg
	mv /packages /var/cache/pacman/pkg
	rm -f /.INSTALL /.MTREE /.PKGINFO
	rm -rf /archroot
	rm -rf /installer

	# restart into new kernel
	systemctl daemon-reload
	systemctl start arch-kernel.service

}

canonicalize_path() {
	local basename="$(basename "${1}")"
	local dirname="$(dirname "${1}")"
	(
		cd "${dirname}"
		echo "$(pwd -P)/${basename}"
	)
}

script_path="$(canonicalize_path "${0}")"
if [ $$ -eq 1 ]; then
	transitory_main "$@"
elif [ "${script_path}" = "/sbin/init" ]; then
	exec /sbin/init.original "$@"
elif [ "${script_path}" = "/installer/script.sh" ]; then
	finalize_main "$@"
else
	installer_main "$@"
fi
exit 0

: <<EMBED
!!!!parse-debian-interfaces
#!/usr/bin/gawk -bf

function iface_setprop(prop, val,   suffix) {
	suffix = iface_family == "inet6" ? 6 : 4
	interfaces[iface_name][prop suffix] = val
}

function iface_getprop(prop, suffix) {
	return interfaces[iface_name][prop suffix]
}

function iface_dump(suffix, fn,   addr, pfx, dnss) {
	addr = iface_getprop("address", suffix)
	pfx = iface_getprop("netmask", suffix)
	if (addr && pfx)
		print "Address=" addr "/" pfx > fn
	else
		return
	addr = iface_getprop("gateway", suffix)
	if (addr)
		print "Gateway=" addr > fn
	split(iface_getprop("dns", suffix), dnss, "|")
	for (i = 1; i in dnss; i++)
		print "DNS=" dnss[i] > fn
}

function netmask_to_prefix(mask,   cmps, bit, pfx) {
	if (mask ~ /\./) {
		pfx = 0
		split(mask, cmps, ".")
		do {
			bit = and(cmps[rshift(pfx, 3) + 1],
					  lshift(1, 7 - and(pfx, 7)))
		} while (bit && ++pfx < 32)
	} else {
		pfx = mask
	}
	return pfx
}

BEGIN {
	netdir = "/run/systemd/network"
	if (system("mkdir -p " netdir) != 0)
		exit 1
}

$1 == "iface" {
	iface_name = $2
	iface_family = $3
	iface_type = $4
	active = (iface_type == "static") &&
	         (iface_family == "inet" || iface_family == "inet6")
}

active && ($1 ~ /^(address|netmask|gateway)$/) {
	($1 == "netmask") && ($2 = netmask_to_prefix($2))
	iface_setprop($1, $2)
}

active && $1 == "dns-nameservers" {
	joined = ""
	for (i = 2; $i; i++)
		joined = joined ? joined "|" $i : $i
	iface_setprop("dns", joined)
}

END {
	for (iface_name in interfaces) {
		fn = netdir "/" iface_name ".network"
		print "# Generated by parse-debian-interfaces" > fn
		print "" > fn
		print "[Match]" > fn
		print "Name=" iface_name > fn
		print "" > fn
		print "[Network]" > fn
		iface_dump(4, fn)
		iface_dump(6, fn)
		close(fn)
	}
}
!!!!
EMBED

#################
# END OF SCRIPT #
#################
