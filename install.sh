#!/bin/bash

### CONFIGURATION
archlinux_mirror="https://mirrors.kernel.org/archlinux/"

set -eu
set -o pipefail
shopt -s nullglob

### VARIABLES
declare -A dependencies
dependencies[pacman]=x

log() {
	echo "[$(date)]" "$@" >&2
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
			read -p '(yes or [no]) ' response
			if [ "${response}" = "yes" ]; then
				prompted=true
			else
				break
			fi
		fi
		rm -rf "/archroot/${file}"
	done {lsfd}< <(ls /archroot)
}

initialize_coredb() {
	log "Downloading package database ..."
	wget "${archlinux_mirror}/core/os/x86_64/core.db"
	log "Unpacking package database ..."
	mkdir core
	tar -zxf core.db -C core
}

remove_version() {
	echo "${1}" | grep -o '^[A-Za-z0-9_-]*'
}

get_package_directory() {
	local dir pkg
	for dir in core/${1}-*; do
		if [ "$(get_package_value ${dir}/desc NAME)" = "${1}" ]; then
			echo "${dir}"
			return
		fi
	done
	for dir in core/*; do
		while read pkg; do
			pkg=$(remove_version "${pkg}")
			if [ "${pkg}" = "${1}" ]; then
				echo "${dir}"
				return
			fi
		done < <(get_package_array ${dir}/depends PROVIDES)
	done
	log "Package '${1}' not found."
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
		wget "${archlinux_mirror}/core/os/x86_64/${filename}" -O "${localfn}"
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

error_occurred() {
	log "Error occurred. Exiting."
}

main() {

	if [ "${EUID}" -ne 0 ] || [ "${UID}" -ne 0 ]; then
		log "Script must be run as root. Exiting."
		exit 1
	fi

	if ! grep -q '^7\.' /etc/debian_version; then
		log "This script only supports Debian 7.x. Exiting."
		exit 1
	fi

	if [ "$(uname -m)" != "x86_64" ]; then
		log "This script only targets 64-bit machines. Exiting."
		exit 1
	fi

	trap error_occurred ERR

	rm -rf /archroot/installer
	mkdir -p /archroot/installer
	cd /archroot/installer

	clean_archroot
	initialize_coredb
	calculate_dependencies
	download_packages
	extract_packages

}

main "$@"
