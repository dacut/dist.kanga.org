#!/bin/bash

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
else
    echo "Unable to determine OS type; assuming RedHat";
    ID="rhel";
fi;

error () {
    echo "$@" 1>&2;
}

update-and-reboot-if-required () {
    case "$ID" in
        amzn | fedora | rhel )
            yum check-update
            if [[ $? -eq 100 ]]; then
                # Updates required.  Install them and reboot.
                if ! yum -y update; then
                    error "yum -y update failed";
                    return 1;
                fi;
                reboot
            fi;;

        debian | ubuntu )
            apt-get update
            if apt-get dist-upgrade --simulate | \
                grep "The following packages will be upgraded"; then
                if ! DEBIAN_FRONTEND=noninteractive apt-get -y \
                    --option Dpkg::Options::="--force-confdef" \
                    --option Dpkg::Options::="--force-confold" dist-upgrade;
                then
                    error "apt-get dist-upgrade failed";
                    return 1;
                fi;
                reboot || exit 1;
            fi;;

        * )
            error "Unsupported system $ID";
            return 2;;
    esac;

    return 0;
}

install-required-packages () {
    case "$ID" in
        amzn | fedora | rhel )
            if ! yum -y install autoconf automake gcc git glib2-devel \
                libtool rpm-devel rpmlint; then
                error "Failed to install additional build tools via yum";
                return 1;
            fi;;

        debian | ubuntu )
            if ! DEBIAN_FRONTEND=noninteractive apt-get -y \
                --option Dpkg::Options::="--force-confdef" \
                --option Dpkg::Options::="--force-confold" install \
                autoconf automake awscli debian-builder gcc git libglib2.0 \
                libglib2.0-dev libtool python-pip; then
                error "Failed to install additional build tools via apt-get";
                return 1;
            fi;;

        * )
            error "Unsupported system $ID";
            return 2;;
    esac;

    if ! pip install --upgrade awscli boto; then
        error "Failed to install awscli and boto via pip";
        return 1;
    fi;

    return 0;
}

update-and-reboot-if-required
install-required-packages

