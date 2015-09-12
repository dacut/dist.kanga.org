#!/bin/bash

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
else
    echo "Unable to determine OS type; assuming RedHat";
    ID="rhel";
fi;

AVAILABILITY_ZONE="`curl --silent http://169.254.169.254/2014-11-05/meta-data/placement/availability-zone`";
REGION="`echo $AVAILABILITY_ZONE | sed -e 's/[a-z]$//'`";

error () {
    echo "$@" 1>&2;
}

start-cloudwatch () {
    if [[ ! -r /etc/cloudwatch-logs.cfg ]]; then
        cat > /etc/cloudwatch-logs.cfg <<EOF
[general]
state_file = /var/awslogs/state/agent-state

[cloud-init]
file = /var/log/cloud-init.log
log_group_name = syslog
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S

[cloud-init-output]
file = /var/log/cloud-init-output.log
log_group_name = syslog
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
EOF
        
        if [[ -e /var/log/messages ]]; then
            cat >> /etc/cloudwatch-logs.cfg <<EOF
[messages]
file = /var/log/messages
log_group_name = syslog
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
EOF
        fi;

        if [[ -e /var/log/syslog ]]; then
            cat >> /etc/cloudwatch-logs.cfg <<EOF
[syslog]
file = /var/log/syslog
log_group_name = syslog
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
EOF
        fi;

        if [[ -e /var/log/boot.log ]]; then
            cat >> /etc/cloudwatch-logs.cfg <<EOF
[boot]
file = /var/log/boot.log
log_group_name = syslog
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
EOF
        fi;

        if [[ -e /var/log/kern.log ]]; then
            cat >> /etc/cloudwatch-logs.cfg <<EOF
[syslog]
file = /var/log/kern.log
log_group_name = syslog
log_stream_name = {instance_id}
datetime_format = %b %d %H:%M:%S
EOF
        fi;
    fi;

    if ! service awslogs start; then
        if ! wget -O /tmp/awslogs-agent-setup.py \
            'https://s3.amazonaws.com/aws-cloudwatch/downloads/latest/awslogs-agent-setup.py'; then
            error "Failed to download CloudWatch Logs daemon";
            exit 1;
        fi;
            
        chmod +x /tmp/awslogs-agent-setup.py
        if ! /tmp/awslogs-agent-setup.py --non-interactive --region=$REGION \
            --configfile=/etc/cloudwatch-logs.cfg; then
            error "Failed to configure/start CloudWatch Logs daemon";
            exit 1;
        fi;
    fi;
}

update-system () {
    case "$ID" in
        amzn | fedora | rhel )
            if ! yum -y update; then
                error "Failed to install updates";
                exit 1;
            fi;
            sync
            echo "Updates installed."
            ;;

        debian | ubuntu )
            apt-get update
            if ! DEBIAN_FRONTEND=noninteractive apt-get -y \
                --option Dpkg::Options::="--force-confdef" \
                --option Dpkg::Options::="--force-confold" dist-upgrade; then
                error "Failed to install updates";
                exit 1;
            fi;
            echo "Updates installed.";;

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
                libtool rpm-devel rpmlint rpm-build createrepo; then
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

fix-sudoers-tty () {
    grep -E -v 'Defaults\s+requiretty' /etc/sudoers > /etc/sudoers.new
    mv /etc/sudoers.new /etc/sudoers
}

create-build-user () {
    useradd --comment "dist.kanga.org build user" --shell /bin/false \
        --home /home/builder builder
    cat > /etc/sudoers.d/builder <<EOF
builder ALL=(ALL) NOPASSWD:ALL
EOF
    su -s /bin/sh - builder -c 'ln -s dist.kanga.org /home/builder/rpmbuild'
}

git-clone () {
    cd /home/builder
    su -s /bin/sh - builder -c \
'cd /home/builder && git clone https://github.com/dacut/dist.kanga.org.git'
}

schedule-repository-build () {
    cat >> /etc/rc.local <<EOF
su -s /bin/sh - builder -c \
'cd /home/builder/dist.kanga.org && ./localbuild.py && ./repoupdate.py'
EOF
}

start-cloudwatch
update-system
install-required-packages
fix-sudoers-tty
create-build-user
git-clone
schedule-repository-build
reboot
