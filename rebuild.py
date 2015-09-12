#!/usr/bin/env python
from __future__ import absolute_import, print_function
from base64 import b64encode
import boto.ec2
from boto.ec2.blockdevicemapping import BlockDeviceMapping, BlockDeviceType
from boto.ec2.networkinterface import (
    NetworkInterfaceCollection, NetworkInterfaceSpecification)
from csv import reader as csv_reader
from getopt import getopt, GetoptError
import logging
from os.path import dirname
from six.moves.configparser import RawConfigParser
from sys import argv, exit, stderr, stdout

class Builder(object):
    def __init__(self, subnet_id=None, key_name=None, security_groups=[],
                 os_ids=[], instance_type='t2.micro', profile=None,
                 instance_profile_name=None, virtualization_type='hvm',
                 root_size=64, region='us-west-2'):
        super(Builder, self).__init__()
        self.subnet_id = subnet_id
        self.key_name = key_name
        self.security_groups = security_groups
        self.os_ids = os_ids
        self.instance_type = instance_type
        self.profile = profile
        self.instance_profile_name = instance_profile_name
        self.virtualization_type = virtualization_type
        self.root_size = root_size
        self.region = region
        self.log = logging.getLogger("builder")
        return

    @property
    def ec2(self):
        ec2 = getattr(self, "_ec2", None)
        if ec2 is None:
            ec2 = self._ec2 = boto.ec2.connect_to_region(
                self.region, profile_name=self.profile)
        return ec2

    @classmethod
    def create_ami_map(cls):
        cls.ami_map = {}
        with open(dirname(__file__) + "/ami_map.csv", "r") as fd:
            reader = csv_reader(fd, dialect='excel-tab')
            header = reader.next()
            
            for row in reader:
                data = dict(zip(header, row))
                key = (data['os_id'], data['version'], data['region'],
                       data['virtualization_type'])
                cls.ami_map[key] = data['ami_id']
        return

    @classmethod
    def create_startup_script(cls):
        with open(dirname(__file__) + "/startup.sh", "r") as fd:
            cls.startup = b64encode(fd.read())

    def build_os(self, os_id, version):
        ami_id = self.ami_map[(os_id, version, self.region,
                               self.virtualization_type)]
        xvda = BlockDeviceType(size=self.root_size, delete_on_termination=True)
        bdm = BlockDeviceMapping()
        bdm['/dev/xvda'] = xvda

        eth0 = NetworkInterfaceSpecification(
            device_index=0, subnet_id=self.subnet_id,
            associate_public_ip_address=True, groups=self.security_groups)
        nic = NetworkInterfaceCollection(eth0)

        reservation = self.ec2.run_instances(
            ami_id, key_name=self.key_name, user_data=self.startup,
            instance_type=self.instance_type, block_device_map=bdm,
            instance_profile_name=self.instance_profile_name,
            network_interfaces=nic)
        self.ec2.create_tags(
            [instance.id for instance in reservation.instances],
            {"Name": "Dist Build",
             "OS": os_id + " " + version})

        self.log.info("Launched %s %s with instance id %s", os_id, version,
                      reservation.instances[0].id)
        return

    def build_all(self):
        """
        Launch builds for every known operating system.
        """
        for osver in self.os_ids:
            os_id, version = osver.split("-", 1)
            self.build_os(os_id, version)

    def parse_option(self, opt, value):
        if opt in ("-g", "--security-group", "--security-groups",
                   "--securitygroup", "--securitygroups", "security-group",
                   "security-groups"):
            self.security_groups.extend(value.split(","))
        elif opt in ("-h", "--help"):
            usage(stdout)
            raise StopIteration()
        elif opt in ("-k", "--key-name", "--keyname", "--key", "key-name",
                     "key"):
            self.key_name = value
        elif opt in ("-i", "--instance-profile-name", "--instance-profile",
                     "--instnaceprofilename", "--instanceprofile",
                     "instance-profile-name", "instance-profile",
                     "instanceprofile"):
            self.instance_profile_name = value
        elif opt in ("-o", "--os", "os"):
            self.os_ids.extend(value.split(","))
        elif opt in ("-p", "--profile", "profile"):
            self.profile = value
        elif opt in ("-r", "--region", "region"):
            self.region = value
        elif opt in ("-s", "--subnet-id", "--subnet", "subnet-id", "subnet"):
            self.subnet_id = value
        elif opt in ("-V", "--volume-size", "volume-size"):
            try:
                self.volume_size = int(value)
            except ValueError:
                raise ValueError("Invalid volume size %r" % value)
        else:
            raise ValueError("Invalid key %r" % opt)
                
        return

    def __repr__(self):
        return ("Builder(subnet_id=%r, key_name=%r, security_groups=%r, "
                "os_ids=%r, instance_type=%r, virtualization_type=%r, "
                "root_size=%r, region=%r)" %
                (self.subnet_id, self.key_name, self.security_groups,
                 self.os_ids, self.instance_type, self.virtualization_type,
                 self.root_size, self.region))
                                              

Builder.create_ami_map()
Builder.create_startup_script()

def main(args):
    builder = Builder()

    try:
        opts, args = getopt(args, "c:g:hi:k:o:p:r:s:V:",
                            ["config=", "security-group=", "security-groups=",
                             "securitygroup=", "securitygroups=", "help",
                             "instance-profile-name=", "instance-profile=",
                             "instanceprofilename=", "instanceprofile-name=",
                             "key-name=", "keyname=", "key=", "os=",
                             "profile=", "region=", "subnet-id=", "subnet=",
                             "volume-size="])
    except GetoptError as e:
        print(str(e), file=stderr)
        usage()
        return 1

    for opt, value in opts:
        if opt in ("-c", "--config"):
            cp = RawConfigParser()
            cp.read([value])
            for opt, value in cp.items("dist.kanga.org"):
                builder.parse_option(opt, value)
        else:
            try:
                builder.parse_option(opt, value)
            except StopIteration:
                return 0
            except ValueError as e:
                print(str(e), file=stderr)
                usage()
                return 1

    if len(builder.os_ids) == 0:
        print("No OS ids specified for building.", file=stderr)
        return 1

    builder.build_all()

    return 0

def usage(fd=stderr):
    fd.write("""\
Usage: rebuild.py [options]

Options:
    -c <filename> | --config=<filename>
        Read configuration options from <filename>

    -g <sg-########> | --security-group=<sg-########> |
    --security-groups=<sg-########>
        Add the security groups to the list of security groups to attach to
        the instance.  Separate multiple security group ids with commas or
        specify multiple -g | --security-group options.

    -h | --help
        Show this usage information.

    -i <instance-profile-name> | --instance-profile=<instance-profile-name>
        Launch EC2 instances with the specified instance profile.

    -k <key-name> | --key-name=<key-name>
        Use the specified keypair to launch the instance.

    -o <os_name>-<version> | --os=<os_name>-<version>
        Add the specified OS name and version to the list of OS builds.
        Separate multiple OS name/version pairs with commas or specify
        multiple -o | --os options.

    -p <profile-name> | --profile <profile-name>
        Use the specified profile for credentials.

    -r <region> | --region=<region>
        Launch instances in the specified region.

    -s <subnet-########> | --subnet=<subnet-########>
        Attach the network interface to the specified subnet.

    -v <size> | --volume-size=<size>
        Set the root volume size in GB.
""")

if __name__ == "__main__":
    logging.basicConfig(
        stream=stderr, level=logging.DEBUG,
        format=("%(asctime)s %(filename)s %(lineno)d [%(levelname)s]: "
                "%(message)s"))
    logging.getLogger("boto").setLevel(logging.INFO)
    exit(main(argv[1:]))
