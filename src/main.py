import argparse
import sys

import frida

from commands import list_applications
from dumper import Dumper


def get_device():
    try:
        return frida.get_usb_device(timeout=5)
    except frida.TimedOutError:
        return None


def main():
    parser = argparse.ArgumentParser(description='frida-ios-dump')
    parser.add_argument('-host', dest='ssh_host', help='SSH Host')
    parser.add_argument('-port', dest='ssh_port', help='SSH Port')
    parser.add_argument('-username', dest='ssh_username', help='SSH Username')
    parser.add_argument('-password', dest='ssh_password', help='SSH Password')
    parser.add_argument('-list', dest='list_applications', action='store_true', help='List the installed apps')
    parser.add_argument('-dump', dest='dump_ipa', help='Bundle identifier or display name of the app to dump')
    parser.add_argument('-out', dest='output_directory', help='Destination of the resulting ipa file')

    # Parse arguments.
    args = parser.parse_args()

    if not args.dump_ipa and not args.list_applications:
        parser.print_help()
        return False

    # Find connected iPhone.
    device = get_device()

    if device is None:
        print('Unable to find a connected usb device with Frida.')
        return False

    result = False

    print('Connected to Frida on device \'%s\'.' % device.name)

    # List applications on device.
    if args.list_applications:
        result = list_applications.execute(device)
    # Dump decrypted ipa from device.
    elif args.dump_ipa:

        dumper = Dumper(device, args.output_directory)

        if not dumper.connect_ssh(args.ssh_host, args.ssh_port, args.ssh_username, args.ssh_password):
            return False

        if not dumper.launch_app(args.dump_ipa):
            return False

        result = dumper.execute()

    return result


if __name__ == '__main__':
    sys.exit(0 if main() else 1)
