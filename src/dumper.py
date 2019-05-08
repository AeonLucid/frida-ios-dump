import codecs
import os
import shutil
import tempfile
import threading
from typing import Union

import frida
import paramiko
from frida.core import Device, Session
from paramiko import SSHClient, AuthenticationException
from paramiko.ssh_exception import NoValidConnectionsError
from scp import SCPClient

script_dir = os.path.dirname(os.path.realpath(__file__))
script_file = os.path.join(script_dir, 'dump.js')

download_dir = 'files'
download_path = os.path.join(script_dir, download_dir)

payload_dir = 'Payload'
payload_path = os.path.join(download_path, payload_dir)


class Dumper:

    _device: Device
    _session: Union[Session, None]

    def __init__(self, device):
        self._device = device
        self._ssh = SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._pid = None
        self._display_name = None
        self._session = None
        self._lock = threading.Event()
        self._file_dict = dict()

    def connect_ssh(self, host, port, username, password):
        try:
            self._ssh.connect(host, port=port, username=username, password=password)
            print('Connected to SSH \'%s@%s:%s\'.' % (username, host, port))
            return True
        except AuthenticationException:
            print('The specified SSH credentials are invalid.')
            return False
        except NoValidConnectionsError:
            print('No SSH server was found at \'%s:%s\'.' % (host, port))
            return False

    def launch_app(self, name):
        print('Launching the target app {}'.format(name))

        pid = None
        display_name = None
        identifier = None

        for application in self._device.enumerate_applications():
            if name == application.identifier or name == application.name:
                pid = application.pid
                display_name = application.name
                identifier = application.identifier

        try:
            if not pid:
                self._pid = self._device.spawn(identifier)
                self._session = self._device.attach(self._pid)
                self._display_name = display_name
                self._device.resume(self._pid)
            else:
                self._pid = pid
                self._display_name = display_name
                self._session = self._device.attach(self._pid)
            return True
        except Exception as e:
            print('Unable to launch target app, error:', e)
            return False

    def execute(self):
        try:
            print('Dumping \'%s.ipa\'..' % self._display_name)

            # Load frida script.
            self._session.on('detached', self._on_detached)

            with codecs.open(script_file, 'r', encoding='utf8') as f:
                script_code = f.read()

            script = self._session.create_script(script_code)
            script.on('message', self._on_message)
            script.load()

            # Create directory.
            if os.path.exists(download_path):
                shutil.rmtree(download_path)

            os.makedirs(payload_path, 0o755)

            if not os.path.exists(payload_path):
                raise RuntimeError('Failed to create payload path.')

            # Start dumping app.
            script.post('dump')

            # Wait until dump is finished on the device.
            try:
                self._lock.wait()
            except KeyboardInterrupt:
                return False

            # Create ipa file.
            ipa_filename = self._display_name + '.ipa'

            print('Creating ipa file of downloaded files.')

            app_name = self._file_dict['app']

            for key, value in self._file_dict.items():
                from_dir = os.path.join(payload_path, key)
                to_dir = os.path.join(payload_path, app_name, value)

                if key != 'app':
                    shutil.move(from_dir, to_dir)

            output_file = shutil.make_archive(os.path.join(os.getcwd(), ipa_filename), 'zip', payload_path)

            # Finished.
            print('Finished dumping.')
        finally:
            if os.path.exists(download_path):
                shutil.rmtree(download_path)

        return True

    def _on_message(self, message, data):
        if 'type' in message:
            if message['type'] == 'error':
                print('Received error from frida script.')
                print(message['stack'])

        if 'payload' in message:
            payload = message['payload']

            if 'dump' in payload:
                origin_path = payload['path']
                dump_path = payload['dump']

                scp_from = dump_path
                scp_to = payload_path + u'/'

                print('Downloading binary file %s.' % scp_from)

                with SCPClient(self._ssh.get_transport(), socket_timeout=60) as scp:
                    scp.get(scp_from, scp_to)

                os.chmod(os.path.join(payload_path, os.path.basename(dump_path)), 0o655)
                index = origin_path.find('.app/')

                self._file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

            if 'app' in payload:
                app_path = payload['app']

                scp_from = app_path
                scp_to = payload_path + u'/'

                print('Downloading app files.')

                with SCPClient(self._ssh.get_transport(), socket_timeout=60) as scp:
                    scp.get(scp_from, scp_to, recursive=True)

                os.chmod(os.path.join(payload_path, os.path.basename(app_path)), 0o755)

                self._file_dict['app'] = os.path.basename(app_path)

            if 'done' in payload:
                print('Finished downloading files.')

                self._lock.set()

    @staticmethod
    def _on_detached(reason, crash):
        print('Frida was detached')
        print('\tReason:', reason)
        print('\tCrash:', crash)
