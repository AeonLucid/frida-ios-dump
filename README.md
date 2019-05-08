# frida-ios-dump

Pull a decrypted IPA from a jailbroken device. Forked from [AloneMonkey/frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) and updated to be compatible with the latest Frida.

## Usage

1. Install most recent [Frida](http://www.frida.re/) on device.
2. `cd src`
3. `pip install -r requirements.txt`
4. `python frida-ios-dump.py`

```
./frida-ios-dump.py
usage: frida-ios-dumper.py [-h] [-host SSH_HOST] [-port SSH_PORT]
                           [-username SSH_USERNAME] [-password SSH_PASSWORD]
                           [-list] [-dump DUMP_IPA]

frida-ios-dump

optional arguments:
  -h, --help            show this help message and exit
  -host SSH_HOST        SSH Host
  -port SSH_PORT        SSH Port
  -username SSH_USERNAME
                        SSH Username
  -password SSH_PASSWORD
                        SSH Password
  -list                 List the installed apps
  -dump DUMP_IPA        Bundle identifier or display name of the app to dump
```
