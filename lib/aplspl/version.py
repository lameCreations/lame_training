import os
import fnmatch
from zipfile import ZipFile

def get_version(workdir):
    __version__ = "unknown"

    # with open("version.cfg", "r") as version_file:
    #    str_version = version_file.readline()
    #    __version__ = str_version.split("version=",1)[1].replace('"', '')

    pattern = 'aplspl-*.whl'
    wheel_file = ''
    for root, dirs, files in os.walk(workdir):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                # wheel_file = os.path.join(workdir, name)
                wheel_file = name
                full_wheel_file = os.path.join(workdir, name)
                with ZipFile(full_wheel_file, 'r') as zip:
                    str_version = zip.read('aplspl/version.cfg')
                    decoded_str_version = str_version.decode()
                    __version__ = decoded_str_version.split("version=",1)[1].replace('"', '')

    return __version__
