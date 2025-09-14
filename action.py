import os, re, subprocess, struct, sys, winreg
from urllib import request

import ssl
from pip._vendor import certifi     # use pip certifi to fix (urllib.error.URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1123)>)


# GitHub Actions sets RUNNER_DEBUG=1 when debug logging is enabled
if verbose := (os.environ.get("RUNNER_DEBUG", default="0") == "1"):
    print(f'GitHub debug logging enabled (RUNNER_DEBUG=1)')
    print(f'Python: {sys.version}')
    print(f'Platform: os.name="{os.name}", sys.platform="{sys.platform}"')


def pe_architecture(path):
    """ Return the architecture of a PE file (`x86`, `amd64`, `arm64`). """
    with open(path, "rb") as fi:
        # Read DOS header to get e_lfanew (offset to PE header)
        fi.seek(0x3C)
        data = fi.read(4)
        if len(data) != 4:
            raise ValueError("Not a valid PE file (cannot read e_lfanew).")
        (e_lfanew,) = struct.unpack("<I", data)

        # Read PE signature + COFF header (at e_lfanew)
        fi.seek(e_lfanew)
        sig = fi.read(4)
        if sig != b"PE\x00\x00":
            raise ValueError("PE signature not found.")

        coff = fi.read(20)  # IMAGE_FILE_HEADER is 20 bytes
        if len(coff) != 20:
            raise ValueError("Truncated COFF header.")
        (machine,) = struct.unpack("<H", coff[:2])

        # https://learn.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
        machines = {0x014c: 'x86', 0x8664: 'amd64', 0xaa64: 'arm64', 0x0200: 'ia64'}
        return machines.get(machine, None)
    return None


def nsis_version(instdir):
    """ Query NSIS version by executing `makensis.exe /VERSION` in the specified installation directory. Returns `None` on error. """
    try:
        process = subprocess.Popen([os.path.join(instdir if instdir is not None else '', 'makensis.exe'), '/VERSION'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cout, cerr = process.communicate()
        process.wait()
        if cout != None:
            for line in cout.decode('utf-8').split("\r\n"):
                if (matches := re.search(r'^v(\d+\.\d+(\.\d+(\.\d+)?)?)', line)) != None:   # look for "v1.2[.3[.4]]"
                    return matches.group(1)
    except Exception as ex:
        print(f'-- get_nsis_version("{instdir}"): {ex}')
    return None


def nsis_list():
    """
    List all NSIS installations found in the registry and default locations.
    Returns:
      List of unique installation directories.
    """
    installations = []

    uninstall_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NSIS"
    for registry in [
        {'hive': winreg.HKEY_LOCAL_MACHINE, 'hivename': "HKLM", 'view': winreg.KEY_WOW64_64KEY},
        {'hive': winreg.HKEY_LOCAL_MACHINE, 'hivename': "HKLM", 'view': winreg.KEY_WOW64_32KEY},
        {'hive': winreg.HKEY_CURRENT_USER,  'hivename': "HKCU", 'view': winreg.KEY_WOW64_64KEY},
        {'hive': winreg.HKEY_CURRENT_USER,  'hivename': "HKCU", 'view': winreg.KEY_WOW64_32KEY},
        ]:
        try:
            with winreg.OpenKey(registry['hive'], uninstall_key, access= winreg.KEY_READ|registry['view']) as regkey:
                if verbose: print(f'>> "{registry["hivename"]}\\{uninstall_key}" ({"wow64" if registry["view"] == winreg.KEY_WOW64_32KEY else "nativ"}): found')
                instdir, regtype = winreg.QueryValueEx(regkey, "InstallLocation")
                winreg.CloseKey(regkey)
                instdir = os.path.normpath(os.path.expandvars(instdir))
                if os.path.exists(os.path.join(instdir, 'makensis.exe')):
                    if instdir not in installations:
                        installations.append(instdir)
                else:
                    if verbose: print(f'-- "{instdir}" has an invalid/corrupted NSIS installation')
        except Exception as ex:
            if verbose: print(f'-- "{registry["hivename"]}\\{uninstall_key}" ({"wow64" if registry["view"] == winreg.KEY_WOW64_32KEY else "nativ"}): {ex}')

    for instdir in [r'%ProgramFiles%\NSIS', r'%ProgramFiles(x86)%\NSIS']:
        instdir = os.path.normpath(os.path.expandvars(instdir))
        if os.path.exists(os.path.join(instdir, 'makensis.exe')):
            if verbose: print(f'>> "{instdir}" found')
            if instdir not in installations:
                installations.append(instdir)
        else:
            if verbose: print(f'-- "{instdir}" not found')

    return installations


if __name__ == '__main__':

    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', help='more verbose output')
    args = parser.parse_args()

    print(f'Arguments: {args.__dict__}')

    if args.verbose:
        verbose = True

    for instdir in (list := nsis_list()):
        print(f'Found nsis/{pe_architecture(os.path.join(instdir, "makensis.exe"))}/{nsis_version(instdir)} in "{instdir}"')
    if not list:
        print('No NSIS installations found')
