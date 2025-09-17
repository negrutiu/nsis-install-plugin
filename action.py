import datetime, importlib, glob, os, re, shutil, subprocess, struct, sys, winreg
from urllib import request

import ssl
from pip._vendor import certifi     # use pip certifi to fix (urllib.error.URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1123)>)

scriptdir = os.path.dirname(os.path.abspath(__file__))

# GitHub Actions sets RUNNER_DEBUG=1 when debug logging is enabled
if verbose := (os.environ.get("RUNNER_DEBUG", default="0") == "1"):
    print(f'GitHub debug logging enabled (RUNNER_DEBUG=1)')
    print(f'Python: {sys.version}')
    print(f'Platform: os.name="{os.name}", sys.platform="{sys.platform}"')


def download_github_asset(owner, repo, tag, name_regex, outdir):
    """
    Download a GitHub release asset matching the specified regex.
    Returns the path to the downloaded file.
    """
    if tag.lower() == 'latest':
        url = f'https://api.github.com/repos/{owner}/{repo}/releases/latest'
    else:
        url = f'https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}'

    asset_url = None
    asset_size = None
    asset_path = None

    if verbose: print(f'Listing assets from "{url}"')
    t0 = datetime.datetime.now()
    sslctx = ssl.create_default_context(cafile=certifi.where())
    with request.urlopen(url, context=sslctx) as http:
        import json
        response_json = json.loads(http.read().decode('utf-8'))
        if verbose:
            print(f'  HTTP {http.status} {http.reason}, {int((datetime.datetime.now()-t0).total_seconds()*1000)} ms')
            for asset in response_json['assets']:
                print(f'> asset: "{asset["name"]}", {asset["size"]} bytes, {asset["browser_download_url"]}')
        for asset in response_json['assets']:
            if 'name' in asset and re.match(name_regex, asset['name'], re.IGNORECASE):
                asset_url = asset['browser_download_url']
                asset_size = asset['size']
                asset_path = os.path.join(outdir, asset['name'])
                break

    if asset_url is None:
        raise ValueError(f'No asset matching "{name_regex}"')

    if os.path.exists(asset_path) and os.path.getsize(asset_path) == asset_size:
        print(f'Reuse existing "{asset_path}"')
        return asset_path

    print(f'Downloading {asset_url} to "{outdir}"')
    t0 = datetime.datetime.now()
    with request.urlopen(asset_url, context=sslctx) as http:
        if not os.path.exists(outdir):
            os.makedirs(outdir, exist_ok=True)
        with open(asset_path, 'wb') as file:
            shutil.copyfileobj(http, file)
            if verbose: print(f'  HTTP {http.status} {http.reason}, {int((datetime.datetime.now()-t0).total_seconds()*1000)} ms')
        return asset_path


def download_file(url, outdir):
    """ Download a file from the specified URL to the specified output directory. Returns the path to the downloaded file. """
    file_path = os.path.join(outdir, os.path.basename(url))
    if os.path.exists(file_path):
        print(f'Reuse existing "{file_path}"')
        return file_path

    print(f'Downloading {url} to "{outdir}"')
    t0 = datetime.datetime.now()
    sslctx = ssl.create_default_context(cafile=certifi.where())
    with request.urlopen(url, context=sslctx) as http:
        if not os.path.exists(outdir):
            os.makedirs(outdir, exist_ok=True)
        with open(file_path, 'wb') as file:
            shutil.copyfileobj(http, file)
            if verbose: print(f'  HTTP {http.status} {http.reason}, {int((datetime.datetime.now()-t0).total_seconds()*1000)} ms')
        return file_path


def import_temp_module(name):
    """ Import module, installing it to a temporary location if necessary. """
    try:
        globals()[name] = importlib.import_module(name)
    except ImportError:
        module_dir = os.path.join(scriptdir, 'temp', name)
        if not os.path.exists(module_dir):
            print(f'Install {name} into temporary directory {module_dir}')
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "--target", module_dir, name])
        print(f'Import "{module_dir}"')
        sys.path.insert(0, module_dir)
        globals()[name] = importlib.import_module(name)
        return module_dir
    return None

def find_7z():
    """ Find 7z.exe in the system PATH or common installation directories. Returns the path to 7z.exe or None if not found. """
    paths = []
    if os.name == 'nt':
        paths += [
            os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), '7-Zip'),
            os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'), '7-Zip'),
            ]
    paths += os.environ.get('PATH', '').split(os.pathsep)

    for path in paths:
        file = os.path.join(path, '7z.exe' if os.name == 'nt' else '7z')
        if os.path.isfile(file) and os.access(file, os.X_OK):
            return file
    return None


def extract_archive(archive, outdir):
    if not os.path.exists(archive):
        raise FileNotFoundError(f'"{archive}" not found')

    if (zip7 := find_7z()) is not None:
        try:
            args = [zip7, 'x', '-y', f'-o{outdir}', archive]
            os.makedirs(os.path.dirname(outdir), exist_ok=True)
            subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if verbose: print(f'Command {args} returned 0')
            return
        except Exception as ex:
            print(f'{ex}')

    if os.path.splitext(archive)[1].lower() == '.zip':
        # only built-in zip methods ("Deflate", "Store") are supported
        # LZMA zips are not supported (example plugins: "NsProcess")
        import zipfile
        with zipfile.ZipFile(archive, 'r') as zip_ref:
            zip_ref.extractall(outdir)
    elif os.path.splitext(archive)[1].lower() in ['.7z', '.7zip']:
        import_temp_module('py7zr')
        with py7zr.SevenZipFile(archive, mode="r") as archive:
            archive.extractall(path=outdir)
    else:
        raise ValueError(f'Unsupported archive format: "{archive}"')


def pe_architecture(path):
    """ Return the architecture of a PE file (`x86`, `amd64`, `arm64`, `ia64`) or `None`. """
    import_temp_module('pefile')

    machine = -1
    with pefile.PE(path) as pe:
        machine = pe.FILE_HEADER.Machine

    # https://learn.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
    machines = {0x014c: 'x86', 0x8664: 'amd64', 0xaa64: 'arm64', 0x0200: 'ia64'}
    return machines.get(machine, None)


def pe_imports_charset_count(path):
    """
    Count the number of ANSI and Wide (Unicode) imports in a PE file.
    Returns:
        tuple: (ansi_count, wide_count)
    """
    import_temp_module('pefile')

    ansi_count = 0
    wide_count = 0

    with pefile.PE(path) as pe:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                # dll_name = entry.dll.decode(errors='ignore')
                for imp in entry.imports:
                    # imp.name is None if imp.import_by_ordinal is True
                    if imp.name is not None and (func_name := imp.name.decode(errors='ignore')):
                        if len(func_name) >= 2 and func_name[-2].islower():
                            if func_name[-1] == 'W':
                                wide_count += 1
                            elif func_name[-1] == 'A':
                                ansi_count += 1
    return (ansi_count, wide_count)

def pe_imports_module_list(path):
    """ Return a list of imported modules in a PE file (e.g. `['kernel32.dll', 'user32.dll']`) """
    import_temp_module('pefile')

    module_list = []
    with pefile.PE(path) as pe:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                module_list.append(entry.dll.decode(errors='ignore'))
    return module_list


def pe_section_name_list(path):
    """ Return a list of section names in a PE file (e.g. `['.text', '.rdata', '.data', '.rsrc', '.reloc']`) """
    import_temp_module('pefile')

    section_list = []
    with pefile.PE(path) as pe:
        for section in pe.sections:
            section_list.append(section.Name.decode(errors='ignore'))
    return section_list

def pe_print_debug_entries(path):
    IMAGE_DEBUG_TYPE_COFF = 1
    IMAGE_DEBUG_TYPE_CODEVIEW = 2
    IMAGE_DEBUG_TYPE_VC_FEATURE = 12
    IMAGE_DEBUG_TYPE_POGO = 13
    IMAGE_DEBUG_TYPE_ILTCG = 14
    IMAGE_DEBUG_TYPE_MPX = 15
    IMAGE_DEBUG_TYPE_REPRO = 16
    IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20

    with pefile.PE(path) as pe:
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            import_temp_module('binascii')
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                if entry.struct.Type == IMAGE_DEBUG_TYPE_CODEVIEW:
                    data = pe.__data__[entry.struct.PointerToRawData:
                                    entry.struct.PointerToRawData+entry.struct.SizeOfData]
                    sig = data[:4]
                    if sig == b'RSDS':
                        guid = data[4:20]
                        age  = struct.unpack('<I', data[20:24])[0]
                        pdb  = data[24:].split(b'\x00',1)[0].decode()
                        print('   CODEVIEW PDB:', pdb)
                elif entry.struct.Type == IMAGE_DEBUG_TYPE_VC_FEATURE:
                    # data = pe.__data__[entry.struct.PointerToRawData:
                    #                 entry.struct.PointerToRawData+entry.struct.SizeOfData]
                    # mask = struct.unpack('<I', data[4:8])[0]
                    # print('   VC_FEATURE mask: 0x%08x' % mask)
                    raw_offset = entry.struct.PointerToRawData
                    raw_size   = entry.struct.SizeOfData
                    raw_bytes = pe.__data__[raw_offset:raw_offset + raw_size]
                    print(f'   VC_FEATURE: [{raw_size}] {binascii.hexlify(raw_bytes)}')
                else:
                    print(f'   Debug Type {entry.struct.Type} not parsed')
        else:
            print('   No debug information found')


def pe_is_debug(path):
    """ Heuristically determine if a PE file is a debug build. Returns `True` or `False`.
    Notes:
    - This function does not guarantee that a PE file is a debug build, it only tries to identify typical characteristics of debug builds
    - Unable to distinguish between msbuild-generated Debug and Release binaries that are linked statically
    """
    debug_modules = [r'msvcrtd\.dll', r'msvcp\d*d\.dll', r'vcruntime\d*d\.dll', r'ucrtd\.dll', r'ucrtbase\.dll']
    for module in pe_imports_module_list(path):
        for regex in debug_modules:
            if re.match(regex, module, re.IGNORECASE):
                # print(f'pe_is_debug("{path}") = True (matched import "{regex}")')
                # print(f'   imports: {pe_imports_module_list(path)}')
                # pe_print_debug_entries(path)
                return True

    debug_sections = [r'\.debug.*', r'\/\d+']
    for section in pe_section_name_list(path):
        for regex in debug_sections:
            if re.match(regex, section, re.IGNORECASE):
                # print(f'pe_is_debug("{path}") = True (matched section "{regex}")')
                # print(f'   sections: {pe_section_name_list(path)}')
                # pe_print_debug_entries(path)
                return True

    # print(f'pe_is_debug("{path}") = False')
    # print(f'   imports: {pe_imports_module_list(path)}')
    # print(f'   sections: {pe_section_name_list(path)}')
    # pe_print_debug_entries(path)
    return False


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

    candidates = []
    def add_candidate(path):
        instdir = os.path.normpath(os.path.expandvars(path)).casefold()
        for candidate in candidates:
            if instdir == candidate.casefold():
                return
        candidates.append(path)

    if os.name == 'nt':
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
                    add_candidate(instdir)
            except Exception as ex:
                if verbose: print(f'-- "{registry["hivename"]}\\{uninstall_key}" ({"wow64" if registry["view"] == winreg.KEY_WOW64_32KEY else "nativ"}): {ex}')

    if os.name == 'nt':
        add_candidate(r'%ProgramFiles%\NSIS')
        add_candidate(r'%ProgramFiles(x86)%\NSIS')

    for path in os.environ.get('PATH', '').split(os.pathsep):
        add_candidate(path)

    for instdir in candidates:
        if os.path.exists(os.path.join(instdir, 'makensis.exe' if os.name == 'nt' else 'makensis')):
            if verbose: print(f'>> "{instdir}" found')
            if instdir not in installations:
                installations.append(instdir)

    return installations

def copytree(srcdir, destdir):
    for file in glob.glob(os.path.join(srcdir, '**'), recursive=True):
        if not os.path.isfile(file):
            continue
        relpath = os.path.relpath(file, srcdir)
        destpath = os.path.join(destdir, relpath)
        print(f'Copy "{relpath}" --> "{destpath}"')
        # if os.path.isdir(file):
        #     if not os.path.exists(destpath):
        #         print(f'  Create directory "{destpath}"')
        #         os.makedirs(destpath, exist_ok=True)
        # else:
        #     destfolder = os.path.dirname(destpath)
        #     if not os.path.exists(destfolder):
        #         print(f'  Create directory "{destfolder}"')
        #         os.makedirs(destfolder, exist_ok=True)
        #     print(f'  Copy file "{file}" to "{destpath}"')
        #     shutil.copy2(file, destpath)

def copyfile(src, destdir, srcdir=None):
    print(f'Copy "{src if srcdir is None else os.path.relpath(src, srcdir)}" --> "{destdir}"')


def nsis_inject_plugin(instdir, plugindir):
    """
    Inject plugin files from `plugindir` into the NSIS installation at `instdir`.
    The function attempts to identify the plugin files by their names and copies them to the appropriate directories.

    The recommended plugin layout is:
    - `plugindir`/
        - Docs/
        - Examples/
        - Include/
        - Plugins/
            - x86-unicode/
            - x86-ansi/
            - amd64-unicode/
    """
    print(f'Injecting plugins from "{plugindir}" into "{instdir}"')

    mandatory_directories = ['Bin', 'Contrib', 'Docs', 'Examples', 'Include', 'Plugins', 'Stubs']
    if os.name == 'nt':
        mandatory_files = ['makensis.exe', 'makensisw.exe', 'bin/makensis.exe']
    else:
        mandatory_files = ['makensis', 'genpat', 'bin/makensisw.exe']
    for dir in mandatory_directories:
        absdir = os.path.join(instdir, dir)
        assert os.path.exists(absdir) and os.path.isdir(absdir), f'Invalid NSIS installation directory: "{instdir}" (missing "{dir}")'
    for file in mandatory_files:
        absfile = os.path.join(instdir, file)
        assert os.path.exists(absfile) and os.path.isfile(absfile), f'Invalid NSIS installation directory: "{instdir}" (missing "{file}")'
    
    # collect all .dll files and classify them by architecture and charset
    plugin_files = []
    for file in glob.glob(os.path.join(plugindir, '**', '*.dll'), recursive=True):
        if os.path.isfile(file):
            relfile = os.path.normpath(os.path.relpath(file, plugindir))
            if (arch := pe_architecture(file)) not in ['x86', 'amd64']:
                print(f'Warning: Ignore "{relfile}" with unsupported architecture "{arch}"')
            elif (subdir := relfile.split(os.sep)[0]).lower() in ['contrib', 'docs', 'examples', 'include']:
                print(f'Warning: Ignore "{relfile}" in reserved directory "{subdir}"')
            elif pe_is_debug(file):
                print(f'Warning: Ignore "{relfile}" (debug PE file)')
            elif relfile[:5].lower() == 'debug':
                print(f'Warning: Ignore "{relfile}" (in "Debug" directory)')
            else:
                plugin_files.append({'path': file})
    
    assert len(plugin_files) > 0, f'No DLL files found in "{plugindir}"'

    pluginame = None
    for plugin in plugin_files:
        # already classified?
        if (target := plugin.get('target', None)) is not None and target != '':
            continue

        # plugin name
        name = os.path.splitext(os.path.basename(file))[0]
        if pluginame is None:
            pluginame = name
        elif pluginame != name:
            print(f'Warning: Multiple plugin names found in "{plugindir}": "{pluginame}" and "{name}"')

        # determine target architecture
        ansi_count, wide_count = pe_imports_charset_count(plugin['path'])
        arch = pe_architecture(plugin['path'])

        relfile = os.path.relpath(plugin['path'], plugindir)
        charset = None
        for regex in [r'.*unicode.*']:
            if re.match(regex, relfile, re.IGNORECASE):
                charset = 'unicode'
                break
        if charset is None:
            for regex in [r'.*ansi.*']:
                if re.match(regex, relfile, re.IGNORECASE):
                    charset = 'ansi'
                    break
        if charset is None and len(plugin_files) == 2:
            # Look for ansi / unicode directory pairs
            # - File layout (e.g. "NsThread", "NsKeyHook", "NsResize", "Nsx", "NsFlash", "NsExpr", "NewAdvSplash"")
            #     \Plugins\plugin.dll
            #     \Unicode\Plugins\plugin.dll
            # - File layout (e.g. "LogEx")
            #     \Plugins\plugin.dll
            #     \Plugins\Unicode\plugin.dll
            # - File layout (e.g. "NSIS-ApplicationID")
            #     \Release\plugin.dll
            #     \ReleaseUnicode\plugin.dll
            other_plugin = [p for p in plugin_files if p != plugin][0]
            other_relfile = os.path.relpath(other_plugin['path'], plugindir)
            other_relfile_ansi = os.path.normpath(other_relfile.lower().replace('unicode', '')).strip(os.sep)
            if other_relfile_ansi == os.path.normpath(relfile).lower():
                charset = 'ansi'
                print(f'Warning: Assuming charset of "{relfile}" is "{charset}" (A:{ansi_count}/W:{wide_count} imports, found counterpart in "{other_relfile}")')
        if charset is None:
            if wide_count > (ansi_count * 2):
                # example plugins: "LockedList" (0 ansi/18 wide)
                charset = 'unicode'
                print(f'Warning: Assuming charset of "{relfile}" is "{charset}" (A:{ansi_count}/W:{wide_count} imports)')
            elif ansi_count > (wide_count * 2):
                # example plugins: "NSIS-Python27" (7 ansi/0 wide), "nsThread" (4/0), "NsKeyHook" (1/0), "NsResize" (1/0), "Nwizplugin" (17/0), "Nwizplugin" (18/0)
                charset = 'ansi'
                print(f'Warning: Assuming charset of "{relfile}" is "{charset}" (A:{ansi_count}/W:{wide_count} imports)')
            else:
                # example plugins: "Stack" (4 ansi, 6 wide), "Locate" (6 ansi, 7 wide)
                print(f'Warning: Cannot clearly determine charset of "{relfile}" (A:{ansi_count}/W:{wide_count} imports)')
        if charset is None and len(plugin_files) == 1:
            # example plugins: "base64", "HwInfo", "NSISList", "NSISpcre", "NsSCM", "NsUnzip", etc.
            if arch == 'x86':
                # classify this plugin as both ansi and unicode
                charset = 'unicode'
                plugin_files.append({'path': plugin['path'], 'target': 'x86-ansi'})
                print(f'Warning: Assuming charset of "{relfile}" is both ansi and unicode (A:{ansi_count}/W:{wide_count} imports, only one x86 plugin DLL found)')
            else:
                charset = 'unicode'
                print(f'Warning: Assuming charset of "{relfile}" is "{charset}" (A:{ansi_count}/W:{wide_count} imports, only one amd64 plugin DLL found)')

        if charset is not None and arch in ['x86', 'amd64']:
            plugin['target'] = f'{arch}-{charset}'
        else:
            raise ValueError(f'Cannot classify "{relfile}". architecture="{arch}", charset="{charset}"')

    assert pluginame is not None, f'Cannot determine plugin name in "{plugindir}"'
    unique_files = []

    # copy plugin (*.dll) files
    for plugin in plugin_files:
        targetdir = os.path.join(instdir, 'Plugins', plugin['target'])
        if os.path.exists(targetdir):
            unique_files.append(plugin['path'])
            copyfile(plugin['path'], targetdir, plugindir)
        else:
            print(f'Skip copying "{os.path.relpath(plugin["path"], plugindir)}" to non-existing "{targetdir}"')

    # copy documentation files
    if os.path.exists(os.path.join(plugindir, 'Docs')) and os.path.isdir(os.path.join(plugindir, 'Docs')):
        copytree(os.path.join(plugindir, 'Docs'), os.path.join(instdir, 'Docs'))
    else:
        for file in glob.glob(os.path.join(plugindir, '**'), recursive=True):
            if os.path.isfile(file):
                for regex in [r'.*readme.*', r'.*howto.*', r'.*docs.*', r'.*\.txt', r'.*\.md']:
                    if re.match(regex, os.path.relpath(file, plugindir), re.IGNORECASE) and file not in unique_files:
                        unique_files.append(file)
                        copyfile(file, os.path.join(instdir, 'Docs', pluginame), plugindir)

    # copy example files
    if os.path.exists(os.path.join(plugindir, 'Examples')) and os.path.isdir(os.path.join(plugindir, 'Examples')):
        copytree(os.path.join(plugindir, 'Examples'), os.path.join(instdir, 'Examples'))
    else:
        for file in glob.glob(os.path.join(plugindir, '**'), recursive=True):
            if os.path.isfile(file):
                for regex in [r'.*\.nsi']:
                    if re.match(regex, os.path.relpath(file, plugindir), re.IGNORECASE) and file not in unique_files:
                        unique_files.append(file)
                        copyfile(file, os.path.join(instdir, 'Examples', pluginame), plugindir)

    # copy include files
    if os.path.exists(os.path.join(plugindir, 'Include')) and os.path.isdir(os.path.join(plugindir, 'Include')):
        copytree(os.path.join(plugindir, 'Include'), os.path.join(instdir, 'Includes'))
    else:
        for file in glob.glob(os.path.join(plugindir, '**'), recursive=True):
            if os.path.isfile(file):
                for regex in [r'.*\.nsh']:
                    if re.match(regex, os.path.relpath(file, plugindir), re.IGNORECASE) and file not in unique_files:
                        unique_files.append(file)
                        copyfile(file, os.path.join(instdir, 'Includes', pluginame), plugindir)

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
