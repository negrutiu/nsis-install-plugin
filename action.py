import datetime, importlib, glob, os, re, shutil, subprocess, struct, sys
from urllib import request

import ssl
from pip._vendor import certifi     # use pip certifi to fix (urllib.error.URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1123)>)

scriptdir = os.path.dirname(os.path.abspath(__file__))
tempdir = os.path.join(scriptdir, 'runtime')
downloadsdir = os.path.join(tempdir, 'downloads')
pluginsdir = os.path.join(tempdir, 'plugins')
modulesdir = os.path.join(scriptdir, 'runtime', 'modules')        # directory for temporary modules


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


def download_file(url, outdir, useragent=None):
    """ Download a file from the specified URL to the specified output directory. Returns the path to the downloaded file. """
    file_path = os.path.join(outdir, os.path.basename(url))
    if os.path.exists(file_path):
        print(f'Reuse existing "{file_path}"')
        return file_path

    print(f'Downloading {url} to "{outdir}"')
    t0 = datetime.datetime.now()
    sslctx = ssl.create_default_context(cafile=certifi.where())
    headers = {'User-Agent': useragent} if useragent else {}
    myrequest = request.Request(url, headers=headers)
    with request.urlopen(myrequest, context=sslctx) as http:
        if not os.path.exists(outdir):
            os.makedirs(outdir, exist_ok=True)
        with open(file_path, 'wb') as file:
            shutil.copyfileobj(http, file)
            if verbose: print(f'  HTTP {http.status} {http.reason}, {int((datetime.datetime.now()-t0).total_seconds()*1000)} ms')
        return file_path


def import_temp_module(modname):
    """ Import module, installing it to a temporary location if necessary. """
    try:
        globals()[modname] = importlib.import_module(modname)
    except ImportError:
        moduledir = os.path.join(modulesdir, modname)
        if not os.path.exists(moduledir):
            print(f'Install {modname} into temporary directory {moduledir}')
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "--target", moduledir, modname])
        print(f'Import "{moduledir}"')
        sys.path.insert(0, moduledir)
        globals()[modname] = importlib.import_module(modname)
        return moduledir
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


def pe_version(path, product=False):
    """ Return the file or product version of a PE file or `None`. """
    import_temp_module('pefile')
    with pefile.PE(path) as pe:
        if 'VS_FIXEDFILEINFO' in pe.__dict__:
            if pe.VS_FIXEDFILEINFO:
                if len(pe.VS_FIXEDFILEINFO) > 0:
                    verinfo = pe.VS_FIXEDFILEINFO[0]
                    if product:
                        return f'{verinfo.ProductVersionMS >> 16}.{verinfo.ProductVersionMS & 0xFFFF}.{verinfo.ProductVersionLS >> 16}.{verinfo.ProductVersionLS & 0xFFFF}'
                    else:
                        return f'{verinfo.FileVersionMS >> 16}.{verinfo.FileVersionMS & 0xFFFF}.{verinfo.FileVersionLS >> 16}.{verinfo.FileVersionLS & 0xFFFF}'
    return None


def pe_header_datetime(path):
    """ Return the PE header timestamp as a `datetime` object or `None`. """
    import_temp_module('pefile')
    with pefile.PE(path) as pe:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        if timestamp != 0:
            return datetime.datetime.fromtimestamp(timestamp)
    return None


def pe_file_is_newer(path1, path2):
    """ Return `True` if `path1` is newer than `path2` based on PE header timestamp. """
    assert os.path.exists(path1) and os.path.isfile(path1), f'File not found: "{path1}"'
    if os.path.exists(path2) and os.path.isfile(path2):
        return pe_header_datetime(path1) > pe_header_datetime(path2)
    return True     # path1 wins


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


def nsis_version(makensis):
    """ Query NSIS version by executing `makensis -VERSION`. Returns a version string like `3.09` or `None`. """
    try:
        process = subprocess.Popen([makensis, '-VERSION'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cout, cerr = process.communicate()
        process.wait()
        if cout != None:
            for line in cout.decode('utf-8').split("\r\n"):
                if (matches := re.search(r'^v(\d+\.\d+(\.\d+(\.\d+)?)?)', line)) != None:   # look for "v1.2[.3[.4]]"
                    return matches.group(1)
    except Exception as ex:
        print(f'-- get_nsis_version("{makensis}"): {ex}')
    return None


def nsis_list():
    """
    List all NSIS installations found in the registry and default locations.
    Returns:
      list: `[(makensis1, instdir1), ...]`
    """
    installations = []

    candidate_list = []
    def candidate_add(path):
        path = os.path.normpath(os.path.expandvars(path))
        for candidate in candidate_list:
            if path.casefold() == candidate.casefold():
                return
        candidate_list.append(path)

    if os.name == 'nt':
        import winreg
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
                    dir, regtype = winreg.QueryValueEx(regkey, "InstallLocation")
                    winreg.CloseKey(regkey)
                    candidate_add(dir)
            except Exception as ex:
                if verbose: print(f'-- "{registry["hivename"]}\\{uninstall_key}" ({"wow64" if registry["view"] == winreg.KEY_WOW64_32KEY else "nativ"}): {ex}')

    if os.name == 'nt':
        candidate_add(r'%ProgramFiles%\NSIS')
        candidate_add(r'%ProgramFiles(x86)%\NSIS')

    for path in os.environ.get('PATH', '').split(os.pathsep):
        candidate_add(path)

    for dir in candidate_list:
        makensis = os.path.join(dir, 'makensis.exe' if os.name == 'nt' else 'makensis')
        if os.path.exists(makensis):
            makensis = os.path.realpath(makensis)   # resolve symlinks
            instdir =os.path.dirname(makensis)
            if instdir == '/usr/bin' or instdir == '/usr/local/bin':
                assert os.name == 'posix'
                instdir = '/usr/share/nsis'
                assert os.path.exists(instdir) and os.path.isdir(instdir), f'Invalid NSIS share directory: "{instdir}"'
            elif os.path.basename(instdir).casefold() == 'bin':
                instdir = os.path.dirname(instdir)  # /opt/homebrew/Cellar/makensis/3.11/bin -> /opt/homebrew/Cellar/makensis/3.11
                assert os.path.exists(instdir) and os.path.isdir(instdir), f'Invalid NSIS share directory: "{instdir}"'

            unique = True
            for makensis0, instdir0 in installations:
                if makensis0.casefold() == makensis.casefold():
                    unique = False
                    break
            if unique:
                installations.append((makensis, instdir))

    return installations

def format_path(file, basedir=None):
    assert file, 'file is None'
    properties = []
    if os.path.exists(file) and os.path.isfile(file) and os.path.splitext(file)[1].lower() in ['.dll', '.exe', '.sys', '.ocx']:
        try:
            if dt := pe_header_datetime(file): properties.append(str(dt.date()))
        except:
            pass
        try:
            if v := pe_version(file): properties.append(v)
        except:
            pass
    return f'"{os.path.relpath(file, basedir) if basedir else file}"{" ["+", ".join(properties)+"]" if properties else ""}'


def nsis_install_plugin_files(instdir, plugindir, input={}):
    """
    Copy plugin files from `plugindir` into the NSIS installation at `instdir`.
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
    
    Parameters:
        instdir (str): Path to the NSIS installation directory.
    
        plugindir (str): Path to the directory containing the plugin files.

        input (dict): Optional input parameters (see script arguments for details), including:
        - `plugin_name`
        - `plugin_x86_ansi_regex`, `plugin_x86_unicode_regex`, `plugin_amd64_unicode_regex`
        - `plugin_ignore_regex`
        - `nsis_overwrite_newer`

    Returns:
        copied (int): Number of files copied.
    """
    copied = 0
    print(f'Installing plugin from "{plugindir}" into "{instdir}"')
    if input is None: input = {}

    mandatory_directories = ['Bin', 'Contrib', 'Docs', 'Examples', 'Include', 'Plugins', 'Stubs']
    mandatory_files = [os.path.join('Stubs', 'uninst')]
    for dir in mandatory_directories:
        absdir = os.path.join(instdir, dir)
        assert os.path.exists(absdir) and os.path.isdir(absdir), f'Invalid NSIS installation directory: "{instdir}" (missing "{dir}")'
    for file in mandatory_files:
        absfile = os.path.join(instdir, file)
        assert os.path.exists(absfile) and os.path.isfile(absfile), f'Invalid NSIS installation directory: "{instdir}" (missing "{file}")'
    
    # collect all .dll files and classify them by architecture and charset
    def should_ignore(relpath):
        """ Return `True` if the path should be ignored. The path can be absolute or relative to `plugindir`. """
        if (regex := input.get('plugin_ignore_regex')) is not None:
            if os.path.isabs(relpath):
                relpath = os.path.normpath(os.path.relpath(relpath, plugindir))
            if re.match(regex, relpath, re.IGNORECASE):
                if verbose: print(f'Info: Ignore "{relpath}" by input regex')
                return True
        return False

    def copyfile(file, destdir):
        """ Copy a file to a directory. `file` can be absolute or relative to `plugindir`. """
        relfile = os.path.normpath(os.path.relpath(file, plugindir) if os.path.isabs(file) else file)
        absfile = os.path.normpath(file if os.path.isabs(file) else os.path.join(plugindir, file))
        destfile = os.path.join(destdir, os.path.basename(file))
        print(f'Copy {format_path(absfile, plugindir)} --> {format_path(destfile, instdir)}')
        os.makedirs(os.path.dirname(destfile), exist_ok=True)
        shutil.copyfile(absfile, destfile)
        nonlocal copied
        copied += 1

    plugin_files = []
    for file in glob.glob(os.path.join(plugindir, '**', '*.dll'), recursive=True):
        if os.path.isfile(file):
            relfile = os.path.normpath(os.path.relpath(file, plugindir))
            if should_ignore(relfile):
                pass
            elif (arch := pe_architecture(file)) not in ['x86', 'amd64']:
                print(f'Warning: Ignore "{relfile}" with unsupported architecture "{arch}"')
            elif (source_dir := relfile.split(os.sep)[0]).lower() in ['contrib', 'docs', 'examples', 'include']:
                print(f'Warning: Ignore "{relfile}" in reserved directory "{source_dir}"')
            elif pe_is_debug(file):
                print(f'Warning: Ignore "{relfile}" (debug PE file)')
            elif relfile[:5].lower() == 'debug':
                print(f'Warning: Ignore "{relfile}" (in "Debug" directory)')
            else:
                plugin_files.append({'path': file})
    assert len(plugin_files) > 0, f'No DLL files found in "{plugindir}"'

    for plugin in plugin_files:
        # already classified?
        if (target := plugin.get('target', None)) is not None and target != '':
            continue

        # PE info
        ansi_count, wide_count = pe_imports_charset_count(plugin['path'])
        arch = pe_architecture(plugin['path'])

        # match by regex
        relfile = os.path.relpath(plugin['path'], plugindir)
        regex_dict = {}
        if (regex := input.get('plugin_x86_unicode_regex')) is not None:   regex_dict['x86-unicode'] = regex
        if (regex := input.get('plugin_x86_ansi_regex')) is not None:      regex_dict['x86-ansi'] = regex
        if (regex := input.get('plugin_amd64_unicode_regex')) is not None: regex_dict['amd64-unicode'] = regex
        match_count = 0
        for target, regex in regex_dict.items():
            if re.match(regex, relfile, re.IGNORECASE):
                match_count += 1
                if match_count == 1:
                    plugin['target'] = target
                else:
                    plugin_files.append({'path': plugin['path'], 'target': target})
                print(f'Info: Classified "{relfile}" as "{target}" by input regex')

        if (target := plugin.get('target', None)):
            continue    # already classified by regex

        # determine target architecture
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
        if charset is None and arch == 'amd64':
            # example plugins: "Registry"
            charset = 'unicode'
            print(f'Warning: Assuming charset of "{relfile}" is "{charset}" (A:{ansi_count}/W:{wide_count} imports, amd64 is likely unicode)')            

        if charset is not None and arch in ['x86', 'amd64']:
            plugin['target'] = f'{arch}-{charset}'
        else:
            raise ValueError(f'Cannot classify "{relfile}". architecture="{arch}", charset="{charset}"')

    unique_files = []

    # plugin name
    pluginame = input.get('plugin_name', None)
    if pluginame is None:
        candidates = []
        for plugin in plugin_files:
            if plugin.get('path') is not None and plugin.get('target') is not None:
                filename = os.path.splitext(os.path.basename(plugin['path']))[0]
                if filename not in candidates:
                    candidates.append(filename)
        if len(candidates) >= 2:
            print(f'Warning: Multiple plugin names found in "{plugindir}": {candidates}')
        if len(candidates) >= 1:
            candidates.sort(key=len)    # prefer shortest name
            pluginame = candidates[0]

    if pluginame and verbose: print(f'Info: Assign plugin name "{pluginame}"')
    assert pluginame, f'Cannot determine plugin name in "{plugindir}"'

    # copy plugin (*.dll) files
    overwrite_newer = input.get('nsis_overwrite_newer', False)
    for plugin in plugin_files:
        targetdir = os.path.join(instdir, 'Plugins', plugin['target'])
        targetdll = os.path.join(targetdir, os.path.basename(plugin['path']))
        if os.path.exists(targetdir):
            unique_files.append(plugin['path'])
            if overwrite_newer or pe_file_is_newer(plugin['path'], targetdll):
                copyfile(plugin['path'], targetdir)
            else:
                print(f'Skip {format_path(plugin["path"], plugindir)} --> {format_path(targetdll, instdir)} (not newer)')
        else:
            print(f'Skip {format_path(plugin["path"], plugindir)} --> {format_path(targetdll, instdir)} (unsupported target)')

    if copied == 0:
        if verbose: print(f'Info: All plugin DLL files are up-to-date. No files copied.')
        return copied

    # copy other files
    copy_matrix = [
        (os.path.join(plugindir, 'Docs'),     [r'.*readme.*', r'.*howto.*', r'.*docs.*', r'.*\.txt', r'.*\.md'], os.path.join(instdir, 'Docs', pluginame)),
        (os.path.join(plugindir, 'Examples'), [r'.*\.nsi'], os.path.join(instdir, 'Examples', pluginame)),
        (os.path.join(plugindir, 'Include'),  [r'.*\.nsh'], os.path.join(instdir, 'Include'))
    ]
    
    for source_dir, source_regex_list, destination_dir in copy_matrix:
        if os.path.exists(source_dir) and os.path.isdir(source_dir):
            # copy source_dir -> destination_dir, where source is available
            for file in glob.glob(os.path.join(source_dir, '**'), recursive=True):
                if os.path.isfile(file):
                    if not should_ignore(file):
                        copyfile(file, destination_dir)
        else:
            # source_dir doesn't exist
            # copy `source\**\<regex>` -> destination_dir
            for file in glob.glob(os.path.join(plugindir, '**'), recursive=True):
                if os.path.isfile(file):
                    for regex in source_regex_list:
                        if re.match(regex, os.path.relpath(file, plugindir), re.IGNORECASE):
                            if file not in unique_files:
                                unique_files.append(file)
                                if not should_ignore(file):
                                    copyfile(file, destination_dir)
    return copied


def nsis_install_plugin(input):
    """ Main function to download and install a NSIS plugin. """

    if verbose:
        print(f'Input: {input}')

    # list NSIS installations
    nsis_installations = []
    if instdir_list := input.get('nsis_directory'):
        assert (type(instdir_list) == list and len(instdir_list) > 0), f'Invalid --nsis-directory argument: {instdir_list}'
        for instdir in instdir_list:
            instdir = os.path.normpath(os.path.expandvars(instdir))
            assert os.path.exists(instdir) and os.path.isdir(instdir), f'Invalid NSIS installation directory: "{instdir}"'
            if os.path.exists(path := os.path.join(instdir, 'makensis.exe')):
                makensis = path
            elif os.path.exists(path := os.path.join(instdir, 'makensis')):
                makensis = path
            else:
                raise ValueError(f'Invalid NSIS installation directory: "{instdir}" (missing "makensis.exe" or "makensis")')
            nsis_installations.append((makensis, instdir))
    else:
        nsis_installations = nsis_list()
    assert len(nsis_installations) > 0, 'No NSIS installations found on the system'

    # download plugin
    github_owner = input.get('github_owner', None)
    github_repo  = input.get('github_repo', None)
    github_tag   = input.get('github_tag', 'latest')
    github_asset_regex = input.get('github_asset_regex', None)
    url = input.get('url', None)
    pluginzip = None
    if github_owner and github_repo and github_tag and github_asset_regex:
        pluginzip = download_github_asset(github_owner, github_repo, github_tag, github_asset_regex, downloadsdir)
    elif url:
        pluginzip = download_file(url, downloadsdir)
    else:
        raise ValueError('No plugin source specified. Use either the GitHub options or the URL option.')
    
    # unzip plugin archive
    plugindir = os.path.join(pluginsdir, os.path.basename(os.path.splitext(pluginzip)[0]))
    extract_archive(pluginzip, plugindir)

    copied = 0
    for makensis, instdir in nsis_installations:
        # try:
        #     version = nsis_version(makensis)
        #     arch = pe_architecture(makensis)
        # except:
        #     version = 'unknown'
        #     arch = 'unknown'
        # print(f'Found nsis/{version}-{arch} in "{instdir}"')
        copied += nsis_install_plugin_files(instdir, plugindir, input)

    print(f'Copied {copied} files.')
    return copied


if __name__ == '__main__':

    from argparse import ArgumentParser
    import argparse
    parser = ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog='nsis-install-plugin',
        description='Download and install NSIS plugins into NSIS installations.',
        epilog=
'''
Examples:
  action.py --github-owner "negrutiu" --github-repo "nsis-nscurl" --github-tag=latest --github-asset-regex "NScurl\\.zip"
  action.py --url "https://nsis.sourceforge.io/mediawiki/images/1/14/NsExpr.zip"
'''
    )
    parser.add_argument("-v", "--verbose", action='store_true', help='more verbose output')

    groupGitHub = parser.add_argument_group('GitHub', 'Download a NSIS plugin from a GitHub release')
    groupGitHub.add_argument('--github-owner', type=str, help='github owner (user or organization)')
    groupGitHub.add_argument('--github-repo', type=str, help='github repository')
    groupGitHub.add_argument('--github-tag', type=str, default='latest', help='github release tag (default: "latest")')
    groupGitHub.add_argument('--github-asset-regex', type=str, help='regex to match github release asset name (e.g. "plugin\\.zip")')

    groupWeb = parser.add_argument_group('Web', 'Download a NSIS plugin from a web URL')
    groupWeb.add_argument('--url', type=str, help='URL to download a file')

    groupPlugin = parser.add_argument_group('NSIS plugin options')
    groupPlugin.add_argument('--plugin-name', type=str, help='optional plugin name (if not specified, the name is inferred from the DLL filenames)')
    groupPlugin.add_argument('--plugin-x86-ansi-regex', type=str, help='optional regex to identify x86-ansi plugin DLL')
    groupPlugin.add_argument('--plugin-x86-unicode-regex', type=str, help='optional regex to identify x86-unicode plugin DLL')
    groupPlugin.add_argument('--plugin-amd64-unicode-regex', type=str, help='optional regex to identify amd64-unicode plugin DLL')
    groupPlugin.add_argument('--plugin-ignore-regex', type=str, help='optional regex to ignore certain files or directories')

    groupNsis = parser.add_argument_group('NSIS installation options')
    groupNsis.add_argument('--nsis-directory', type=str, action='append', help='NSIS installation directory to use. By default, the NSIS plugin is installed into all NSIS installations found on the system. This option can be specified multiple times.')
    groupNsis.add_argument('--nsis-overwrite-newer', action='store_true', help='overwrite target files even if they are newer than the source files (default: False)')

    args = parser.parse_args()

    if args.verbose:
        verbose = True

    nsis_install_plugin(args.__dict__)
