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


def ensure(condition, message=None):
    """ Reimplementation of `assert` that works in optimized mode. """
    if condition:
        return  # all good

    import inspect
    frame = inspect.currentframe().f_back           # caller's frame
    try:
        call_line = inspect.getframeinfo(frame).code_context[0]
        call_line = call_line.strip()               # strip indentation
        condition = call_line[call_line.find("(") + 1 : call_line.rfind(")")].strip()   # "ensure(cond, msg)" -> "cond, msg"
        # extract condition from `condition, rf'message'`
        strdelim = condition[-1]                    # string end-delimiter (' or ")
        if (msgstart := condition.rfind(strdelim, 0, -1)) > 0:
            condition = condition[:msgstart]        # remove message string
            condition = condition.rstrip(strdelim)  # remove string start-delimiter
            condition = condition.rstrip('rf')      # remove possible r or f prefix
            condition = condition.rstrip(', ')      # remove comma between condition and message
    finally:
        del frame   # avoid reference cycles

    condition = '(' + condition + ')' + (f' --- "{message}"' if message else '')
    raise AssertionError(condition)


def download_github_asset(owner, repo, tag, name_regex, token, outdir):
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

    # GITHUB_TOKEN is optional, but recommended to avoid rate limiting
    if not token:
        token = os.environ.get('GITHUB_TOKEN', None)    # fallback to environment variable

    t0 = datetime.datetime.now()
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    http_request = request.Request(url)
    http_request.add_header('Accept', 'application/vnd.github.v3+json')
    if token:
        http_request.add_header('Authorization', f'Bearer {token}')
    with request.urlopen(http_request, context=ssl_context) as http:
        import json
        response_json = json.loads(http.read().decode('utf-8'))
        print(f'GET {url} --> {http.status} {http.reason}, {int((datetime.datetime.now()-t0).total_seconds()*1000)} ms')
        if verbose:
            print(f'    Request headers {http_request.header_items()}')
            print(f'    Response headers {http.getheaders()}')
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

    t0 = datetime.datetime.now()
    http_request = request.Request(asset_url)
    http_request.add_header('Accept', 'application/octet-stream')
    if token:
        http_request.add_header('Authorization', f'Bearer {token}')
    with request.urlopen(http_request, context=ssl_context) as http:
        if not os.path.exists(outdir):
            os.makedirs(outdir, exist_ok=True)
        with open(asset_path, 'wb') as file:
            shutil.copyfileobj(http, file)
            print(f'GET {asset_url} --> {http.status} {http.reason}, {int((datetime.datetime.now()-t0).total_seconds()*1000)} ms')
            if verbose:
                print(f'    Request headers: {http_request.header_items()}')
                print(f'    Response headers: {http.getheaders()}')
        return asset_path


def download_file(url, outdir, headers={}):
    """ Download a file from the specified URL to the specified output directory. Returns the path to the downloaded file. """
    filepath = os.path.join(outdir, os.path.basename(url))
    if os.path.exists(filepath):
        print(f'Reuse existing "{filepath}"')
        return filepath

    t0 = datetime.datetime.now()
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    http_request = request.Request(url, headers=headers)
    with request.urlopen(http_request, context=ssl_context) as http:
        if not os.path.exists(outdir):
            os.makedirs(outdir, exist_ok=True)
        with open(filepath, 'wb') as file:
            shutil.copyfileobj(http, file)
            print(f'GET {url} --> {http.status} {http.reason}, {int((datetime.datetime.now()-t0).total_seconds()*1000)} ms')
            if verbose:
                print(f'    Request headers {http_request.header_items()}')
                print(f'    Response headers {http.getheaders()}')
        return filepath


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
    if os.name == 'nt':
        path = \
            os.path.expandvars('%ProgramFiles%\\7-Zip') + os.pathsep + \
            os.path.expandvars('%ProgramFiles(x86)%\\7-Zip') + os.pathsep + \
            os.environ.get('PATH', '')
        if file := shutil.which('7z.exe', path=path):
            return file
    else:
        # on posix prefer 7zz (from "7zip" on ubuntu, "sevenzip" on macos) over 7z (from deprecated "p7zip")
        if file := shutil.which('7zz'):
            return file
        if file := shutil.which('7z'):
            return file
    return None


def extract_archive(archive, outdir):
    if not os.path.exists(archive):
        raise FileNotFoundError(f'"{archive}" not found')

    # use 7z/7zz if available (supports more formats than built-in modules)
    if (sevenzip := find_7z()) is not None:
        try:
            args = [sevenzip, 'x', '-y', f'-o{outdir}', archive]
            os.makedirs(os.path.dirname(outdir), exist_ok=True)
            try:
                subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                subprocess.check_call(args)     # retry with output, useful for debugging
            if verbose: print(f'Command {args} returned 0')
            return
        except Exception as ex:
            print(f'Warning: {ex}')

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
    config = lief.PE.ParserConfig()
    config.parse_exports = config.parse_imports = config.parse_reloc = config.parse_rsrc = config.parse_signature = False
    if pe := lief.PE.parse(path, config):
        assert isinstance(pe, lief.PE.Binary)
        # https://learn.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
        machines = {0x014c: 'x86', 0x8664: 'amd64', 0xaa64: 'arm64', 0x0200: 'ia64'}
        return machines.get(pe.header.machine.value, None)
    return None


def pe_version(path, product=False):
    """ Return the file/product version of a PE file or `None`. """
    config = lief.PE.ParserConfig()
    config.parse_exports = config.parse_imports = config.parse_reloc = config.parse_signature = False
    config.parse_rsrc = True
    if pe := lief.PE.parse(path, config):
        assert isinstance(pe, lief.PE.Binary)
        if pe.has_resources:
            if pe.resources_manager.has_version:
                version = pe.resources_manager.version[0].file_info
                if product:
                    return f'{version.product_version_ms >> 16}.{version.product_version_ms & 0xFFFF}.{version.product_version_ls >> 16}.{version.product_version_ls & 0xFFFF}'
                else:
                    return f'{version.file_version_ms >> 16}.{version.file_version_ms & 0xFFFF}.{version.file_version_ls >> 16}.{version.file_version_ls & 0xFFFF}'
    return None


def pe_header_datetime(path):
    """ Return the PE header timestamp as a `datetime` object or `None`. """
    config = lief.PE.ParserConfig()
    config.parse_exports = config.parse_imports = config.parse_reloc = config.parse_rsrc = config.parse_signature = False
    if pe := lief.PE.parse(path, config):
        assert isinstance(pe, lief.PE.Binary)
        return datetime.datetime.fromtimestamp(pe.header.time_date_stamps)
    return None


def pe_file_is_newer(path1, path2):
    """ Return `True` if `path1` is newer than `path2` based on PE header timestamp. """
    ensure(os.path.exists(path1) and os.path.isfile(path1), f'File not found: "{path1}"')
    if os.path.exists(path2) and os.path.isfile(path2):
        return pe_header_datetime(path1) > pe_header_datetime(path2)
    return True     # path1 wins


def pe_imports_charset_count(path):
    """
    Count the number of ANSI and Wide (Unicode) imports in a PE file.
    Returns:
        tuple: (ansi_count, wide_count)
    """
    ansi_count = 0
    wide_count = 0

    config = lief.PE.ParserConfig()
    config.parse_exports = config.parse_reloc = config.parse_rsrc = config.parse_signature = False
    config.parse_imports = True
    if pe := lief.PE.parse(path, config):
        assert isinstance(pe, lief.PE.Binary)
        if pe.has_imports:
            for module in pe.imports:
                for func in module.entries:
                    if not func.is_ordinal:
                        # print(f'-- {module.name}!{func.name}')
                        if len(func.name) >= 2 and func.name[-2].islower():
                            if func.name[-1] == 'W':
                                wide_count += 1
                            elif func.name[-1] == 'A':
                                ansi_count += 1
        
    return (ansi_count, wide_count)


def pe_imports_module_list(path):
    """ Return a list of imported modules in a PE file (e.g. `['kernel32.dll', 'user32.dll']`) """

    module_list = []
    config = lief.PE.ParserConfig()
    config.parse_exports = config.parse_reloc = config.parse_rsrc = config.parse_signature = False
    config.parse_imports = True
    if pe := lief.PE.parse(path, config):
        assert isinstance(pe, lief.PE.Binary)
        if pe.has_imports:
            for module in pe.imports:
                module_list.append(module.name)
    return module_list


def pe_section_name_list(path):
    """ Return a list of section names in a PE file (e.g. `['.text', '.rdata', '.data', '.rsrc', '.reloc']`) """
    section_list = []
    config = lief.PE.ParserConfig()
    config.parse_exports = config.parse_imports = config.parse_reloc = config.parse_rsrc = config.parse_signature = False
    if pe := lief.PE.parse(path, config):
        assert isinstance(pe, lief.PE.Binary)
        for section in pe.sections:
            section_list.append(section.name)
    return section_list


def pe_print_debug_entries(path):
    if pe := lief.PE.parse(path, lief.PE.ParserConfig.all):
        assert isinstance(pe, lief.PE.Binary)
        print('++++++++++')
        print(f'PDB: {pe.codeview_pdb.filename if pe.codeview_pdb else ""}')
        print('++++++++++')
        print(f'Number of COFF string tables: {len(pe.coff_string_table) if pe.coff_string_table else 0}')
        # for table in pe.coff_string_table:
        #     print(table)      # can be very verbose
        print('++++++++++')
        print(f'Number of COFF symbols: {len(pe.symbols) if pe.symbols else 0}')
        # for symbol in pe.symbols:
        #     print(symbol)     # can be very verbose
        print('++++++++++')
        if pe.has_resources:
            if pe.resources_manager.has_version:
                for version in pe.resources_manager.version:
                    is_debug = version.file_info.has(lief.PE.ResourceVersion.fixed_file_info_t.FILE_FLAGS.DEBUG)
                    print(f'version.file_info.file_flags: {version.file_info.file_flags} {version.file_info.flags} debug={is_debug}')
                    print(f'version.file_info.file_flags_mask: {version.file_info.file_flags_mask}')
                    print(f'version.file_info.file_os: {version.file_info.file_os}')
                    print(f'version.file_info.file_subtype: {version.file_info.file_subtype}')
                    print(f'version.file_info.file_type: {version.file_info.file_type} ({version.file_info.file_type_details})')
        print('++++++++++')
        if pe.has_debug:
            for debug in pe.debug:
                print(debug)
        else:
            print('   No debug information found')
        # for section in pe.sections:
        #     print(section)


def pe_version_has_debug_flag(path):
    """ Return `True` if the PE file has `VS_FF_DEBUG` flag in its version info, `False` otherwise. """
    config = lief.PE.ParserConfig()
    config.parse_exports = config.parse_imports = config.parse_reloc = config.parse_signature = False
    config.parse_rsrc = True
    if pe := lief.PE.parse(path, config):
        assert isinstance(pe, lief.PE.Binary)
        if pe.has_resources:
            if pe.resources_manager.has_version:
                for version in pe.resources_manager.version:
                    return version.file_info.has(lief.PE.ResourceVersion.fixed_file_info_t.FILE_FLAGS.DEBUG)
    return False


def pe_is_debug(path):
    """ Heuristically determine if a PE file is a debug build. Returns `True` or `False`.
    Notes:
    - This function does not guarantee that a PE file is a debug build, it only tries to identify typical characteristics of debug builds
    - Unable to distinguish between msbuild-generated Debug and Release binaries that are linked statically
    """
    is_debug = False

    if not is_debug:
        if pe_version_has_debug_flag(path):
            is_debug = True

    if not is_debug:
        debug_modules = [r'msvcrtd\.dll', r'msvcp\d*d\.dll', r'vcruntime\d*d\.dll', r'ucrtd\.dll', r'ucrtbase\.dll']
        for module in pe_imports_module_list(path):
            for regex in debug_modules:
                if re.match(regex, module, re.IGNORECASE):
                    is_debug = True

    if not is_debug:
        debug_sections = [r'\.debug.*', r'\/\d+']
        for section in pe_section_name_list(path):
            for regex in debug_sections:
                if re.match(regex, section, re.IGNORECASE):
                    is_debug = True

    # print(f'pe_is_debug("{path}") = False')
    # print(f'   imports: {pe_imports_module_list(path)}')
    # print(f'   sections: {pe_section_name_list(path)}')
    # pe_print_debug_entries(path)

    return is_debug


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
                ensure(os.path.exists(instdir) and os.path.isdir(instdir), f'Invalid NSIS share directory: "{instdir}"')
            elif os.path.basename(instdir).casefold() == 'bin' and sys.platform == 'darwin':
                instdir = os.path.dirname(instdir)  # /opt/homebrew/Cellar/makensis/3.11/bin -> /opt/homebrew/Cellar/makensis/3.11/share/nsis
                instdir += '/share/nsis'
                ensure(os.path.exists(instdir) and os.path.isdir(instdir), f'Invalid NSIS share directory: "{instdir}"')

            unique = True
            for makensis0, instdir0 in installations:
                if makensis0.casefold() == makensis.casefold():
                    unique = False
                    break
            if unique:
                installations.append((makensis, instdir))

    return installations


def format_path(file, basedir=None):
    assert file
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

    # mandatory_directories = ['Bin', 'Contrib', 'Docs', 'Examples', 'Include', 'Plugins', 'Stubs']
    mandatory_directories = ['Include', 'Plugins', 'Stubs']
    for dir in mandatory_directories:
        absdir = os.path.join(instdir, dir)
        ensure(os.path.exists(absdir) and os.path.isdir(absdir), f'Invalid NSIS installation directory: "{instdir}" (missing "{dir}")')
    
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
    ensure(len(plugin_files) > 0, f'No DLL files found in "{plugindir}"')

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
            # note: exclude the file name, only look at the directory path (e.g. plugin "unicode.dll" would always match unicode)
            if re.match(regex, os.path.dirname(relfile), re.IGNORECASE):
                charset = 'unicode'
                break
        if charset is None:
            for regex in [r'.*ansi.*']:
                if re.match(regex, os.path.dirname(relfile), re.IGNORECASE):
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

    # check for overlapping plugin files
    for plugin in plugin_files:
        overlapping = sum(1 for entry in plugin_files if entry['target'] == plugin['target'] and os.path.basename(entry['path']).casefold() == os.path.basename(plugin['path']).casefold())
        if overlapping > 1:
            for entry in plugin_files:
                print(f'Found "{entry["path"]}" for target "{entry["target"]}"')
            raise ValueError(f'Found overlapping plugin DLLs for target "{plugin["target"]}". Use "plugin_ignore_regex" to exclude duplicates.')

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
            ensure(os.path.exists(instdir) and os.path.isdir(instdir), f'Invalid NSIS installation directory: "{instdir}"')
            if os.path.exists(path := os.path.join(instdir, 'makensis.exe')):
                makensis = path
            elif os.path.exists(path := os.path.join(instdir, 'makensis')):
                makensis = path
            else:
                raise ValueError(f'Invalid NSIS installation directory: "{instdir}" (missing "makensis.exe" or "makensis")')
            nsis_installations.append((makensis, instdir))
    else:
        nsis_installations = nsis_list()
    
    if len(nsis_installations) == 0:
        print('No NSIS installations found on the system (tip: use "nsis-directory" to indicate one)')
        return 0

    # download plugin
    github_owner = input.get('github_owner', None)
    github_repo  = input.get('github_repo', None)
    github_tag   = input.get('github_tag', 'latest')    # optional, default: latest
    github_asset_regex = input.get('github_asset_regex', None)
    github_token = input.get('github_token', None)      # optional
    url = input.get('url', None)
    pluginzip = None
    if github_owner and github_repo and github_tag and github_asset_regex:
        pluginzip = download_github_asset(github_owner, github_repo, github_tag, github_asset_regex, github_token, downloadsdir)
    elif url:
        pluginzip = download_file(url, downloadsdir)
    else:
        raise ValueError('No plugin source specified (tip: use either the GitHub options or the URL option)')
    
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


import_temp_module('lief')

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
    groupGitHub.add_argument('--github-token', type=str, help='optional (but highly recommended) github token to increase the rate limit')

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
