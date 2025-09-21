import glob, os, re, shutil, sys

scriptdir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(scriptdir)))
import action    # ../../action.py

action.tempdir = os.path.join(scriptdir, 'runtime')                 # override
action.downloadsdir = os.path.join(action.tempdir, 'downloads')
action.pluginsdir = os.path.join(action.tempdir, 'plugins')
action.modulesdir = os.path.join(action.tempdir, 'modules')

def print_line(char='-', length=80, suffix=''):
    print(char * length + suffix)

def test_nsis_list(force_download=False, force_extract=False):
    nsis_list = []

    github_sources = [
        ('negrutiu', 'nsis', 'latest', r'nsis-.*-x86\.exe', 'nsis-negrutiu-x86'),
        ('negrutiu', 'nsis', 'latest', r'nsis-.*-amd64\.exe', 'nsis-negrutiu-amd64'),
        ]
    web_sources = [
        ('https://unlimited.dl.sourceforge.net/project/nsis/NSIS%203/3.11/nsis-3.11-setup.exe', r'nsis-3\.11-setup\.exe', 'nsis-3.11'),
        ]
    
    for owner, repo, tag, regex, dirname in github_sources:
        instdir = os.path.join(action.tempdir, 'nsis', dirname)
        if force_extract:
            shutil.rmtree(instdir, ignore_errors=True)  # delete and re-extract
        if not os.path.exists(instdir):
            setupexe = None
            for file in glob.glob(os.path.join(action.downloadsdir, '*')):
                if os.path.isfile(file) and re.match(regex, os.path.basename(file), re.IGNORECASE):
                    if force_download:
                        os.remove(file)     # delete and re-download
                    else:
                        setupexe = file     # use this file
            if not setupexe:
                setupexe = action.download_github_asset(owner, repo, tag, regex, None, action.downloadsdir)
                action.extract_archive(setupexe, instdir)
        makensisexe = os.path.join(instdir, 'makensis.exe')
        assert os.path.isfile(makensisexe), f'File not found: {makensisexe}'
        nsis_list.append((makensisexe, instdir))

    for url, regex, dirname in web_sources:
        instdir = os.path.join(action.tempdir, 'nsis', dirname)
        if force_extract:
            shutil.rmtree(instdir, ignore_errors=True)  # delete and re-extract
        if not os.path.exists(instdir):
            setupexe = None
            for file in glob.glob(os.path.join(action.downloadsdir, '*')):
                if os.path.isfile(file) and re.match(regex, os.path.basename(file), re.IGNORECASE):
                    if force_download:
                        os.remove(file)     # delete and re-download
                    else:
                        setupexe = file     # use this file
            if not setupexe:
                setupexe = action.download_file(url, action.downloadsdir)
                action.extract_archive(setupexe, instdir)
        makensisexe = os.path.join(instdir, 'makensis.exe')
        assert os.path.isfile(makensisexe), f'File not found: {makensisexe}'
        nsis_list.append((makensisexe, instdir))

    # return action.nsis_list()     # return local NSIS installations
    return nsis_list


def test_github_plugins(overwrite_newer=False, expect_zero_copies=False):
    input_list = [
        {'github_owner': 'negrutiu',      'github_repo': 'nsis-nscurl',        'github_tag': 'latest', 'github_asset_regex': r'NScurl\.zip'},
        {'github_owner': 'negrutiu',      'github_repo': 'nsis-nsxfer',        'github_tag': 'latest', 'github_asset_regex': r'NSxfer.*\.7z'},
        {'github_owner': 'negrutiu',      'github_repo': 'nsis-nsutils',       'github_tag': 'latest', 'github_asset_regex': r'NSutils.*\.7z'},
        {'github_owner': 'connectiblutz', 'github_repo': 'NSIS-ApplicationID', 'github_tag': 'latest', 'github_asset_regex': r'NSIS-ApplicationID\.zip',
         'tags': ['ignore', 'debug']},  # ignore (Debug/ApplicationID.dll, DebugUnicode/ApplicationID.dll)
        {'github_owner': 'lordmulder',    'github_repo': 'stdutils',           'github_tag': 'latest', 'github_asset_regex': r'StdUtils.*\.zip',
          'plugin_ignore_regex': r'.*(\/|\\)Tiny(\/|\\).*',
          'tags': ['overlapping']},  # multiple DLLs with same name and target
        ]

    copied = 0
    index = 0
    for input in input_list:
        index += 1
        print_line()
        print(f'[github][{index}/{len(input_list)}] {str(input)}')
        input['nsis_directory'] = [nsis[1] for nsis in test_nsis_list()]  # list of NSIS installation directories
        input['nsis_overwrite_newer'] = overwrite_newer
        copied += action.nsis_install_plugin(input)
        if overwrite_newer:
            assert copied > 0, f'No files were copied for {str(input)}, non-zero expected'
        if expect_zero_copies:
            assert copied == 0, f'{copied} files were copied for {str(input)}, zero expected'

    return copied


def test_web_plugins(overwrite_newer=False, expect_zero_copies=False):
    input_list = [
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4a/AccessControl.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/7b/Animate.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/1a/AnimGif.zip', 'tags': ['ignore', 'reserved']},  # ignore (Contrib\AnimGif\AnimGif.dll)
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/9d/AnimGifPe.zip', 'tags': ['ignore', 'debug']},   # ignore debug (Plugins\AnimGif.dll)
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d4/AppAssocReg-0.4.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/8/84/Aero.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/fd/Base64.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c3/BaseConervt.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/62/BgWorker.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c0/Blowfish.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/a7/BlowfishDLL.7z', 'tags': ['7z']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/76/BrandingURL.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4c/ButtonEvent.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/aa/Cabdll.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/ce/CABSetup.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c7/CabX.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/73/CallAnsiPlugin_0.2.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/50/Cdrom.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/8/8e/ChangeRes.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/9c/CLR.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/6d/ComPlusAdminEX.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/8/87/Cpudesc.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/a5/CPUFeatures.2013-02-26.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/cd/Crypto.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/0/01/DcryptDll.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/56/Debug_plug-in.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/75/Dialogs.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/3/38/DumpLog.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4e/Dumpstate.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4e/Dumpstate.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/72/EBanner.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/eb/Email_validation.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/7c/EmbedHTML.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/6a/EmbeddedLists.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/62/EnumINI.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/7f/EnVar_plugin.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/0/02/EventLog.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/7e/ExDlg.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/2/2f/ExecCmd.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/0/0f/ExecDos.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4c/ExecPri.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/3/34/Extractdll.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/aa/Extractdllex.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/9c/Fct.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/3/34/Firewall-disabler-1.0.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/0/0e/Floatop.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c0/FontInfo.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/0/08/FreeArcPlugin.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/2/21/Fsp.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/b/b8/NSIS_version_plugin_03.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/9a/GetFirstRemovable.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/61/HandleFileDragDrop.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/f6/HwInfo.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/97/InetBgDL.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c9/Inetc.zip'},
        {'url': 'https://master.dl.sourceforge.net/project/nsis-ioex/IOEx%20beta/2.4.5%20beta%203/InstallOptionsEx2.4.5b3.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d4/Internet.zip'},
    #   {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/12/InvokeShellVerb-1.1.zip'},   # 404
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c1/IpConfig.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/53/KillProcDll&FindProcDll.zip', 'tags': ['multiple']},  # multiple plugins in one archive
    #   {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/12/KillProcDLL-bin.zip'},       # conflict with above
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/55/Linker-1.2.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/af/Locate.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d3/LockedList.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d1/LogEx.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/13/Marquee.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d7/Md5dll.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/67/Mssql_oledb2.zip', 'tags': ['classify'],
         'plugin_x86_unicode_regex': r'Plugins(\/|\\)UMSSQL_OLEDB\.dll',
         'plugin_x86_ansi_regex': r'Plugins(\/|\\)MSSQL_OLEDB\.dll'},   # charset classification failure "Plugins\UMSSQL_OLEDB.dll"
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/19/Name2ip.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/cf/NewAdvSplash.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/69/Nsis7z_19.00.7z', 'tags': ['7z', 'bcj2']},   # BCJ2 filter is not supported by py7zr
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/97/NsArray.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/14/NsExpr.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/ea/NsFlash.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/f0/NsJSON.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/ae/NsKeyHook.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/e7/NsODBC.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d0/NsODBC-unicode.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/fc/NsODBCext.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/18/NsProcess.zip', 'tags': ['lzma']},           # LZMA zip
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/59/NsRandom.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/0/0f/NsResize.zip'},
        {'url': 'https://oss.netfarm.it/win32/nsRestartExplorer-1.4.7z',
         'plugin_ignore_regex': r'.*MinGW Ansi.*',
         'tags': ['7z', 'overlapping']},  # multiple DLLs with same name and target
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/e5/NsRichEdit.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/7e/NsSCM.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/1e/NsScreenshot.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/2/25/NsThread.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/8/88/NsUnzip.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/2/28/Nsisos.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/5d/Nsisdt.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/dd/NSISGames.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/76/Nsislog.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/48/NSISpcre.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/8/8d/NSISDotNetChecker-Unicode.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/3/3b/NSISDirEx.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4e/NSISList-Plugin.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c2/NSIS-Python27.zip', 'tags': ['depends']},    # extra python27.dll
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/76/NSIS_Simple_Firewall_Plugin_ANSI_1.21.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/e0/NSIS_Simple_Firewall_Plugin_Unicode_1.21.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/2/24/NSIS_Simple_Service_Plugin_ANSI_1.30.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/ef/NSIS_Simple_Service_Plugin_Unicode_1.30.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/cc/NSIS_TCP_Plugin_Unicode_x86.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/8/80/NsisUrlLib.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/8/85/NotifyIcon.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/ee/Nwizplugin.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/e6/Nxs.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/45/PassDialog.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/1a/Pixelshader.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/8/86/ProxySettings.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/cf/PS.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/93/Pwgen-001.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/ce/RealProgress.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/13/RegBin.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/47/Registry.zip', 'tags': ['classify'],
         'plugin_ignore_regex': r'.*PocketPC.*',
         'plugin_x86_unicode_regex': r'.*Plugin(\/|\\)registry\.dll',
         'plugin_x86_ansi_regex': r'.*Plugin(\/|\\)registry\.dll'},    # charset classification failure
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/fe/ScrollLicense.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/0/08/SelfDel.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/51/Services.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/11/SetCursor.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/fb/Sfhelper.zip'},
    #   {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c7/ShellExecAsUser.zip'},               # conflict with below
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/68/ShellExecAsUser_amd64-Unicode.7z', 'tags': ['7z', 'bcj2']},   # BCJ2 filter is not supported by py7zr
    #   {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/1d/ShellExecAsUserUnicodeUpdate.zip'},  # conflict with above
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/6c/Shelllink.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/f9/ShutDown.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/3/35/ShutdownAllow.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4c/SpiderBanner_plugin.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/78/Stack.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c1/SysRestore.zip'},
        {'url': 'http://www.cherubicsoft.com/_media/nsis/tapihelp.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/e/eb/Textreplace.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/59/ThreadTimer_v1.1.1.7z', 'tags': ['7z']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/aa/Time.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/fc/TitlebarProgress.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/2/22/ToggleInstFiles.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/40/Tooltips.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/3/3d/Unicode_V1.2.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/a7/UnicodePathTest_1.0.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/13/Untbgz.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/9d/Untgz.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4a/UserMgr_(2021).zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/6f/Win7TaskbarProgress_20091109.zip'},
        ]
    
    copied = 0
    index = 0
    for input in input_list:
        index += 1
        if input.get('url'):
            print_line()
            print(f'[web][{index}/{len(input_list)}] {input["url"]}')
            input['nsis_directory'] = [nsis[1] for nsis in test_nsis_list()]  # list of NSIS installation directories
            input['nsis_overwrite_newer'] = overwrite_newer
            copied += action.nsis_install_plugin(input)
            if overwrite_newer:
                assert copied > 0, f'No files were copied for {str(input)}, non-zero expected'
            if expect_zero_copies:
                assert copied == 0, f'{copied} files were copied for {str(input)}, zero expected'

    return copied


if __name__ == '__main__':

    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', help='more verbose output')
    parser.add_argument("--recreate-test-nsis", action='store_true', help='download and extract NSIS test installations even if they already exist')
    args = parser.parse_args()

    print(f'Arguments: {args.__dict__}')

    if args.verbose:
        action.verbose = True

    print('Preparing temporary NSIS installations...')
    test_nsis_list(force_extract=args.recreate_test_nsis, force_download=args.recreate_test_nsis)

    copied = 0
    copied += test_github_plugins()
    copied += test_web_plugins()

    print_line('=')
    print(f'Copied {copied} files')
    print_line('=')

