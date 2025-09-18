import glob, os, re, shutil, sys

scriptdir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(scriptdir)))
import action    # ../../action.py

tempdir = os.path.join(scriptdir, 'runtime')
downloadsdir = os.path.join(tempdir, 'downloads')
pluginsdir = os.path.join(tempdir, 'plugins')
action.modulesdir = os.path.join(tempdir, 'modules')  # override the location of temporary modules

def print_line(char='-', length=60, suffix=''):
    print(char * length + suffix)

def test_nsis_list(force_download=False, force_extract=False):
    nsis_list = []

    github_sources = [
        {'owner': 'negrutiu', 'repo': 'nsis', 'tag': 'latest', 'file-regex': r'nsis-.*-x86\.exe', 'dirname': 'nsis-negrutiu-x86'},
        {'owner': 'negrutiu', 'repo': 'nsis', 'tag': 'latest', 'file-regex': r'nsis-.*-amd64\.exe', 'dirname': 'nsis-negrutiu-amd64'},
        ]
    web_sources = [
        {'url': 'https://unlimited.dl.sourceforge.net/project/nsis/NSIS%203/3.11/nsis-3.11-setup.exe', 'file-regex': 'nsis-3\.11-setup\.exe', 'dirname': 'nsis-3.11'},
        ]
    
    for source in github_sources:
        instdir = os.path.join(tempdir, 'nsis', source['dirname'])
        if force_extract:
            shutil.rmtree(instdir, ignore_errors=True)  # delete and re-extract
        if not os.path.exists(instdir):
            setupexe = None
            for file in glob.glob(os.path.join(downloadsdir, '*')):
                if os.path.isfile(file) and re.match(source['file-regex'], os.path.basename(file), re.IGNORECASE):
                    if force_download:
                        os.remove(file)     # delete and re-download
                    else:
                        setupexe = file     # use this file
            if not setupexe:
                setupexe = action.download_github_asset(source['owner'], source['repo'], source['tag'], source['file-regex'], downloadsdir)
                action.extract_archive(setupexe, instdir)
        makensisexe = os.path.join(instdir, 'makensis.exe')
        assert os.path.isfile(makensisexe), f'File not found: {makensisexe}'
        nsis_list.append((makensisexe, instdir))

    for source in web_sources:
        instdir = os.path.join(tempdir, 'nsis', source['dirname'])
        if force_extract:
            shutil.rmtree(instdir, ignore_errors=True)  # delete and re-extract
        if not os.path.exists(instdir):
            setupexe = None
            for file in glob.glob(os.path.join(downloadsdir, '*')):
                if os.path.isfile(file) and re.match(source['file-regex'], os.path.basename(file), re.IGNORECASE):
                    if force_download:
                        os.remove(file)     # delete and re-download
                    else:
                        setupexe = file     # use this file
            if not setupexe:
                setupexe = action.download_file(source['url'], downloadsdir)
                action.extract_archive(setupexe, instdir)
        makensisexe = os.path.join(instdir, 'makensis.exe')
        assert os.path.isfile(makensisexe), f'File not found: {makensisexe}'
        nsis_list.append((makensisexe, instdir))

    # return action.nsis_list()     # return local NSIS installations
    return nsis_list


def test_github_plugins():
    github_plugins = [
        {'owner': 'negrutiu',      'repo': 'nsis-nscurl',        'tag': 'latest', 'name_regex': r'NScurl\.zip'},
        {'owner': 'negrutiu',      'repo': 'nsis-nsxfer',        'tag': 'latest', 'name_regex': r'NSxfer.*\.7z'},
        {'owner': 'negrutiu',      'repo': 'nsis-nsutils',       'tag': 'latest', 'name_regex': r'NSutils.*\.7z'},
        {'owner': 'connectiblutz', 'repo': 'NSIS-ApplicationID', 'tag': 'latest', 'name_regex': r'NSIS-ApplicationID\.zip'},
        {'owner': 'lordmulder',    'repo': 'stdutils',           'tag': 'latest', 'name_regex': r'StdUtils.*\.zip'},
        ]

    count = 0
    index = 0
    for plugin in github_plugins:
        index += 1
        print_line()
        print(f'[github][{index}/{len(github_plugins)}] {str(plugin)}')
        pluginzip = action.download_github_asset(plugin['owner'], plugin['repo'], plugin['tag'], plugin['name_regex'], downloadsdir)
        plugindir = os.path.join(pluginsdir, os.path.splitext(os.path.basename(pluginzip))[0])
        action.extract_archive(pluginzip, plugindir)
        for makensis, instdir in test_nsis_list():
            count += action. nsis_inject_plugin(instdir, plugindir)

    return count


def test_web_plugins():
    web_plugins = [
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/4/4a/AccessControl.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/7/7b/Animate.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/1a/AnimGif.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/9/9d/AnimGifPe.zip', 'tags': ['debug']},  # debug dll (ansi)
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
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/12/InvokeShellVerb-1.1.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c1/IpConfig.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/53/KillProcDll&FindProcDll.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/12/KillProcDLL-bin.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/55/Linker-1.2.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/a/af/Locate.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d3/LockedList.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d1/LogEx.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/13/Marquee.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/d/d7/Md5dll.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/67/Mssql_oledb2.zip', 'tags': ['classify'],
         'input': {'x86-unicode': r'Plugins(\/|\\)UMSSQL_OLEDB\.dll', 'x86-ansi': r'Plugins(\/|\\)MSSQL_OLEDB\.dll'}},   # charset classification failure "Plugins\UMSSQL_OLEDB.dll"
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
        {'url': 'https://oss.netfarm.it/win32/nsRestartExplorer-1.4.7z', 'tags': ['7z']},
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
         'input': {'ignore': r'.*PocketPC.*', 'x86-unicode': r'.*Plugin(\/|\\)registry\.dll', 'x86-ansi': r'.*Plugin(\/|\\)registry\.dll'}},    # charset classification failure
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/fe/ScrollLicense.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/0/08/SelfDel.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/5/51/Services.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/11/SetCursor.zip', 'tags': ['stu']},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/f/fb/Sfhelper.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/c/c7/ShellExecAsUser.zip'},
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/6/68/ShellExecAsUser_amd64-Unicode.7z', 'tags': ['7z', 'bcj2']},   # BCJ2 filter is not supported by py7zr
        {'url': 'https://nsis.sourceforge.io/mediawiki/images/1/1d/ShellExecAsUserUnicodeUpdate.zip'},
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
    
    count = 0
    index = 0
    for plugin in web_plugins:
        index += 1
        if not plugin.get('url'): continue
        print_line()
        print(f'[web][{index}/{len(web_plugins)}] {plugin["url"]}')
        pluginzip = action.download_file(plugin['url'], downloadsdir)
        plugindir = os.path.join(pluginsdir, os.path.splitext(os.path.basename(pluginzip))[0])
        action.extract_archive(pluginzip, plugindir)
        for makensis, instdir in test_nsis_list():
            count += action.nsis_inject_plugin(instdir, plugindir, input_dict=plugin.get('input'))

    return count


if __name__ == '__main__':

    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', help='more verbose output')
    parser.add_argument("--recreate-test-nsis", action='store_true', help='download and extract NSIS test installations even if they already exist')
    args = parser.parse_args()

    print(f'Arguments: {args.__dict__}')

    if args.verbose:
        action.verbose = True

    print('Preparing test NSIS installations...')
    test_nsis_list(force_extract=args.recreate_test_nsis, force_download=args.recreate_test_nsis)

    copy_count = 0

    copy_count += test_github_plugins()
    copy_count += test_web_plugins()

    print('================================================================================')
    print(f'Copied {copy_count} files')
    print('================================================================================')

