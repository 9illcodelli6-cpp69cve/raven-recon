# PyInstaller hook (RAVEN Linux port): bundle the WebKit2-4.1 GObject typelib so the
# frozen app can open the pywebview GTK window without the distro's gir1.2 package.
# PyInstaller ships no hook for WebKit2; this mirrors its built-in gi hooks (e.g. Soup).
from PyInstaller.utils.hooks.gi import GiModuleInfo

module_info = GiModuleInfo("WebKit2", "4.1")
if module_info.available:
    binaries, datas, hiddenimports = module_info.collect_typelib_data()
