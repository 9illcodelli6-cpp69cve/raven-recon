"""RAVEN desktop launcher (Windows + Linux).

Starts the local server on a background thread and opens the workbench. Prefers a
native window (pywebview) when it is available; otherwise falls back to the
default browser.

    Windows:  double-click RAVEN.bat / RAVEN.exe, or `python launch.py`
    Linux:    `./raven-app` (source), the packaged `RAVEN` binary, or the
              "RAVEN Recon" entry in the applications menu

Native window backends: Windows uses EdgeChromium (WebView2, via pythonnet);
Linux uses GTK + WebKit2GTK (needs the `gir1.2-webkit2-4.1` package) or Qt.

Options:
    --browser        skip the native window, open the default browser instead
    --port N         preferred loopback port (default 8765; falls back if busy)
    --gui NAME       force a pywebview backend (gtk | qt); also RAVEN_GUI env
    --debug          enable the WebView inspector (right-click > Inspect)
"""
import argparse
import os
import sys
import time
import webbrowser
from pathlib import Path

PORT = 8765


def _resource(*parts) -> Path:
    """Locate a bundled resource (PyInstaller) or a source-tree file."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base.joinpath(*parts)


def _parse_args(argv=None):
    p = argparse.ArgumentParser(prog="raven", description="RAVEN Recon desktop app")
    p.add_argument("--browser", action="store_true",
                   help="open in the default browser instead of a native window")
    p.add_argument("--port", type=int, default=PORT, help="preferred loopback port")
    p.add_argument("--gui", default=os.environ.get("RAVEN_GUI") or None,
                   help="force a pywebview backend: gtk or qt")
    p.add_argument("--debug", action="store_true", help="enable the WebView inspector")
    return p.parse_args(argv)


def _prepare_linux_webview_env():
    """WebKit2GTK quirks that otherwise show a blank/white window on some setups.

    The DMA-BUF renderer (WebKitGTK >= 2.42) fails on many VMs and NVIDIA/older
    Mesa stacks; disabling it is the upstream-recommended workaround and costs
    little for a local dashboard. setdefault() lets the user override either flag.
    """
    if sys.platform.startswith("linux"):
        os.environ.setdefault("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
        # Window/taskbar grouping must match StartupWMClass in raven-recon.desktop.
        try:
            import gi  # noqa: F401  (system PyGObject; optional)
            from gi.repository import GLib
            GLib.set_prgname("raven-recon")
            GLib.set_application_name("RAVEN Recon")
        except Exception:
            pass


class _WindowApi:
    """Window controls exposed to the page (pywebview js_api): the title-bar buttons in
    RAVEN OS and the Workbench call these. Only these three methods are reachable; the
    window handle is a private attribute, which pywebview does not expose to JS."""

    def __init__(self):
        self._window = None
        self._maximized = False

    def _bind(self, window):
        self._window = window

    def minimize(self):
        if self._window is not None:
            self._window.minimize()

    def toggle_maximize(self):
        if self._window is None:
            return
        if self._maximized:
            self._window.restore()
        else:
            self._window.maximize()
        self._maximized = not self._maximized

    def close_window(self):
        if self._window is not None:
            self._window.destroy()


def _open_native_window(url: str, args) -> None:
    """Open the pywebview window; raises if no native backend is usable."""
    _prepare_linux_webview_env()
    import webview  # optional dependency

    # Report export ("Download .md" / "Export workspace report") saves a file the
    # page generates; pywebview blocks downloads unless this is enabled, and then
    # asks the user where to save via the native dialog.
    try:
        webview.settings["ALLOW_DOWNLOADS"] = True
    except Exception:
        pass
    api = _WindowApi()
    window = webview.create_window("RAVEN Recon", url, width=1440, height=900,
                                   min_size=(1024, 640), background_color="#030206",
                                   js_api=api)
    api._bind(window)
    start_kwargs = {"debug": bool(args.debug)}
    if args.gui:
        start_kwargs["gui"] = args.gui
    icon = _resource("packaging", "linux", "raven-recon.png")
    if sys.platform != "win32" and icon.is_file():
        start_kwargs["icon"] = str(icon)
    webview.start(**start_kwargs)


def _serve_in_browser(url: str) -> None:
    webbrowser.open(url)
    print(f"RAVEN Recon is running at {url}")
    print("Close this window (or press Ctrl+C) to stop the server.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopped")


def main(argv=None):
    args = _parse_args(argv)
    # Imported here (not at module top) so --help works instantly and so that
    # RAVEN_DATA_DIR set by a wrapper is honoured before the server module loads.
    from raven.api.server import start_background, shutdown_background_work, DATA_ROOT

    # Binds (with port fallback) and starts serving before returning — no race.
    httpd, port = start_background(port=args.port)
    url = f"http://127.0.0.1:{port}"
    print(f"RAVEN Recon {url}  (data: {Path(DATA_ROOT).resolve()})", flush=True)
    try:
        if args.browser:
            _serve_in_browser(url)
        else:
            try:
                _open_native_window(url, args)
            except Exception as exc:
                # No pywebview / no GTK-WebKit or Qt backend: say why, then use the
                # browser so the app is still usable.
                print(f"Native window unavailable ({type(exc).__name__}: {exc}); "
                      f"falling back to the default browser.", file=sys.stderr, flush=True)
                if sys.platform.startswith("linux"):
                    print("Tip: sudo apt install gir1.2-webkit2-4.1   (enables the native window)",
                          file=sys.stderr, flush=True)
                _serve_in_browser(url)
    finally:
        # Refuse new work before stopping HTTP; cancelled jobs retain partial data.
        shutdown_background_work(wait=True)
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
