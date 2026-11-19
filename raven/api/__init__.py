"""RAVEN local backend — stdlib-only HTTP server for the desktop UI.

Exposes the web workbench and a scope-aware request sender (Repeater / Intruder /
curl) that performs real HTTP requests through the same strict scope rules the
recon engine uses. No third-party dependencies, so it runs anywhere Python does
and packages cleanly into a Windows executable.
"""
