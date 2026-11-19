"""Run the repository tests with a process-local loopback-only socket guard."""
import ipaddress
import socket
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def local_host(host):
    if isinstance(host, bytes):
        host = host.decode('ascii')
    if host in (None, '', 'localhost'):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


original_dns = socket.getaddrinfo
original_connect = socket.socket.connect
original_connect_ex = socket.socket.connect_ex


def guarded_dns(host, *args, **kwargs):
    if not local_host(host):
        raise AssertionError('Test attempted non-loopback DNS; mock the transport')
    return original_dns(host, *args, **kwargs)


def guarded_connect(self, address):
    if not isinstance(address, tuple) or not local_host(address[0]):
        raise AssertionError('Test attempted non-loopback connection')
    return original_connect(self, address)


def guarded_connect_ex(self, address):
    if not isinstance(address, tuple) or not local_host(address[0]):
        raise AssertionError('Test attempted non-loopback connection')
    return original_connect_ex(self, address)


socket.getaddrinfo = guarded_dns
socket.socket.connect = guarded_connect
socket.socket.connect_ex = guarded_connect_ex

import pytest

raise SystemExit(pytest.main([str(REPO / 'tests'), '-q', *sys.argv[1:]]))
