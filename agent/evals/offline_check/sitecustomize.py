"""Optional process-local network denial for the offline live-service check."""
import os
import sys


if os.getenv('TRIAGE_OFFLINE_AUDIT') == '1':
    def audit(event, args):
        if event == 'socket.getaddrinfo':
            host = args[0]
        elif event == 'socket.connect':
            address = args[1]
            if not isinstance(address, tuple):
                return
            host = address[0]
        elif event == 'socket.sendto':
            address = args[-1]
            if not isinstance(address, tuple):
                return
            host = address[0]
        else:
            return
        if host not in {None, '', 'localhost', '127.0.0.1', '::1'}:
            raise PermissionError('Offline check prohibits non-loopback network access')
    sys.addaudithook(audit)
