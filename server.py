#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import base64
from binascii import hexlify
import os
import socket
import sys
import threading
from threading import Thread
from Queue import Queue, Empty
import traceback

import paramiko
from paramiko.py3compat import b, u, decodebytes


# setup logging
paramiko.util.log_to_file('demo_server.log')

host_key = paramiko.RSAKey(filename='test_rsa.key')
#host_key = paramiko.DSSKey(filename='test_dss.key')

print('Read key: ' + u(hexlify(host_key.get_fingerprint())))


class Server (paramiko.ServerInterface):
    # 'data' is the output of base64.encodestring(str(key))
    # (using the "user_rsa_key" files)
    data = (b'AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp'
            b'fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC'
            b'KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT'
            b'UWT10hcuO4Ks8=')
    good_pub_key = paramiko.RSAKey(data=decodebytes(data))

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if (username == 'robey') and (password == 'foo'):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        print('Auth attempt with key: ' + u(hexlify(key.get_fingerprint())))
        if (username == 'robey') and (key == self.good_pub_key):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, cmd):
        print("Got exec request on channel %s for cmd %s" % (channel, cmd,))
        import base64
        print('hi')
        try:
            p = Popen(['PowerShell.exe', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', base64.b64encode(cmd)], cwd=curpath, shell=True, stdout=PIPE, stderr=PIPE)
            (stdout, stderr) = p.communicate()
            print('I got your std right here:', stdout, stderr)
            p = Popen(['PowerShell.exe', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', base64.b64encode('echo hi')], cwd=curpath, shell=True)
            p.communicate()
            channel.send(stdout)
            channel.send(stderr)
            channel.send_exit_status(0)
            return True
        except:
            print('got an error')
            return False
    
    def check_auth_gssapi_with_mic(self, username,
                                   gss_authenticated=paramiko.AUTH_FAILED,
                                   cc_file=None):
        """
        .. note::
            We are just checking in `AuthHandler` that the given user is a
            valid krb5 principal! We don't check if the krb5 principal is
            allowed to log in on the server, because there is no way to do that
            in python. So if you develop your own SSH server with paramiko for
            a certain platform like Linux, you should call ``krb5_kuserok()`` in
            your local kerberos library to make sure that the krb5_principal
            has an account on the server and is allowed to log in as a user.

        .. seealso::
            `krb5_kuserok() man page
            <http://www.unix.com/man-page/all/3/krb5_kuserok/>`_
        """
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(self, username,
                                gss_authenticated=paramiko.AUTH_FAILED,
                                cc_file=None):
        if gss_authenticated == paramiko.AUTH_SUCCESSFUL:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        UseGSSAPI = True
        GSSAPICleanupCredentials = False
        return UseGSSAPI

    def get_allowed_auths(self, username):
        return 'gssapi-keyex,gssapi-with-mic,password,publickey'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth,
                                  pixelheight, modes):
        return True


DoGSSAPIKeyExchange = True

import select

def wait_read(sock):
    while True:
        inputready, outputready, exceptready = select.select([sock],[],[],.1)
        if len(inputready):
            break

def wait_write(sock):
    while True:
        inputready, outputready, exceptready = select.select([],[sock],[],.1)
        if len(outputready):
            break

def udp(port):
    address = ('127.0.0.1', port)
    sock = socket.socket(type=socket.SOCK_DGRAM)

    sock.bind(address)

    in_queue = Queue()
    out_queue = Queue() 

    def read():
        while True:
            try:
                wait_read(sock.fileno())
                data, address = sock.recvfrom(port)
                #print(role, 'received %s:%s: got %r' % (address + (data, )))
                in_queue.put((data, address))
            except socket.error as e:
                print('Socket error:', e)
                break

    def write():
        while True:
            try:
                wait_write(sock.fileno())
                (msg, target) = out_queue.get()
                #print(role, 'sending %s' % msg)
                out_bytes = sock.sendto(msg, ('127.0.0.1', target))
            except socket.error as e:
                print('Socket error:', e)
                break

    gevent.spawn(read)
    gevent.spawn(write)

    return (in_queue, out_queue)

def spawn(target, *args):
    t = Thread(target=target, args=args)
    t.daemon = True
    t.start()
    return t

def tcp(role, port):
    address = ('127.0.0.1', port)

    in_queue = Queue()
    out_queue = Queue()

    conns = []

    def connectify():
        sock = socket.socket(type=socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if role == 'server':
            sock.bind(address)
            sock.listen(1)
        else:
            first = True
            while True:
                try:
                    sock.connect(address)
                    break
                except socket.error as e:
                    sock = socket.socket(type=socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    if first:
                        print('Waiting for server on %s...' % (address,))
                        first = False
                    gevent.sleep(1)

        if role == 'client':
            spawn(read, sock)
            spawn(write, sock)
        if role == 'server':
            spawn(read_clients, sock)
            spawn(write_clients, conns)

    def read_clients(sock):
        while True:
            try:
                wait_read(sock.fileno())
                conn, addr = sock.accept()
                conns.append(conn)
                spawn(read, conn)
            except socket.error as e:
                print('Socket error:', e)
                break

    def read(conn):
        while True:
            try:
                wait_read(conn.fileno())
                data = conn.recv(port)
                #print(role, 'received %r' % (data, ))
                if not data:
                    break
                in_queue.put(data)
            except socket.error as e:
                print('Socket error:', e)
                break
        conn.close()
        try:
            conns.remove(conn)
        except:
            pass

    def write(sock):
        while True:
            try:
                wait_write(sock.fileno())
                msg = out_queue.get()
                #print(role, 'sending %s' % msg)
                out_bytes = sock.send(msg)
            except socket.error as e:
                print('Socket error:', e)
                break

    def write_clients(conns):
        while True:
            try:
                # wait_write(sock.fileno())
                msg = out_queue.get()
                #print(role, 'sending %s' % msg)
                for conn in conns:
                    out_bytes = conn.send(msg)
            except socket.error as e:
                print('Socket error:', e)
                break

    spawn(connectify)
    return (in_queue, out_queue)

(inq, outq) = tcp('server', 2266)

from subprocess import Popen
import os
import sys

curpath = os.path.dirname(os.path.realpath(__file__))

p = Popen(['PowerShell.exe', '-ExecutionPolicy', 'Bypass', '-File', 'server.ps1'], cwd=curpath, shell=True)

# now connect
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 2200))
except Exception as e:
    print('*** Bind failed: ' + str(e))
    traceback.print_exc()
    sys.exit(1)

try:
    sock.listen(100)
    print('Listening for connection ...')
    client, addr = sock.accept()
except Exception as e:
    print('*** Listen/accept failed: ' + str(e))
    traceback.print_exc()
    sys.exit(1)

print('Got a connection!')

import stub_sftp

try:
    t = paramiko.Transport(client, gss_kex=DoGSSAPIKeyExchange)
    t.set_gss_host(socket.getfqdn(""))
    try:
        t.load_server_moduli()
    except:
        print('(Failed to load moduli -- gex will be unsupported.)')
        raise
    t.add_server_key(host_key)
    server = Server()
    try:
        t.set_subsystem_handler("sftp", paramiko.SFTPServer, stub_sftp.StubSFTPServer)
        t.start_server(server=server)
    except paramiko.SSHException:
        print('*** SSH negotiation failed.')
        sys.exit(1)

    # wait for auth
    chan = t.accept(20)
    if chan is None:
        print('*** No channel.')
        sys.exit(1)
    print('Authenticated!')

    server.event.wait(10)
    if not server.event.is_set():
        print('*** Client never asked for a shell.')
        sys.exit(1)

    chan.send('\r\n\r\nWelcome to my dorky little BBS!\r\n\r\n')
    chan.send('We are on fire all the time!  Hooray!  Candy corn for everyone!\r\n')
    chan.send('Happy birthday to Robot Dave!\r\n\r\n')

    f = chan.makefile('rU')

    import re

    def outer():
        line = ''
        while True:
            inp = f.read(1)
            chan.send(re.sub(r'\r\n?', '\r\n', inp))
            line += inp
            for l in line.split('\r')[:-1]:
                outq.put(l + '\r\n')
            line = line.split('\r')[-1]

    spawn(outer)

    while True:
        try:
            data = inq.get(timeout=1000)
        except Empty:
            continue
        chan.send(re.sub(r'\r?\n', '\r\n', data))
    # f = chan.makefile('rU')
    # username = f.readline().strip('\r\n')
    # chan.send('\r\nI don\'t like you, ' + username + '.\r\n')
    # chan.close()

except Exception as e:
    print('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)
