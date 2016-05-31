#!/usr/bin/env python
#
# Texecom Alarm Receiving Server - Test Script
# Copyright 2016 Mike Stirling
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

import socket
from argparse import ArgumentParser

parser = ArgumentParser(description='Test tool for SIA and ContactID')
parser.add_argument('test', type=str, nargs=1,
                help='Name of test to execute: poll, arm, disarm, alarm, panic')
parser.add_argument('-H', dest='host', type=str,
                help='ARC host address', default='127.0.0.1')
parser.add_argument('-P', dest='port', type=int,
                help='ARC port number', default=10500)
parser.add_argument('-A', dest='account', type=int,
                help='User account number',  default='1000')
parser.add_argument('-n', dest='number', type=int,
                help='User or zone number', default=0)
parser.add_argument('-N', dest='name', type=str,
                help='User or zone name', default='')
parser.add_argument('-m', dest='mode', type=int,
                help='Operating mode: 2=ContactID, 3=SIA', default=2)
parser.add_argument('-f', dest='flags', type=int,
                help='Poller flags', default=0)

args = parser.parse_args()
print args

def poll(sock, account, flags):
    sock.send("POLL%04u#%c\0\0\0\r\n" % (account, chr(flags)))
    
    reply = sock.recv(1024)
    if reply[0:3] == '[P]' and reply[5:] == '\x06\r\n':
        interval = ord(reply[4])
        print "POLL OK"
        print "Server requested polling interval %u minutes" % (interval)
    else:
        print "Bad reply to poll:", reply.strip()
        
def contactid(sock, account, qualifier, event, zone_or_user):
    account = ("%04u" % (account)).replace('0','A')
    msg = account + "18%01u%03u01%03u" % (qualifier, event, zone_or_user)
    
    # Calculate check digit (0 is valued as 10)
    checksum = 0
    for c in msg:
        if c == '0':
            checksum += 10
        else:
            checksum += int(c, 16)
    checkdigit = "%01X" % (15 - (checksum % 15))
    if checkdigit == 'A':
        checkdigit = '0'
        
    # Wrap in Texecom wrapper
    sock.send('2' + msg + checkdigit + '\r\n')
    
    # Wait for ACK
    reply = sock.recv(1024)
    if reply == '2\x06\r\n':
        print "Ack received OK"
    else:
        print "Bad reply to message:", strip(reply)
         
    
def sia(sock, account, event, zone_or_user, name):
    recs = [
        "#%04u" % (account),
        "Nri1%2s%03u" % (event, zone_or_user),
        ]
    if name:
        recs = recs + [ "A%s" % (name) ]
        
    # Add start byte and checksum for each record
    msg = ''
    for rec in recs:
        rec = chr(0xc0 + len(rec) - 1) + rec
        checksum = 0xff
        for c in rec:
            checksum ^= ord(c)
        msg = msg + rec + chr(checksum)
        
    # Add terminator and wrap in Texecom wrapper for sending
    sock.send('3' + msg + '\x40\x30\x8f' + '\r\n')
    
    # Wait for ACK
    reply = sock.recv(1024)
    if reply == '3\x06\r\n':
        print "Ack received OK"
    else:
        print "Bad reply to message:", reply.strip()


# List of tests along with ContactID and SIA event codes
TESTS = {
    'arm'    : (3, 401, 'CL'),
    'disarm' : (1, 401, 'OP'),
    'alarm'  : (1, 130, 'BA'),
    'panic'  : (1, 123, 'PA'),
    }

if __name__=='__main__':
    # Open socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    sock.settimeout(2.0)
    
    test = args.test[0]
    if test == 'poll':
        poll(sock, args.account, args.flags)
    else:
        try:
            (cid_qual, cid_event, sia_event) = TESTS[test]
            
            if args.mode == 2:
                contactid(sock, args.account, cid_qual, cid_event, args.number)
            elif args.mode == 3:
                sia(sock, args.account, sia_event, args.number, args.name)
            else:
                print "Bad mode:", args.mode
        except KeyError:            
            print "Unknown test:", test
        
    sock.close()
    
    
