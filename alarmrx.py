#!/usr/bin/env python
#
# Texecom Alarm Receiving Server
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

import SocketServer
import ConfigParser
import logging
import sys
import daemon
import lockfile
import json
import paho.mqtt.client as mqtt
import time
from datetime import datetime, timedelta
from threading import Thread, Lock
from binascii import hexlify

APP_NAME = 'alarmserver'
CONFIG_FILE = '/etc/alarmserver/alarmserver.conf'

# Configuration defaults
DEFAULTS = {
	'server' : {
		'host' : '0.0.0.0',
		'port' : 10500,
		'log_file' : '/tmp/alarmserver.log',
		'pid_file' : '/tmp/alarmserver.pid',
	},
	'alarm' : {
		'polling_interval' : 2,
		'max_misses' : 1,
		'account_file' : '/etc/alarmserver/accounts.conf'
	},
	'mqtt' : {
		'host' : '127.0.0.1',
		'port' : 1883,
		'username' : None,
		'password' : None,
		'cafile' : None
	},
}

config = ConfigParser.ConfigParser()
config.read(CONFIG_FILE)

def get_config(section, option):
	try:
		value = config.get(section, option)
	except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
		value = DEFAULTS[section][option]
	return value

LOG_FILE = get_config('server', 'log_file')
PID_FILE = get_config('server', 'pid_file')

# Configure logging
LOG_FORMAT = '%(asctime)-15s %(levelname)-6s %(tag)-15s %(message)s'
logging.basicConfig(level=logging.DEBUG, format = LOG_FORMAT)
logger = logging.getLogger(APP_NAME)

fh = logging.FileHandler(LOG_FILE, 'a')
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(fh)

class AccountManager(object):
	error = lambda self, acc, msg: logger.error(msg, extra={'tag': acc})
	info = lambda self, acc, msg: logger.info(msg, extra={'tag': acc})
	debug = lambda self, acc, msg: logger.debug(msg, extra={'tag': acc})

	# Polling timer tolerance (seconds)
	POLLING_TOLERANCE = 30

	def __init__(self):
		self.MAX_MISSES = int(get_config('alarm', 'max_misses'))
		self.ACCOUNT_FILENAME = get_config('alarm', 'account_file')
		self.POLLING_INTERVAL = int(get_config('alarm', 'polling_interval'))

		self.account_lock = Lock()
		self.watchdog_running = False
		self.polling_timeout = timedelta(minutes=self.POLLING_INTERVAL, seconds=self.POLLING_TOLERANCE)

		# Open and load list of accounts
		# File should be formatted as <account number> <expected IP address>
		self.accounts = {}
		try:
			with open(self.ACCOUNT_FILENAME) as f:
				while True:
					entry = f.readline().strip()
					if not entry:
						break
					if entry[0] == '#':
						continue
					fields = entry.split()
					if len(fields) < 2:
						# Skip if row has less than 2 columns
						continue
					(account, ip) = fields[:2]
					self.accounts[account] = dict(ip=ip, last_poll=None, timeout=None, missed=0)
		except IOError:
			# Missing account file just means no accounts
			self.error('', 'Failed to open account file')

	def publish_polling_event(self, account, state):
		# Post event message to broker (not retained)
		info = {
			'client_ip': '',
			'client_port': 0,
			'account': int(account),
			'timestamp': datetime.now().isoformat(),
			'area': 0,
			'value': 0,
			'value_type': '',
			'extra_text': '',
			}
		if state:
			info['event'] = 'Polling restored'
			msg = 'Polling restored'
		else:
			info['event'] = 'Polling timeout'
			msg = 'Polling timeout'
		self.mqtt_client.publish("/alarms/%s/event" % (account), json.dumps(info), qos=1, retain=False)
		self.mqtt_client.publish("/alarms/%s/message" % (account), msg, qos=1, retain=False)

	def start_polling_watchdog(self):
		# Initialise polling timeouts
		for k,acc in self.accounts.iteritems():
			acc['timeout'] = datetime.now() + self.polling_timeout

		# Start timer for polling monitor
		self.watchdog_running = True
		self.watchdog_thread = Thread(target = self.watchdog_func)
		self.watchdog_thread.daemon = True
		self.watchdog_thread.start()

	def stop_polling_watchdog(self):
		self.watchdog_running = False
		self.watchdog_thread.join()

	def watchdog_func(self):
		while self.watchdog_running:
			self.account_lock.acquire()

			# Check for missed polls every few seconds.  Doesn't really
			# matter if we are a few seconds late
			now = datetime.now()
			for k,acc in self.accounts.iteritems():
				if acc['timeout'] < now:
					# Account has missed a poll event
					acc['missed'] = acc['missed'] + 1
					acc['timeout'] = now + self.polling_timeout
					self.info(k, "Polling deadline missed (%d/%d)" % (acc['missed'], self.MAX_MISSES))
					if acc['missed'] == self.MAX_MISSES:
						# Generate polling error event
						self.error(k, "Polling alert")
						self.publish_polling_event(k, False)

			self.account_lock.release()
			time.sleep(5)

	def polled(self, account):
		self.account_lock.acquire()

		try:
			self.info(account, 'Poll received')
			acc = self.accounts[account]
			if acc['missed'] > 0:
				# Generate polling restored event
				self.info(account, "Polling recovered after %d misses" % (acc['missed']))
				self.publish_polling_event(account, True)

			now = datetime.now()
			acc['last_poll'] = now
			acc['timeout'] = now + self.polling_timeout
			acc['missed'] = 0
		except KeyError:
			self.error(account, 'Unknown account')

		self.account_lock.release()

	def get_ip(self, account):
		try:
			return self.accounts[account]['ip']
		except KeyError:
			self.error(account, 'Unknown account')
			return None

	def get_polling_interval(self, account):
		return self.POLLING_INTERVAL


class EventParser(object):
	error = lambda self, msg: logger.error(type(self).__name__ + ': ' + msg, extra={'tag': self.client_ip})
	info = lambda self, msg: logger.info(type(self).__name__ + ': ' + msg, extra={'tag': self.client_ip})
	debug = lambda self, msg: logger.debug(type(self).__name__ + ': ' + msg, extra={'tag': self.client_ip})

	# Defaults
	client_ip = '0.0.0.0'
	account_number = ''
	area = 0
	event = ''
	description = ''
	value = 0
	value_name = ''
	extra_text = ''
	
	def __init__(self):
		pass

class ContactId(EventParser):	
	QUALIFIERS = {
		1 : 'Event/Activated',
		3 : 'Restore/Secured',
		6 : 'Status'
		}
	EVENTS = {
		100: 'Medical',
		110: 'Fire',
		120: 'Panic',
		121: 'Duress',
		122: 'Silent Attack',
		123: 'Audible Attack',
		130: 'Intruder',
		131: 'Perimeter',
		132: 'Interior',
		133: '24 Hour',
		134: 'Entry/Exit',
		135: 'Day/Night',
		136: 'Outdoor',
		137: 'Zone Tamper',
		139: 'Confirmed Alarm',
		145: 'System Tamper',

		300: 'System Trouble',
		301: 'AC Lost',
		302: 'Low Battery',
		305: 'System Power Up',
		320: 'Mains Over-voltage',
		333: 'Network Failure',
		351: 'ATS Path Fault',
		354: 'Failed to Communicate',

		400: 'Arm/Disarm',
		401: 'Arm/Disarm by User',
		403: 'Automatic Arm/Disarm',
		406: 'Alarm Abort',
		407: 'Remote Arm/Disarm',
		408: 'Quick Arm',

		411: 'Download Start',
		412: 'Download End',
		441: 'Part Arm',

		457: 'Exit Error',
		459: 'Recent Closing',
		570: 'Zone Locked Out',

		601: 'Manual Test',
		602: 'Periodic Test',
		607: 'User Walk Test',

		623: 'Log Capacity Alert',
		625: 'Date/Time Changed',
		627: 'Program Mode Entry',
		628: 'Program Mode Exit',
		}
	
	def __init__(self, client_ip, msg):
		self.client_ip = client_ip
		
		# Validate
		if len(msg) != 16:
			self.error("Invalid message size %u" % (len(msg)))
			return
		if msg[4:6] != '18' and msg[4:6] != '98':
			self.error("Invalid message type %s" % (msg[4:6]))
			return

		# Parse fields
		account = msg[0:4].replace('A','0')
		try:
			qualifier = int(msg[6:7])
			event = int(msg[7:10])
			group = int(msg[10:12])
			value = int(msg[12:15])
		except ValueError:
			self.error("Parse error")
			return
		
		try:
			qualstr = ' ' + self.QUALIFIERS[qualifier]
		except KeyError:
			qualstr = ''
		try:
			eventstr = self.EVENTS[event]
		except KeyError:
			eventstr = "Unknown Event %03u" % (event)

		# Populate class properties
		self.account_number = account
		self.area = group
		self.event = eventstr + qualstr
		self.description = eventstr + qualstr
		self.value = value
		self.value_name = 'Zone/User'
	
class SIA(EventParser):	
	EVENTS = {
		'AA': ("Alarm - Panel Substitution", "An attempt to substitute an alternate alarm panel for a secure panel has been made", "Condition Number"),
		'AB': ("Abort", "An event message was not sent due to User action", "Zone"),
		'AN': ("Analog Restoral", "An analog fire sensor has been restored to normal operation", "Zone"),
		'AR': ("AC Restoral", "AC power has been restored", ""),
		'AS': ("Analog Service", "An analog fire sensor needs to be cleaned or calibrated", "Zone"),
		'AT': ("AC Trouble", "AC power has been failed", ""),
		'BA': ("Burglary Alarm", "Burglary zone has been violated while armed", "Zone"),
		'BB': ("Burglary Bypass", "Burglary zone has been bypassed", "Zone"),
		'BC': ("Burglary Cancel", "Alarm has been cancelled by authorized user", "User"),
		'BD': ("Swinger Trouble", "A non-fire zone has been violated after a Swinger Shutdown on the zone", "Zone"),
		'BE': ("Swinger Trouble Restore", "A non-fire zone restores to normal from a Swinger Trouble state", "Zone"),
		'BG': ("Unverified Event - Burglary", "A point assigned to a Cross Point group has gone into alarm but the Cross Point remained normal", "Zone"),
		'BH': ("Burglary Alarm Restore", "Alarm condition eliminated", "Zone"),
		'BJ': ("Burglary Trouble Restore", "Trouble condition eliminated", "Zone"),
		'BM': ("Burglary Alarm -  Cross Point", "Burglary alarm w/cross point also in alarm - alarm verified", "Zone"),
		'BR': ("Burglary Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'BS': ("Burglary Supervisory", "Unsafe intrusion detection system condition", "Zone"),
		'BT': ("Burglary Trouble", "Burglary zone disabled by fault", "Zone"),
		'BU': ("Burglary Unbypass", "Zone bypass has been removed", "Zone"),
		'BV': ("Burglary Verified", "A burglary alarm has occurred and been verified within programmed conditions. (zone or point not sent)", "Area"),
		'BX': ("Burglary Test", "Burglary zone activated during testing", "Zone"),
		'BZ': ("Missing Supervision", "A non-fire Supervisory point has gone missing", "Zone"),
		'CA': ("Automatic Closing", "System armed automatically", "Area"),
		'CD': ("Closing Delinquent", "The system has not been armed for a programmed amount of time", "Area"),
		'CE': ("Closing Extend", "Extend closing time", "User"),
		'CF': ("Forced Closing", "System armed, some zones not ready", "User"),
		'CG': ("Close Area", "System has been partially armed", "Area"),
		'CI': ("Fail to Close", "An area has not been armed at the end of the closing window", "Area"),
		'CJ': ("Late Close", "An area was armed after the closing window", "User"),
		'CK': ("Early Close", "An area was armed before the closing window", "User"),
		'CL': ("Closing Report", "System armed, normal", "User"),
		'CM': ("Missing Alarm - Recent Closing", "A point has gone missing within 2 minutes of closing", "Zone"),
		'CO': ("Command Sent", "A command has been sent to an expansion/peripheral device", "Condition Number"),
		'CP': ("Automatic Closing", "System armed automatically", "User"),
		'CQ': ("Remote Closing", "The system was armed from a remote location", "User"),
		'CR': ("Recent Closing", "An alarm occurred within five minutes after the system was closed", "User"),
		'CS': ("Closing Keyswitch", "Account has been armed by keyswitch", "Zone"),
		'CT': ("Late to Open", "System was not disarmed on time", "Area"),
		'CW': ("Was Force Armed", "Header for a force armed session, forced point msgs may follow", "Area"),
		'CX': ("Custom Function Executed", "The panel has executed a preprogrammed set of instructions", "Custom Function"),
		'CZ': ("Point Closing", "A point, as opposed to a whole area or account, has closed", "Zone"),
		'DA': ("Card Assigned", "An access ID has been added to the controller", "User"),
		'DB': ("Card Deleted", "An access ID has been deleted from the controller", "User"),
		'DC': ("Access Closed", "Access to all users prohibited", "Door"),
		'DD': ("Access Denied", "Access denied, unknown code", "Door"),
		'DE': ("Request to Enter", "An access point was opened via a Request to Enter device", "Door"),
		'DF': ("Door Forced", "Door opened without access request", "Door"),
		'DG': ("Access Granted", "Door access granted", "Door"),
		'DH': ("Door Left Open - Restoral", "An access point in a Door Left Open state has restored", "Door"),
		'DI': ("Access Denied - Passback", "Access denied because credential has not exited area before attempting to re-enter same area", "Door"),
		'DJ': ("Door Forced - Trouble", "An access point has been forced open in an unarmed area", "Door"),
		'DK': ("Access Lockout", "Access denied, known code", "Door"),
		'DL': ("Door Left Open - Alarm", "An open access point when open time expired in an armed area", "Door"),
		'DM': ("Door Left Open - Trouble", "An open access point when open time expired in an unarmed area", "Door"),
		'DN': ("Door Left Open (non-alarm, non-trouble)", "An access point was open when the door cycle time expired", "Door"),
		'DO': ("Access Open", "Access to authorized users allowed", "Door"),
		'DP': ("Access Denied - Unauthorized Time", "An access request was denied because the request is occurring outside the user's authorized time window(s)", "Door"),
		'DQ': ("Access Denied Unauthorized Arming State", "An access request was denied because the user was not authorized in this area when the area was armed", "Door"),
		'DR': ("Door Restoral", "Access alarm/trouble condition eliminated", "Door"),
		'DS': ("Door Station", "Identifies door for next report", "Door"),
		'DT': ("Access Trouble", "Access system trouble", ""),
		'DU': ("Dealer ID", "Dealer ID number", "Dealer ID"),
		'DV': ("Access Denied Unauthorized Entry Level", "An access request was denied because the user is not authorized in this area", "Door"),
		'DW': ("Access Denied - Interlock", "An access request was denied because the doors associated Interlock point is open", "Door"),
		'DX': ("Request to Exit", "An access point was opened via a Request to Exit device", "Door"),
		'DY': ("Door Locked", "The door's lock has been engaged", "Door"),
		'DZ': ("Access Denied - Door Secured", "An access request was denied because the door has been placed in an Access Closed state", "Door"),
		'EA': ("Exit Alarm", "An exit zone remained violated at the end of the exit delay period", "Zone"),
		'EE': ("Exit Error", "An exit zone remained violated at the end of the exit delay period", "User"),
		'EJ': ("Expansion Tamper Restore", "Expansion device tamper restoral", "Device"),
		'EM': ("Expansion Device Missing", "Expansion device missing", "Device"),
		'EN': ("Expansion Missing Restore", "Expansion device communications re-established", "Device"),
		'ER': ("Expansion Restoral", "Expansion device trouble eliminated", "Expander"),
		'ES': ("Expansion Device Tamper", "Expansion device enclosure tamper", "Device"),
		'ET': ("Expansion Trouble", "Expansion device trouble", "Expander"),
		'EX': ("External Device Condition", "A specific reportable condition is detected on an external device", "Device"),
		'EZ': ("Missing Alarm - Exit Error", "A point remained missing at the end of the exit delay period", "Zone"),
		'FA': ("Fire Alarm", "Fire condition detected", "Zone"),
		'FB': ("Fire Bypass", "Zone has been bypassed", "Zone"),
		'FC': ("Fire Cancel", "A Fire Alarm has been cancelled by an authorized person", "Zone"),
		'FG': ("Unverified Event - Fire", "A point assigned to a Cross Point group has gone into alarm but the Cross Point remained normal", "Zone"),
		'FH': ("Fire Alarm Restore", "Alarm condition eliminated", "Zone"),
		'FI': ("Fire Test Begin", "The transmitter area's fire test has begun", "Area"),
		'FJ': ("Fire Trouble Restore", "Trouble condition eliminated", "Zone"),
		'FK': ("Fire Test End", "The transmitter area's fire test has ended", "Area"),
		'FL': ("Fire Alarm Silenced", "The fire panel's sounder was silenced by command", "Zone"),
		'FM': ("Fire Alarm - Cross Point", "Fire Alarm with Cross Point also in alarm verifying the Fire Alarm", "Zone"),
		'FQ': ("Fire Supervisory Trouble Restore", "A fire supervisory zone that was in trouble condition has now restored to normal", "Zone"),
		'FR': ("Fire Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'FS': ("Fire Supervisory", "Unsafe fire detection system condition", "Zone"),
		'FT': ("Fire Trouble", "Zone disabled by fault", "Zone"),
		'FU': ("Fire Unbypass", "Bypass has been removed", "Zone"),
		'FV': ("Fire Supervision Restore", "A fire supervision zone that was in alarm has restored to normal", "Zone"),
		'FW': ("Fire Supervisory Trouble", "A fire supervisory zone is now in a trouble condition", "Zone"),
		'FX': ("Fire Test", "Fire zone activated during test", "Zone"),
		'FY': ("Missing Fire Trouble", "A fire point is now logically missing", "Zone"),
		'FZ': ("Missing Fire Supervision", "A Fire Supervisory point has gone missing", "Zone"),
		'GA': ("Gas Alarm", "Gas alarm condition detected", "Zone"),
		'GB': ("Gas Bypass", "Zone has been bypassed", "Zone"),
		'GH': ("Gas Alarm Restore", "Alarm condition eliminated", "Zone"),
		'GJ': ("Gas Trouble Restore", "Trouble condition eliminated", "Zone"),
		'GR': ("Gas Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'GS': ("Gas Supervisory", "Unsafe gas detection system condition", "Zone"),
		'GT': ("Gas Trouble", "Zone disabled by fault", "Zone"),
		'GU': ("Gas Unbypass", "Bypass has been removed", "Zone"),
		'GX': ("Gas Test", "Zone activated during test", "Zone"),
		'HA': ("Holdup Alarm", "Silent alarm, user under duress", "Zone"),
		'HB': ("Holdup Bypass", "Zone has been bypassed", "Zone"),
		'HH': ("Holdup Alarm Restore", "Alarm condition eliminated", "Zone"),
		'HJ': ("Holdup Trouble Restore", "Trouble condition eliminated", "Zone"),
		'HR': ("Holdup Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'HS': ("Holdup Supervisory", "Unsafe holdup system condition", "Zone"),
		'HT': ("Holdup Trouble", "Zone disabled by fault", "Zone"),
		'HU': ("Holdup Unbypass", "Bypass has been removed", "Zone"),
		'IA': ("Equipment Failure Condition", "A specific, reportable condition is detected on a device", "Zone"),
		'IR': ("Equipment Fail - Restoral", "The equipment condition has been restored to normal", "Zone"),
		'JA': ("User Code Tamper", "Too many unsuccessful attempts have been made to enter a user ID", "Area"),
		'JD': ("Date Changed", "The date was changed in the transmitter/receiver", "User"),
		'JH': ("Holiday Changed", "The transmitter's holiday schedule has been changed", "User"),
		'JK': ("Latchkey Alert", "A designated user passcode has not been entered during a scheduled time window", "User"),
		'JL': ("Log Threshold", "The transmitter's log memory has reached its threshold level", ""),
		'JO': ("Log Overflow", "The transmitter's log memory has overflowed", ""),
		'JP': ("User On Premises", "A designated user passcode has been used to gain access to the premises.", "User"),
		'JR': ("Schedule Executed", "An automatic scheduled event was executed", "Area"),
		'JS': ("Schedule Changed", "An automatic schedule was changed", "User"),
		'JT': ("Time Changed", "The time was changed in the transmitter/receiver", "User"),
		'JV': ("User Code Changed", "A user's code has been changed", "User"),
		'JX': ("User Code Deleted", "A user's code has been removed", "User"),
		'JY': ("User Code Added", "A user's code has been added", "User"),
		'JZ': ("User Level Set", "A user's authority level has been set", "User"),
		'KA': ("Heat Alarm", "High temperature detected on premise", "Zone"),
		'KB': ("Heat Bypass", "Zone has been bypassed", "Zone"),
		'KH': ("Heat Alarm Restore", "Alarm condition eliminated", "Zone"),
		'KJ': ("Heat Trouble Restore", "Trouble condition eliminated", "Zone"),
		'KR': ("Heat Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'KS': ("Heat Supervisory", "Unsafe heat detection system condition", "Zone"),
		'KT': ("Heat Trouble", "Zone disabled by fault", "Zone"),
		'KU': ("Heat Unbypass", "Bypass has been removed", "Zone"),
		'LB': ("Local Program", "Begin local programming", ""),
		'LD': ("Local Program Denied", "Access code incorrect", ""),
		'LE': ("Listen-in Ended", "The listen-in session has been terminated", ""),
		'LF': ("Listen-in Begin", "The listen-in session with the RECEIVER has begun", ""),
		'LR': ("Phone Line Restoral", "Phone line restored to service", "Line"),
		'LS': ("Local Program Success", "Local programming successful", ""),
		'LT': ("Phone Line Trouble", "Phone line trouble report", "Line"),
		'LU': ("Local Program Fail", "Local programming unsuccessful", ""),
		'LX': ("Local Programming Ended", "A local programming session has been terminated", ""),
		'MA': ("Medical Alarm", "Emergency assistance request", "Zone"),
		'MB': ("Medical Bypass", "Zone has been bypassed", "Zone"),
		'MH': ("Medical Alarm Restore", "Alarm condition eliminated", "Zone"),
		'MI': ("Message", "A canned message is being sent", "Message"),
		'MJ': ("Medical Trouble Restore", "Trouble condition eliminated", "Zone"),
		'MR': ("Medical Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'MS': ("Medical Supervisory", "Unsafe system condition exists", "Zone"),
		'MT': ("Medical Trouble", "Zone disabled by fault", "Zone"),
		'MU': ("Medical Unbypass", "Bypass has been removed", "Zone"),
		'NA': ("No Activity", "There has been no zone activity for a programmed amount of time", "Zone"),
		'NC': ("Network Condition", "A communications network has a specific reportable condition", "Network"),
		'NF': ("Forced Perimeter Arm", "Some zones/points not ready", "Area"),
		'NL': ("Perimeter Armed", "An area has been perimeter armed", "Area"),
		'NM': ("Perimeter Armed, User Defined", "A user defined area has been perimeter armed", "Area"),
		'NR': ("Network Restoral", "A communications network has returned to normal operation", "Network"),
		'NS': ("Activity Resumed", "A zone has detected activity after an alert", "Zone"),
		'NT': ("Network Failure", "A communications network has failed", "Network"),
		'OA': ("Automatic Opening", "System has disarmed automatically", "Area"),
		'OC': ("Cancel Report", "Untyped zone cancel", "User"),
		'OG': ("Open Area", "System has been partially disarmed", "Area"),
		'OH': ("Early to Open from Alarm", "An area in alarm was disarmed before the opening window", "User"),
		'OI': ("Fail to Open", "An area has not been armed at the end of the opening window", "Area"),
		'OJ': ("Late Open", "An area was disarmed after the opening window", "User"),
		'OK': ("Early Open", "An area was disarmed before the opening window", "User"),
		'OL': ("Late to Open from Alarm", "An area in alarm was disarmed after the opening window", "User"),
		'OP': ("Opening Report", "Account was disarmed", "User"),
		'OQ': ("Remote Opening", "The system was disarmed from a remote location", "User"),
		'OR': ("Disarm From Alarm", "Account in alarm was reset/disarmed", "User"),
		'OS': ("Opening Keyswitch", "Account has been disarmed by keyswitch", "Zone"),
		'OT': ("Late To Close", "System was not armed on time", "User"),
		'OU': ("Output State - Trouble", "An output on a peripheral device or NAC is not functioning", "Output"),
		'OV': ("Output State - Restore", "An output on a peripheral device or NAC is back to normal operation", "Output"),
		'OZ': ("Point Opening", "A point, rather than a full area or account, disarmed", "Zone"),
		'PA': ("Panic Alarm", "Emergency assistance request, manually activated", "Zone"),
		'PB': ("Panic Bypass", "Panic zone has been bypassed", "Zone"),
		'PH': ("Panic Alarm Restore", "Alarm condition eliminated", "Zone"),
		'PJ': ("Panic Trouble Restore", "Trouble condition eliminated", "Zone"),
		'PR': ("Panic Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'PS': ("Panic Supervisory", "Unsafe system condition exists", "Zone"),
		'PT': ("Panic Trouble", "Zone disabled by fault", "Zone"),
		'PU': ("Panic Unbypass", "Panic zone bypass has been removed", "Zone"),
		'QA': ("Emergency Alarm", "Emergency assistance request", "Zone"),
		'QB': ("Emergency Bypass", "Zone has been bypassed", "Zone"),
		'QH': ("Emergency Alarm Restore", "Alarm condition has been eliminated", "Zone"),
		'QJ': ("Emergency Trouble Restore", "Trouble condition has been eliminated", "Zone"),
		'QR': ("Emergency Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'QS': ("Emergency Supervisory", "Unsafe system condition exists", "Zone"),
		'QT': ("Emergency Trouble", "Zone disabled by fault", "Zone"),
		'QU': ("Emergency Unbypass", "Bypass has been removed", "Zone"),
		'RA': ("Remote Programmer  Call Failed", "Transmitter failed to communicate with the remote programmer", ""),
		'RB': ("Remote Program Begin", "Remote programming session initiated", ""),
		'RC': ("Relay Close", "A relay has energized", "Relay"),
		'RD': ("Remote Program Denied", "Access passcode incorrect", ""),
		'RN': ("Remote Reset", "A TRANSMITTER was reset via a remote programmer", ""),
		'RO': ("Relay Open", "A relay has de-energized", "Relay"),
		'RP': ("Automatic Test", "Automatic communication test report", ""),
		'RR': ("Power Up", "System lost power, is now restored", ""),
		'RS': ("Remote Program Success", "Remote programming successful", ""),
		'RT': ("Data Lost", "Dialer data lost, transmission error", "Line"),
		'RU': ("Remote Program Fail", "Remote programming unsuccessful", ""),
		'RX': ("Manual Test", "Manual communication test report", "User"),
		'RY': ("Test Off Normal", "Test signal(s) indicates abnormal condition(s) exist", "Zone"),
		'SA': ("Sprinkler Alarm", "Sprinkler flow condition exists", "Zone"),
		'SB': ("Sprinkler Bypass", "Sprinkler zone has been bypassed", "Zone"),
		'SC': ("Change of State", "An expansion/peripheral device is reporting a new condition or state change", "Condition Number"),
		'SH': ("Sprinkler Alarm Restore", "Alarm condition eliminated", "Zone"),
		'SJ': ("Sprinkler Trouble Restore", "Trouble condition eliminated", "Zone"),
		'SR': ("Sprinkler Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'SS': ("Sprinkler Supervisory", "Unsafe sprinkler system condition", "Zone"),
		'ST': ("Sprinkler Trouble", "Zone disabled by fault", "Zone"),
		'SU': ("Sprinkler Unbypass", "Sprinkler zone bypass has been removed", "Zone"),
		'TA': ("Tamper Alarm", "Alarm equipment enclosure opened", "Zone"),
		'TB': ("Tamper Bypass", "Tamper detection has been bypassed", "Zone"),
		'TC': ("All Points Tested", "All point tested", ""),
		'TE': ("Test End", "Communicator restored to operation", ""),
		'TH': ("Tamper Alarm Restore", "An Expansion Device's tamper switch restores to normal from an Alarm state", ""),
		'TJ': ("Tamper Trouble Restore", "An Expansion Device's tamper switch restores to normal from a Trouble state", ""),
		'TP': ("Walk Test Point", "This point was tested during a Walk Test", "Zone"),
		'TR': ("Tamper Restoral", "Alarm equipment enclosure has been closed", "Zone"),
		'TS': ("Test Start", "Communicator taken out of operation", ""),
		'TT': ("Tamper Trouble", "Equipment enclosure opened in disarmed state", "Zone"),
		'TU': ("Tamper Unbypass", "Tamper detection bypass has been removed", "Zone"),
		'TW': ("Area Watch Start", "Area watch feature has been activated", ""),
		'TX': ("Test Report", "An unspecified (manual or automatic) communicator test", ""),
		'TZ': ("Area Watch End", "Area watch feature has been deactivated", ""),
		'UA': ("Untyped Zone Alarm", "Alarm condition from zone of unknown type", "Zone"),
		'UB': ("Untyped Zone Bypass", "Zone of unknown type has been bypassed", "Zone"),
		'UG': ("Unverified Event - Untyped", "A point assigned to a Cross Point group has gone into alarm but the Cross Point remained normal", "Zone"),
		'UH': ("Untyped Alarm Restore", "Alarm condition eliminated", "Zone"),
		'UJ': ("Untyped Trouble Restore", "Trouble condition eliminated", "Zone"),
		'UR': ("Untyped Zone Restoral", "Alarm/trouble condition eliminated from zone of unknown type", "Zone"),
		'US': ("Untyped Zone Supervisory", "Unsafe condition from zone of unknown type", "Zone"),
		'UT': ("Untyped Zone Trouble", "Trouble condition from zone of unknown type", "Zone"),
		'UU': ("Untyped Zone Unbypass", "Bypass on zone of unknown type has been removed", "Zone"),
		'UX': ("Undefined", "An undefined alarm condition has occurred", ""),
		'UY': ("Untyped Missing Trouble", "A point or device which was not armed is now logically missing", "Zone"),
		'UZ': ("Untyped Missing Alarm", "A point or device which was armed is now logically missing", "Zone"),
		'VI': ("Printer Paper In", "TRANSMITTER or RECEIVER paper in", "Printer"),
		'VO': ("Printer Paper Out", "TRANSMITTER or RECEIVER paper out", "Printer"),
		'VR': ("Printer Restore", "TRANSMITTER or RECEIVER trouble restored", "Printer"),
		'VT': ("Printer Trouble", "TRANSMITTER or RECEIVER trouble", "Printer"),
		'VX': ("Printer Test", "TRANSMITTER or RECEIVER test", "Printer"),
		'VY': ("Printer Online", "RECEIVER'S printer is now online", ""),
		'VZ': ("Printer Offline", "RECEIVER'S printer is now offline", ""),
		'WA': ("Water Alarm", "Water detected at protected premises", "Zone"),
		'WB': ("Water Bypass", "Water detection has been bypassed", "Zone"),
		'WH': ("Water Alarm Restore", "Water alarm condition eliminated", "Zone"),
		'WJ': ("Water Trouble Restore", "Water trouble condition eliminated", "Zone"),
		'WR': ("Water Restoral", "Water alarm/trouble condition has been eliminated", "Zone"),
		'WS': ("Water Supervisory", "Water unsafe water detection system condition", "Zone"),
		'WT': ("Water Trouble", "Water zone disabled by fault", "Zone"),
		'WU': ("Water Unbypass", "Water detection bypass has been removed", "Zone"),
		'XA': ("Extra Account Report", "CS RECEIVER has received an event from a non-existent account", ""),
		'XE': ("Extra Point", "Panel has sensed an extra point not specified for this site", "Zone"),
		'XF': ("Extra RF Point", "Panel has sensed an extra RF point not specified for this site", "Zone"),
		'XH': ("RF Interference Restoral", "A radio device is no longer detecting RF Interference", "Receiver"),
		'XI': ("Sensor Reset", "A user has reset a sensor", "Zone"),
		'XJ': ("RF Receiver Tamper Restoral", "A Tamper condition at a premises RF Receiver has been restored", "Receiver"),
		'XL': ("Low Received Signal Strength", "The RF signal strength of a reported event is below minimum level", "Receiver"),
		'XM': ("Missing Alarm - Cross Point", "Missing Alarm verified by Cross Point in Alarm (or missing)", "Zone"),
		'XQ': ("RF Interference", "A radio device is detecting RF Interference", "Receiver"),
		'XR': ("Transmitter Battery Restoral", "Low battery has been corrected", "Zone"),
		'XS': ("RF Receiver Tamper", "A Tamper condition at a premises receiver is detected", "Receiver"),
		'XT': ("Transmitter Battery Trouble", "Low battery in wireless transmitter", "Zone"),
		'XW': ("Forced Point", "A point was forced out of the system at arm time", "Zone"),
		'XX': ("Fail to Test", "A specific test from a panel was not received", ""),
		'YA': ("Bell Fault", "A trouble condition has been detected on a Local Bell, Siren, or Annunciator", ""),
		'YB': ("Busy Seconds", "Percent of time receiver's line card is on-line", "Line Card"),
		'YC': ("Communications Fail", "RECEIVER and TRANSMITTER", ""),
		'YD': ("Receiver Line Card Trouble", "A line card identified by the passed address is in trouble", "Line Card"),
		'YE': ("Receiver Line Card Restored", "A line card identified by the passed address is restored", "Line Card"),
		'YF': ("Parameter Checksum Fail", "System data corrupted", ""),
		'YG': ("Parameter Changed", "A TRANSMITTER'S parameters have been changed", ""),
		'YH': ("Bell Restored", "A trouble condition has been restored on a Local Bell, Siren, or Annunciator", ""),
		'YI': ("Overcurrent Trouble", "An Expansion Device has detected an overcurrent condition", ""),
		'YJ': ("Overcurrent Restore", "An Expansion Device has restored from an overcurrent condition", ""),
		'YK': ("Communications Restoral", "TRANSMITTER has resumed communication with a RECEIVER", ""),
		'YM': ("System Battery Missing", "TRANSMITTER/RECEIVER battery is missing", ""),
		'YN': ("Invalid Report", "TRANSMITTER has sent a packet with invalid data", ""),
		'YO': ("Unknown Message", "An unknown message was received from automation or the printer", ""),
		'YP': ("Power Supply Trouble", "TRANSMITTER/RECEIVER has a problem with the power supply", ""),
		'YQ': ("Power Supply Restored", "TRANSMITTER'S/RECEIVER'S power supply has been restored", ""),
		'YR': ("System Battery Restoral", "Low battery has been corrected", ""),
		'YS': ("Communications Trouble", "RECEIVER and TRANSMITTER", ""),
		'YT': ("System Battery Trouble", "Low battery in control/communicator", ""),
		'YU': ("Diagnostic Error", "An expansion/peripheral device is reporting a diagnostic error", "Condition Number"),
		'YW': ("Watchdog Reset", "The TRANSMITTER created an internal reset", ""),
		'YX': ("Service Required", "A TRANSMITTER/RECEIVER needs service", ""),
		'YY': ("Status Report", "This is a header for an account status report transmission", ""),
		'YZ': ("Service Completed", "Required TRANSMITTER / RECEIVER service completed", ""),
		'ZA': ("Freeze Alarm", "Low temperature detected at premises", "Zone"),
		'ZB': ("Freeze Bypass", "Low temperature detection has been bypassed", "Zone"),
		'ZH': ("Freeze Alarm Restore", "Alarm condition eliminated", "Zone"),
		'ZJ': ("Freeze Trouble Restore", "Trouble condition eliminated", "Zone"),
		'ZR': ("Freeze Restoral", "Alarm/trouble condition has been eliminated", "Zone"),
		'ZS': ("Freeze Supervisory", "Unsafe freeze detection system condition", "Zone"),
		'ZT': ("Freeze Trouble", "Zone disabled by fault", "Zone"),
		'ZU': ("Freeze Unbypass", "Low temperature detection bypass removed", "Zone"),
	}
	
	def parse_record(self, data):
		try:
			rectype = ord(data[0]) & 0xc0
			payloadlength = ord(data[0]) & 0x3f
			payloadtype = data[1]
			payload = data[2:2 + payloadlength]
			nextrec = data[3 + payloadlength:]
		except IndexError:
			self.error('Record parse error')
			return ('', '', '')
		
		# Verify check byte
		check = 0xff
		for a in data[:3 + payloadlength]:
			check ^= ord(a)
		if check != 0:
			self.error('Check byte error')
			return ('', '', '')
		
		if rectype == 0xc0:
			return (payloadtype, payload, nextrec)
		else:
			return ('', '', nextrec)
	
	def __init__(self, client_ip, message):
		self.client_ip = client_ip
		
		while message:
			(t, payload, message) = self.parse_record(message)
			
			self.debug(t + ' ' + payload)
			
			if t == '#':
				self.account_number = payload
			elif t == 'A':
				self.extra_text = payload
			elif t == 'N':
				try:
					area = int(payload[2])
					event_code = payload[3:5]
					value = int(payload[5:8])
				except:
					self.error("Payload parse error")
					continue
				
				# Populate class properties
				self.area = area
				self.value = value
				try:
					(self.event, self.description, self.value_name) = self.EVENTS[event_code]
				except KeyError:
					self.error("Unknown event code " + event_code)

class TexecomService(SocketServer.BaseRequestHandler):
	error = lambda self, msg: logger.error(msg, extra={'tag': self.client_address[0]})
	info = lambda self, msg: logger.info(msg, extra={'tag': self.client_address[0]})
	debug = lambda self, msg: logger.debug(msg, extra={'tag': self.client_address[0]})

	# POLL flags (not all of these are verified - see docs)
	FLAG_LINE_FAILURE = 1
	FLAG_AC_FAILURE = 2
	FLAG_BATTERY_FAILURE = 4
	FLAG_ARMED = 8
	FLAG_ENGINEER = 16

	def handle_poll(self, data):
		self.debug(data)

		try:
			parts = data[4:].strip().split('#')
			account = parts[0]
			flags = ord(parts[1][0])
		except:
			self.error("POLL parse error")
			return

		self.info("Poll for a/c %s flags 0x%02x" % (account, flags))

		# Check we recognise the account number and that
		# the client IP matches
		if self.server.account_manager.get_ip(account) != self.client_address[0]:
			self.error("Invalid IP address for account %s" % (account))
			return

		# Send ack/polling delay in minutes
		interval = self.server.account_manager.get_polling_interval(account)
		self.request.send('[P]\x00' + chr(interval) + '\x06\r\n')

		# Record poll event
		self.server.account_manager.polled(account)
		
		# Post retained status update to broker
		info = {
			'client_ip': self.client_address[0],
			'client_port': self.client_address[1],
			'account': int(account),
			'timestamp': datetime.now().isoformat(),
			'interval': interval * 60,
			'flags_raw': flags,
			'line_failure': (flags & self.FLAG_LINE_FAILURE) > 0,
			'ac_failure': (flags & self.FLAG_AC_FAILURE) > 0,
			'battery_failure': (flags & self.FLAG_BATTERY_FAILURE) > 0,
			'armed': (flags & self.FLAG_ARMED) > 0,
			'engineer': (flags & self.FLAG_ENGINEER) > 0,
			}
		self.server.mqtt_client.publish("/alarms/%s/status" % (account), json.dumps(info), qos=1, retain=True)

	def handle_message(self, data, parser):
		# Parse message
		message = parser(self.client_address[0], data[1:])
		
		self.info("%s: a/c %s area %d %s %s %d %s" % (type(message).__name__, message.account_number, message.area, message.event, message.value_name, message.value, message.extra_text))
		if message.description:
			self.debug(message.description)

		# Check we recognise the account number and that
		# the client IP matches
		if self.server.account_manager.get_ip(message.account_number) != self.client_address[0]:
			self.error("Invalid IP address for account %s" % (message.account_number))
			return
		
		# Send ACK
		self.request.send(data[0] + '\x06\r\n')
		
		# Post event message to broker (not retained)
		info = {
			'client_ip': self.client_address[0],
			'client_port': self.client_address[1],
			'account': int(message.account_number),
			'timestamp': datetime.now().isoformat(),
			'area': message.area,
			'event': message.event,
			'value': message.value,
			'value_type': message.value_name,
			'extra_text': message.extra_text,
			}
		self.server.mqtt_client.publish("/alarms/%s/event" % (message.account_number), json.dumps(info), qos=1, retain=False)
		msg = "Area %d %s %s %d" % (message.area, message.event, message.value_name, message.value)
		if message.extra_text:
			msg = msg + " (" + message.extra_text + ")"
		self.server.mqtt_client.publish("/alarms/%s/message" % (message.account_number), msg, qos=1, retain=False)

	def handle(self):
		self.debug("Client connected from %s:%s" % (self.client_address[0], self.client_address[1]))
		
		while True:
			data = self.request.recv(1024)
			if not data:
				break
			
			# Dump raw packet
			self.debug('RAW: ' + hexlify(data))

			if data[0:3] == '+++':
				# End of transmission - we'll got a TCP disconnection after this
				# so just ignore this silently
				continue
			
			# All other messages should have <CR><LF> terminator which we
			# can remove
			if data[-2:] != '\r\n':
				self.error("Ignoring line with missing terminator")
				continue
			data = data[:-2]
			
			# Determine packet type and pass to handler
			if data[0:4] == 'POLL':
				# Polling packet
				self.handle_poll(data)
			elif data[0] == '2':
				self.handle_message(data, ContactId)
			elif data[0] == '3':
				self.handle_message(data, SIA)
			else:
				self.error("Unhandled message: " + hexlify(data))

		self.debug("Client disconnected")
		self.request.close()

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	pass

def on_mqtt_connect(client, userdata, rc):
	logger.info("MQTT connection established: %d" % (rc), extra={'tag': ''})

def on_mqtt_disconnect(client, userdata, rc):
	logger.info("MQTT connection lost: %d" % (rc), extra={'tag': ''})

def on_mqtt_publish(client, userdata, mid):
	logger.debug("MQTT publish complete", extra={'tag': ''})

def main():
	# Start account manager
	manager = AccountManager()

	# Start threaded MQTT client
	MQTT_HOST = get_config('mqtt', 'host')
	MQTT_PORT = int(get_config('mqtt', 'port'))
	MQTT_USERNAME = get_config('mqtt', 'username')
	MQTT_PASSWORD = get_config('mqtt', 'password')
	MQTT_CAFILE = get_config('mqtt', 'cafile')	
	logger.info("Starting MQTT client for %s:%u" % (MQTT_HOST, MQTT_PORT), extra={'tag': ''})

	client = mqtt.Client()
	client.on_connect = on_mqtt_connect
	client.on_disconnect = on_mqtt_disconnect
	client.on_publish = on_mqtt_publish
	if MQTT_CAFILE:
		client.tls_set(MQTT_CAFILE)
	if MQTT_USERNAME and MQTT_PASSWORD:
		client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
	client.connect(MQTT_HOST, MQTT_PORT, 60)
	client.loop_start()

	# Start ARC server
	SERVER_HOST = get_config('server', 'host')
	SERVER_PORT = int(get_config('server', 'port'))
	logger.info("Starting alarm server on %s:%u" % (SERVER_HOST, SERVER_PORT), extra={'tag': ''})
	
	# Start monitoring missed polls
	manager.start_polling_watchdog()
	manager.mqtt_client = client

	t = ThreadedTCPServer((SERVER_HOST, SERVER_PORT), TexecomService)
	t.mqtt_client = client
	t.account_manager = manager
	t.serve_forever()

if __name__ == '__main__':
	if len(sys.argv)>1 and sys.argv[1] == '-d':
		# Daemonize while retaining logger file handles
		daemon = daemon.DaemonContext(
			pidfile = lockfile.FileLock(PID_FILE),
			files_preserve = [ fh.stream ],
			)
		logger.info("Daemonizing...", extra={'tag': ''})
		daemon.open()

	# Log exceptions
	try:
		main()
	except Exception:
		logger.exception("Terminated due to exception", extra={'tag': ''})

