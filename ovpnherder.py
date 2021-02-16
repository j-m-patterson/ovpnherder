#!/usr/bin/python

import dpkt,socket,struct,time
#pip install dpkt
import select
import sys
import ldap
#apt-get install python-ldap
import hmac,hashlib,base64
from os import listdir,path
import signal
import iptc
#pip install python-iptables
import dns.query, dns.tsigkeyring, dns.update
#pip install dnspython
import logging, logging.handlers, daemon
#apt-get install python-daemon
import thread
import json

# This is no longer needed unless you have a very old copy of dpkt
#monkeypatch the __len__ function in dpkt.rip.RIP, which was borked.
#def monkeylen(self):
	#"monkey-patched fix for bad variable name in dpkt.rip.RIP len function"
	#n = self.__hdr_len__
	#if self.auth:
		#n += mylen(self.auth)
	#n += sum(map(len, self.rtes))
	#return n
#dpkt.rip.RIP.__len__ = monkeylen

def reportstate(signum,stackframe):
	"""
	used by the sigusr1 signal handler, very simple dump of internal state to a file
	"""
	logfile = open('ovpnherder.log','w')
	logfile.write(repr(daemondict))
	logfile.close()

def sendrip(srcip,dstip):
	"""
	Send RIP update packets containing all the routes in daemondict clients from srcip to dstip
	"""
	rtes = []
	for conn in daemondict.keys():
		# the 'nexthop' is the ip of the openvpn process
		nh = daemondict[conn]['nexthop']
		for client in daemondict[conn]['clients'].keys():
			if 'dctime' in daemondict[conn]['clients'][client].keys():
				#this client disconnected, poison its routes
				metric = 16
			else:
				metric = 1
			if 'routes' in daemondict[conn]['clients'][client].keys():
				for (addr,mask) in daemondict[conn]['clients'][client]['routes']:
					rte = dpkt.rip.RTE()
					rte.addr = struct.unpack('!I',socket.inet_aton(addr))
					rte.subnet = struct.unpack('!I',socket.inet_aton(mask))
					rte.next_hop = struct.unpack('!I',socket.inet_aton(nh))
					rte.metric = metric
					rtes.append(rte)
	rip = dpkt.rip.RIP()
	rip.rtes = rtes
	rip.cmd = dpkt.rip.RESPONSE
	rip.auth = None

	udp = dpkt.udp.UDP()
	udp.data = rip
	udp.ulen = len(udp)
	udp.sport = 520
	udp.dport = 520

	ip = dpkt.ip.IP()
	ip.data = udp
	ip.p = 17
	ip.src = socket.inet_aton(srcip)
	ip.dst = socket.inet_aton(dstip)

	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	sock.sendto(str(ip),(dstip,0))

def normalizeCFGfile(cfgfile,path='.'):
	"""
	recurse into any included files and return a single unified list of lines
	"""
	global logger
	#note that 'path' is the path prepended to included files.  This should generally be the cwd of the openvpn process
	linelist = []
	try:
		cfgfileFD = open(cfgfile,'r')
	except IOError:
		logger.warning('could not open config file %s' % cfgfile)
		return([])
	for line in cfgfileFD:
		if line.lower().startswith("config "):
			if line.split(" ")[1].startswith("/"):
				linelist += normalizeCFGfile(line.split(" ")[1].rstrip(),"/")
			else:
				linelist += normalizeCFGfile(path+"/"+line.split(" ")[1].rstrip(),path)
		else:
			linelist.append(line.rstrip())
	cfgfileFD.close()
	return(linelist)
	

def processCCD(ccdfile):
	"""
	process a ccd file to generate a client config dictionary containing the important bits
	"""
	cltcfgdict = {'fwgrp':[],'routes':[],'ipset':[],'cfgstring':""}
	CCD = normalizeCFGfile(ccdfile)
	for line in CCD:
		if line.lower().startswith("ifconfig-push "):
				#this entry has a static IP address assigned, need it pushed into rip
				# a note on what we're doing here: bitwise and of a /30 mask with the tunnel IP to find the tunnel address, because we don't actually
				# have that in our cinfodict, I don't think.
				cltcfgdict['routes'].append([socket.inet_ntoa(struct.pack(">I",struct.unpack(">I",socket.inet_aton(line.split(" ")[1]))[0] & 4294967292)), "255.255.255.252"])
				cltcfgdict['static_ip'] = line.split(" ")[1]
				cltcfgdict['cfgstring'] += line
				cltcfgdict['cfgstring'] += "\n"
		elif line.lower().startswith("iroute "):
				#this entry has a network routed to it, need to push into rip
				cltcfgdict['routes'].append([line.split(" ")[1], line.split(" ")[2]])
				cltcfgdict['cfgstring'] += line
				cltcfgdict['cfgstring'] += "\n"
		elif line.lower().startswith("#fwgroup "):
				#fwgroup config: traffic from this ip will get sent to the $fwgroup chain
				cltcfgdict['fwgrp'].append(line.split(" ")[1])
		elif line.lower().startswith("#ipsourceallowed "):
				#This ccd only allows connections from a list of cidr blocks
				#I'm abandoning IPy, so I'm only going to allow ipsourceallowed in cidr notation.
				cltcfgdict['ipset'].append(line.split(" ")[1])
		elif line.lower().startswith("#totpkey "):
				cltcfgdict['TOTPkey'] = line.split(" ")[1]
		elif line.lower().startswith("#ddnszone "):
				cltcfgdict['DDNSZone'] = line.split(" ")[1]
		else:
				cltcfgdict['cfgstring'] += line
				cltcfgdict['cfgstring'] += "\n"
	return (cltcfgdict)

def recvcltdata(rlist):
	"""
	called when there's data to be read from a daemon socket, spawns handleconn threads for each client block read
	"""
	for conn in rlist:
		sparedata = []
		with daemonlock:
			newdata = daemondict[conn]['sparedata']
			daemondict[conn]['sparedata'] = ''
		while not select.select([conn],[],[],0) == ([],[],[]):
			rcvbuf = conn.recv(2048)
			if rcvbuf == '':
				logger.error('openvpn instance %s seems to have closed its mgmt interface.  Cleaning all of its data and reconnecting' % (daemondict[conn]['ovpncfgfile']))
				thread.start_new_thread(parseOVPNcfg,(daemondict[conn]['ovpncfgfile'],daemondict))
				conn.close()
				with daemonlock:
					daemondict.pop(conn,None)
			newdata += rcvbuf
		#logger.debug('client data:\n %s' % (newdata))
		cinfolist = newdata.split("\n")
		logger.debug('got %d lines of data' % len(cinfolist))
		cinfodict = dict()
		for line in cinfolist:
			sparedata.append(line)
			if not line.startswith('>CLIENT'):
				logger.debug('got non-client info from daemon: \n %s' % (line))
			elif line.startswith('>CLIENT:ADDRESS'):
				logger.debug('client address line: %s' % (line))
			elif line.startswith('>CLIENT:ENV,END'):
				#we have reached the end of a single block of client data
				logger.debug('end of client data block, handing data off to connection handler')
				thread.start_new_thread(handleconn,(cinfodict,conn))
				cinfodict = dict()
				sparedata = []
			elif not cinfodict:
				#if cinfodict is empty, this is the first client line and should contain the conntype
				cinfodict['conntype'] = line[8:].rstrip().split(',')
			else:
				keyname = line[12:].split('=')[0]
				value  = line.rstrip()[13+len(keyname):]
				#logger.debug('adding value %s to key %s' % (value,keyname))
				cinfodict[keyname] = value
		with daemonlock:
			daemondict[conn]['sparedata'] += '\n'.join(sparedata)
		#I probably *should* check if there's another full block in the buffer, but I think I should be fine, because 
		# whatever gets done with the previous connection will trigger output, which means that we will run this again.

def handleconn(cinfodict,conn):
	"""
	invoked as a thread to handle authentication and route/fw/dns updates for a single client instance
	"""
	#cinfodict['conntype'][0] should be one of CONNECT,REAUTH,ESTABLISHED,DISCONNECT
	logger.info('new client info of type %s' % (cinfodict['conntype'][0]))
	logger.debug(cinfodict.keys())
	if 'common_name' in cinfodict.keys():
		(ccdauth,ccdfile) = authViaCCD(cinfodict['common_name'],daemondict[conn]['ccdir'])
		if ccdauth:
			logger.debug('using client config from %s' % (ccdfile))
			cltcfgdict = processCCD(ccdfile)
	if cinfodict['conntype'][0] == 'CONNECT':
		if not ccdauth:
			logger.debug('client denied due to lack of ccd')
			conn.sendall("client-deny %s %s \"No such Client Config file\"\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
			return
		if 'ipset' in cltcfgdict.keys() and len(cltcfgdict['ipset']) > 0:
			logger.debug('checking source IP %s' %(cinfodict['untrusted_ip']))
			if not authViaSrcIP(cinfodict['untrusted_ip'],cltcfgdict['ipset']):
				logger.debug('client ip source auth failed')
				conn.sendall("client-deny %s %s \"Client not permitted from this IP\" \"Client not permitted from this IP\"\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
				return
		# if this is a user connection, check passwords
		if len(daemondict[conn]['ldapuri']) > 0:
			if not 'password' in cinfodict.keys():
				logger.debug('client needed password, but none was supplied')
				conn.sendall("client-deny %s %s \"password failed\" \"Authentication Failed\"\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
				return
			# if the password starts with SCRV1:, this is a static challenge.  Parse appropriately.
			if cinfodict['password'].startswith('SCRV1:'):
				logger.debug('parsing static challenge password')
				(tag,passwd,challenge) = cinfodict['password'].split(':')
				challenge = base64.b64decode(challenge)
				cinfodict['password'] = base64.b64decode(passwd)
			# if the user has a TOTPkey, check it
			if 'TOTPkey' in cltcfgdict.keys():
				logger.debug('checking TOTP key')
				if 'challenge' in locals():
					(totpauth,realval) = authViaTOTP(cltcfgdict['TOTPkey'],challenge)
				else:
					(totpauth,realval) = authViaTOTP(cltcfgdict['TOTPkey'],cinfodict['password'])
				if not totpauth:
					conn.sendall("client-deny %s %s \"OTP failed\" \"Authentication Failed\"\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
					return
			# check the user against LDAP
			logger.debug('checking user/pass against LDAP')
			ldapuri = daemondict[conn]['ldapuri']
			ldapbasedn = daemondict[conn]['ldapbasedn']
			if 'TOTPkey' in cltcfgdict.keys() and not 'challenge' in locals():
				(ldapauth,user) = authViaLDAP(ldapuri,ldapbasedn,cinfodict['common_name'],cinfodict['password'][:len(cinfodict['password'])-6])
			else:
				(ldapauth,user) = authViaLDAP(ldapuri,ldapbasedn,cinfodict['common_name'],cinfodict['password'])
			if not ldapauth:
				logger.debug('user auth failed for user %s' % (cinfodict['common_name']))
				conn.sendall("client-deny %s %s \"password failed\" \"Authentication Failed\"\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
				return
		# if we've made it here, user is authenticated.
		logger.debug('user %s successfully authenticated' % (cinfodict['common_name']))
		if cinfodict['conntype'][1] in daemondict[conn]['clients'].keys():
			#uh-oh.  This client id already exists.  That probably means the client has disconnected while we were doing other stuff
			return
		daemondict[conn]['clients'][cinfodict['conntype'][1]] = dict()
		daemondict[conn]['clients'][cinfodict['conntype'][1]]['common_name'] = cinfodict['common_name']
		# if fwgrp is populated, adjust FW rules and populate daemondict.client.fwgrp
		if len(cltcfgdict['fwgrp']) > 0 and 'static_ip' in cltcfgdict.keys():
			logger.debug('setting firewall rules for static IP client')
			for groupname in cltcfgdict['fwgrp']:
				rule = iptc.Rule()
				rule.src = cltcfgdict['static_ip']
				rule.target = iptc.Target(rule,groupname)
				chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),"FWGroups")
				chain.insert_rule(rule)
		daemondict[conn]['clients'][cinfodict['conntype'][1]]['fwgrp'] = cltcfgdict['fwgrp']
		if 'DDNSZone' in cltcfgdict.keys() and 'static_ip' in cltcfgdict.keys():
			keyring = dns.tsigkeyring.from_text({daemondict[conn]['ddnskeys'][0] : daemondict[conn]['ddnskeys'][1]})
			update = dns.update.Update(cltcfgdict['DDNSZone'],keyring=keyring)
			update.add(cinfodict['common_name'],300,'a',cltcfgdict['static_ip'])
			logger.debug('adding name %s to zone %s with static IP %s' % (cinfodict['common_name'],cltcfgdict['DDNSZone'],cltcfgdict['static_ip']))
			if 'username' in cinfodict.keys() and cinfodict['common_name'] != cinfodict['username']:
				update.add('%s.%s' % (cinfodict['username'],cinfodict['common_name']),300,'a',cltcfgdict['static_ip'])
			try:
				response = dns.query.tcp(update, daemondict[conn]['ddnshost'])
			except dns.tsig.PeerError:
				logger.error('DNS zone update failed due to peer error')
				# we tried, it didn't work.
		# if there are routes to add, populate daemondict.client.routes
		daemondict[conn]['clients'][cinfodict['conntype'][1]]['routes'] = cltcfgdict['routes']
		# finally, tell openvpn this client is OK.
		logger.debug('sending client config to openvpn')
		conn.sendall("client-auth %s %s\n%s\nEND\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2],cltcfgdict['cfgstring']))
		with open(daemondict[conn]['statefile'],'w') as stateFD:
			logger.debug('saving state to %s' % (daemondict[conn]['statefile']))
			json.dump(daemondict[conn],stateFD,indent=4)
	elif cinfodict['conntype'][0] == 'REAUTH':
		logger.debug('client reauthentication')
		if not ccdauth:
			logger.debug('client ccd file removed after initial auth?  Terminating client')
			conn.sendall("client-deny %s %s \"No such Client Config file\"\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
			return
		# if this is a user connection, check passwords
		if len(daemondict[conn]['ldapuri']) > 0:
			if not 'password' in cinfodict.keys():
				logger.debug('client needed password, but none was supplied')
				conn.sendall("client-deny %s %s \"password failed\" \"Authentication Failed\"\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
				return
			# if the password starts with SCRV1:, this is a static challenge.  Parse appropriately.
			if cinfodict['password'].startswith('SCRV1:'):
				(tag,passwd,challenge) = cinfodict['password'].split(':')
				challenge = base64.b64decode(challenge)
				cinfodict['password'] = base64.b64decode(passwd)
			# check the user against LDAP
			ldapuri = daemondict[conn]['ldapuri']
			ldapbasedn = daemondict[conn]['ldapbasedn']
			if 'TOTPkey' in cltcfgdict.keys() and not 'challenge' in locals():
				(ldapauth,user) = authViaLDAP(ldapuri,ldapbasedn,cinfodict['common_name'],cinfodict['password'][:len(cinfodict['password'])-6])
			else:
				(ldapauth,user) = authViaLDAP(ldapuri,ldapbasedn,cinfodict['common_name'],cinfodict['password'])
			if not ldapauth:
				conn.sendall("client-deny %s %s \"password failed\" \"Authentication Failed\"\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
				return
		conn.sendall("client-auth-nt %s %s\n" % (cinfodict['conntype'][1],cinfodict['conntype'][2]))
	elif cinfodict['conntype'][0] == 'DISCONNECT':
		logger.debug('processing client disconnect')
		if not cinfodict['conntype'][1] in daemondict[conn]['clients'].keys():
			#looks like we've disconnected before connecting.  Leave an empty dict to let the auth thread know.
			logger.debug('client %s disconnected before connection completion' % (cinfodict['conntype'][1]))
			daemondict[conn]['clients'][cinfodict['conntype'][1]] = dict()
			daemondict[conn]['clients'][cinfodict['conntype'][1]]['dctime'] = time.time()
			return
		#remove any fwgrp rules
		if len(daemondict[conn]['clients'][cinfodict['conntype'][1]]['fwgrp']) > 0:
			for groupname in daemondict[conn]['clients'][cinfodict['conntype'][1]]['fwgrp']:
				rule = iptc.Rule()
				if 'ifconfig_pool_remote_ip' in cinfodict.keys():
					rule.src = cinfodict['ifconfig_pool_remote_ip']
				else:
					break
				rule.target = iptc.Target(rule,groupname)
				chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),"FWGroups")
				chain.delete_rule(rule)
		if 'DDNSZone' in cltcfgdict.keys():
			if 'static_ip' in cltcfgdict.keys():
				ipaddr = cltcfgdict['static_ip']
			elif 'ifconfig_pool_remote_ip' in cinfodict.keys():
				ipaddr = cinfodict['ifconfig_pool_remote_ip']
			keyring = dns.tsigkeyring.from_text({daemondict[conn]['ddnskeys'][0] : daemondict[conn]['ddnskeys'][1]})
			update = dns.update.Update(cltcfgdict['DDNSZone'],keyring=keyring)
			update.delete(cinfodict['common_name'],'a',ipaddr)
			if 'username' in cinfodict.keys() and cinfodict['common_name'] != cinfodict['username']:
				update.delete('%s.%s' % (cinfodict['username'],cinfodict['common_name']),'a',ipaddr)
			try:
				response = dns.query.tcp(update, daemondict[conn]['ddnshost'])
			except dns.tsig.PeerError:
				# we tried, it didn't work.
				pass
		#mark this client as disconnected and note time, trash collection should clean it up after its routes are all poisoned
		daemondict[conn]['clients'][cinfodict['conntype'][1]]['dctime'] = time.time()
		with open(daemondict[conn]['statefile'],'w') as stateFD:
			logger.debug('saving state to %s' % (daemondict[conn]['statefile']))
			json.dump(daemondict[conn],stateFD,indent=4)
	elif cinfodict['conntype'][0] == 'ESTABLISHED':
		#the only time we should need to care about ESTABLISHED messages is if we have fwgrp or dns and a pool IP.
		if len(cltcfgdict['fwgrp']) > 0 and not 'static_ip' in cltcfgdict.keys():
			for groupname in cltcfgdict['fwgrp']:
				logger.debug('setting firewall rule %s for dynamic ip %s' % (groupname,cinfodict['ifconfig_pool_remote_ip']))
				rule = iptc.Rule()
				rule.src = cinfodict['ifconfig_pool_remote_ip']
				rule.target = iptc.Target(rule,groupname)
				chain = iptc.Chain(iptc.Table(iptc.Table.FILTER),"FWGroups")
				chain.insert_rule(rule)
		daemondict[conn]['clients'][cinfodict['conntype'][1]]['fwgrp'] = cltcfgdict['fwgrp']
		if 'DDNSZone' in cltcfgdict.keys() and not 'static_ip' in cltcfgdict.keys():
			keyring = dns.tsigkeyring.from_text({daemondict[conn]['ddnskeys'][0] : daemondict[conn]['ddnskeys'][1]})
			update = dns.update.Update(cltcfgdict['DDNSZone'],keyring=keyring)
			update.add(cinfodict['common_name'],300,'a',cinfodict['ifconfig_pool_remote_ip'])
			logger.debug('adding name %s to zone %s with dynamic IP %s' % (cinfodict['common_name'],cltcfgdict['DDNSZone'],cinfodict['ifconfig_pool_remote_ip']))
			if 'username' in cinfodict.keys() and cinfodict['common_name'] != cinfodict['username']:
				update.add('%s.%s' % (cinfodict['username'],cinfodict['common_name']),300,'a',cinfodict['ifconfig_pool_remote_ip'])
			try:
				response = dns.query.tcp(update, daemondict[conn]['ddnshost'])
			except dns.tsig.PeerError:
				# we tried, it didn't work.
				pass
		with open(daemondict[conn]['statefile'],'w') as stateFD:
			logger.debug('saving state to %s' % (daemondict[conn]['statefile']))
			json.dump(daemondict[conn],stateFD,indent=4)
	elif cinfodict['conntype'][0] == 'ADDRESS':
		pass
	else:
		#should never get here, but just in case.
		logger.warning('encountered unknown connection type: %s' % (cinfodict['conntype'][0]))
	with open(daemondict[conn]['statefile'],'w') as stateFD:
		logger.debug('updating state file %s' % (daemondict[conn]['statefile']))
		json.dump(daemondict[conn],stateFD,indent=4)
	sendrip('127.0.0.2','127.0.0.1')

def authViaLDAP(uri,basedn,uid,password):
	"""
	Check if the username and password are valid within the basedn on any of the list of ldap server URI's
	"""
	global logger
	#I'm wrapping everything in a try bubble because any failure is an auth fail
	srvfailmsg = []
	for ldapserver in uri:
		try:
			logger.debug('authenticating uid %s against %s' % (uid,ldapserver))
			ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
			conn=ldap.initialize(ldapserver)
			trash=conn.simple_bind_s()
			results=conn.search_s(basedn,ldap.SCOPE_SUBTREE,"uid="+uid)
			if len(results) == 0:
				logger.debug('user %s not found on ldap server %s' % (uid,ldapserver))
				return(False,"No user found")
			elif len(results) > 1:
				logger.error('too many users (%d)  matched uid %s on server %s' % (uid,len(results),ldapserver))
				return(False,"Something's fucky, too many users matched")
			logger.debug('attempting to bind to server %s as %s' % (ldapserver,results[0][0]))
			conn.simple_bind_s(results[0][0],password)
		except ldap.INVALID_CREDENTIALS as ldaperror:
			logger.debug('user ldap auth failed')
			return(False,ldaperror.message['desc'])
		except ldap.LDAPError as ldaperror:
			logger.error('LDAP auth failed for %s with message %s' % (ldapserver,ldaperror.message['desc']))
			srvfailmsg.append(ldaperror.message['desc'])
		else:
			return(True,results[0][0])
	return(False,"No functional servers available: "+repr(srvfailmsg))

def authViaTOTP(key,password,digits=6,window=30):
	"""
	Checks if the OTP at the end of the password is valid for the given key
	"""
	count = int(time.time()/window)
	count_bytes = struct.pack(b"!Q", count)
	hmac_digest = hmac.new(key=base64.b32decode(key), msg=count_bytes, digestmod=hashlib.sha1).hexdigest()
	offset = int(hmac_digest[-1], 16)
	binary = int(hmac_digest[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
	if str(binary)[-digits:] == str(password)[-digits:]:
		return(True,str(binary)[-digits:])
	else:
		return(False,str(binary)[-digits:])

def authViaCCD(username,ccdir):
	"""
	checks is a CCD file exists for the given user or, failing that, an appropriate template file.  Returns the ccd file to use.
	"""
	useccd=""
	if path.isfile(ccdir+username):
		useccd = ccdir+username
	else:
		for filename in listdir(ccdir+"/templates/"):
			if username.startswith(filename):
				useccd = ccdir+"/templates/"+filename
		if useccd == "":
			return(False,"")
	return(True,useccd)

def authViaSrcIP(srcip,ipset):
	"""
	checks to see if a given source IP is within any of the cidr blocks in a list
	"""
	global logger
	for cidr in ipset:
		try:
			(address,netmask) = cidr.split('/')
			srcnet = struct.unpack(">I",socket.inet_aton(srcip))[0] & (0xffffffff ^ (1 << 32 - int(netmask)) - 1)
			cidrnet = struct.unpack(">I",socket.inet_aton(address))[0] & (0xffffffff ^ (1 << 32 - int(netmask)) - 1)
			if srcnet == cidrnet:
				return True
		except ValueError:
			logger.error('bad value when checking allowed ip src. CIDR: %s' % (cidr))
		except socket.error:
			logger.error('bad IP address when checking allowed ip src. CIDR: %s' % (cidr))
	return False

def supernetIP(ipA,ipB):
	"""
	given two IP addresses, returns the smallest network/mask that contains both
	"""
	foo = zip("".join([bin(int(x)+256)[3:] for x in ipA.split('.')]),"".join([bin(int(x)+256)[3:] for x in ipB.split('.')]))
	wcard = len(foo)
	while foo[-wcard][0] == foo[-wcard][1]:
		wcard -= 1
	maskbits = len(foo) - wcard
	network = socket.inet_ntoa(struct.pack(">I",struct.unpack(">I",socket.inet_aton(ipA))[0] & (0xffffffff ^ (1 << 32 - maskbits) - 1)))
	mask = socket.inet_ntoa(struct.pack('!I',0xffffffff ^ (1 << 32 - maskbits) - 1))
	return(network,mask)

def parseOVPNcfg(ovpncfgfile,daemondict):
	"""
	constructs a daemoninfo dictionary based on a config file that should pull in an openvpn config
	"""
	cfglines = normalizeCFGfile(ovpncfgfile)
	thisconfig = {'ovpncfgfile' : ovpncfgfile, 
			'statefile' : ovpncfgfile+'.state',
			'sparedata' : '', 
			'ldapuri' : [], 
			'ldapbasedn' : 'dc=example,dc=com', 
			'ccdir' : '/etc/openvpn/ccd/', 
			'clients' : {'self' : {'routes': []}}}
	for line in cfglines:
		if line.lower().startswith('ifconfig-pool '):
			thisconfig['clients']['self']['routes'].append(supernetIP(line.split(" ")[1],line.split(" ")[2]))
		elif line.lower().startswith('ifconfig '):
			thisconfig['nexthop'] = line.split(" ")[2]
		elif line.lower().startswith('management '):
			thisconfig['mgmt'] = (line.split(" ")[1],int(line.split(" ")[2]))
		elif line.lower().startswith('client-config '):
			thisconfig['ccdir'] = line.split(" ")[1]
		elif line.lower().startswith('ldapuri '):
			thisconfig['ldapuri'].append(line.split(" ")[1])
		elif line.lower().startswith('ldapbasedn '):
			thisconfig['ldapbasedn'] = line.split(" ")[1]
		elif line.lower().startswith('statefile '):
			thisconfig['statefile'] = line.split(" ")[1]
		elif line.lower().startswith('ddnsinfo '):
			# format of ddnsinfo line is "host keyname keydata"
			thisconfig['ddnshost'] = line.split(" ")[1]
			thisconfig['ddnskeys'] = line.split(" ")[2:]
		elif line.lower().startswith('debug '):
			debuglog = logging.FileHandler(line.split(" ")[1])
			debuglog.setLevel(logging.DEBUG)
			debuglog.setFormatter(formatter)
			logger.addHandler(debuglog)
	if not 'mgmt' in thisconfig.keys():
		logger.error('no management line in %s, cannot manage this instance' % (ovpncfgfile))
		return
	daemonsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	while True:
		try:
			daemonsock.connect(thisconfig['mgmt'])
		except socket.error:
			time.sleep(5)
			#I'd like to make this an exponential backoff with a ceiling, but for the moment every 5 seconds will have to do.
		else:
			break
	if path.isfile(thisconfig['statefile']):
		with open(thisconfig['statefile']) as stateFD:
			statedict = json.load(stateFD)
		daemonsock.sendall('status 2\n')
		statdata = daemonsock.recv(2048)
		while select.select([daemonsock],[],[],0) != ([],[],[]):
			statdata += daemonsock.recv(2048)
		statlines = statdata.split('\n')
		for line in statlines:
			if line.startswith('TITLE,OpenVPN'):
				ovpnver = line.split(' ')[1].split('.')
				if int(ovpnver[0]) != 2 or int(ovpnver[1]) < 4:
					logger.critical('openvpn major version is %s, minor is %d' % (ovpnver[0],int(ovpnver[1])))
					break
			elif line.startswith('CLIENT_LIST'):
				#this is a connected client, copy from statedict to thisconfig
				thisCID = line.split(',')[9]
				if thisCID in statedict['clients'].keys():
					thisconfig['clients'][thisCID] = statedict['clients'][thisCID]
		thisconfig['sparedata'] = statdata
		#while we're not losing any data here, I think there may be a race condition where a client connects immediately on startup
		# and we're going to wait for the next select.select to come back live before handling it.  But I think the worst case scenario 
		# is that the client times out and has to retry.
	with daemonlock:
		daemondict.update({daemonsock : thisconfig})
		with open(thisconfig['statefile'],'w') as stateFD:
			logger.debug('saving state to %s' % (thisconfig['statefile']))
			json.dump(thisconfig,stateFD,indent=4)

def liststale(stalesec):
	"""
	Make a list of stale clients that are ripe for pruning
	"""
	staleCID = []
	connlist = daemondict.keys()
	for conn in connlist:
		clientlist = daemondict[conn]['clients']
		for client in clientlist:
			if 'dctime' in daemondict[conn]['clients'][client].keys():
				if int(time.time()) - int(daemondict[conn]['clients'][client]['dctime']) > stalesec:
					staleCID.append((conn,client))
	return(staleCID)

def setuplogs():
	"""
	written in the vain hope that it would make testing easier by making my functions that rely on logger work 
	when I import this as a library.  Alas, it is not so.
	"""
	logger = logging.getLogger('ovpnherder')
	logger.setLevel(logging.DEBUG)
	syslog = logging.handlers.SysLogHandler(address='/dev/log')
	syslog.setLevel(logging.ERROR)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	syslog.setFormatter(formatter)
	logger.addHandler(syslog)
	return(logger,formatter)
	

if __name__ == "__main__":

	errorlog = open('ovpnherder.stderr.txt','w')
	outlog = open('/dev/null','w')
	# if *something* isn't opened for stdout and stderr, things get wonky.  In prod, these will both be /dev/null
	# in dev/test, stderr will actually go to a file
	# this is important, because DaemonContext eats stdout/stderr, and threading means that exceptions don't 
	# cause crashes, they just exit the thread they happen in, so without this all hell can break loose and 
	# you'll be none the wiser.
	context = daemon.DaemonContext(
		working_directory='/etc/openvpn/',
		umask=0o0077,
		stderr=errorlog,
		stdout=outlog,
		)
	context.signal_map = {
		signal.SIGUSR1: reportstate
		}
	with context:
		(logger,formatter) = setuplogs()
		update = 30
		daemondict = dict()
		daemonlock = thread.allocate_lock()
		numdaemons = 0
		if len(sys.argv) > 1:
			numdaemons = len(sys.argv)
			for configfile in sys.argv[1:]:
				thread.start_new_thread(parseOVPNcfg,(configfile,daemondict))
		else:
			for configfile in listdir('/etc/openvpn/'):
				if configfile.endswith('.ovh'):
					numdaemons += 1
					thread.start_new_thread(parseOVPNcfg,(configfile,daemondict))
		if numdaemons < 1:
			logger.error('no config files on command line or in /etc/openvpn, exiting')
		else:
			while True:
				daemonsocks = daemondict.keys()
				try:
					(rlist,wlist,xlist) = select.select(daemonsocks,[],daemonsocks,update)
				except select.error:
					rlist = []
				recvcltdata(rlist)
				staleCID = liststale(300)
				if len(staleCID) > 0:
					logger.debug('removing stale connections: %s' % (repr(staleCID)))
				with daemonlock:
					for (conn,client) in staleCID:
						daemondict[conn]['clients'].pop(client,None)
				with daemonlock:
					sendrip('127.0.0.2','127.0.0.1')

