# ovpnherder

Helping to do a little more with openVPN.

## Purpose

The original purpose of this project was to help distribute iroute and ifconfig-push information from openVPN into a routing protocol. In the process, there were some other helpful features added. It uses the openVPN management interface to handle authentication and push useful information from connected clients into other systems.

## Features

### route updates

As it authenticates clients, the application will track iroute and ifconfig-push statements. It will then push these routes out via RIPv2 to localhost, where a listening RIPv2 process (such as [Quagga](https://quagga.net) ) can receive them for insertion into the local routing table and/or redistribution into other routing protocols.
> As a note, it should also be possible to send these routing updates out on an external interface, but that is more complicated and probably less useful. It would require that the process figure out the interface address in order to send out RIP broadcasts from the right IP and to the right broadcast address, which shouldn't be particularly hard. But in order for the dynamic iroutes to be useful, they would also need to be inserted into the local routing table. It seemed much more complicated to write that code than to simply insist on a routing daemon listening for RIP on localhost.

### ccd templates

If you have a lot of clients with identical ccd files and similar names (think user1, user2, user3; or client-alice, client-bob, client-carol), you can put a template directory within your ccd directory.  Then, when user1 connects, the management process will first look for user1 in the ccd directory, then, failing that, will look in the template directory and (for instance) apply a template named "user". This makes for less updating of the ccd directory (which is especially useful if you have a lot of identical openvpn servers and have to manage synchronization of ccd directories between servers).

### MFA

when authenticating, ovh optionally uses the certificates presented, the existence of a ccd file or template, LDAP authentication, and a TOTP. The LDAP configuration is given in the ccd or template, meaning that you can have different clients authenticate against different servers. The totp key is also stored in the ccd, and is only used on initial connections, not on reauth (meaning that you neither have to put in a new OTP every reneg-sec, nor turn off renegotiation). OTP's can be provided either at the end of a password, or via SCRV1.

TODO: replace the LDAP authentication with a way to specify a specific PAM service file.

### ddns

A domain and tsig key can be put in the config so that when clients connect, their IP address is registered in ddns as their CN.

### ccd firewall rules

fwgroup can be included in a ccd, and when a client connects, an iptables rule will be added directing traffic from their IP address into a specific iptables chain.

### source IP filtering

You can specify one or more IP subnets from which a client can connect

## Instructions

TODO: better packaging.

* place ovpnherder in /usr/sbin
* place the ovpnherder.service file in tha appropriate place (/etc/systemd/system/ovpnherder.service?)
* create .ovh files for each of your openvpn instances.  These contain all of the ovh-specific configuration options, and also a "config" line pointing to the openvpn conf file for this instance.
* if you only want to manage some instances, but for whatever reason want to have ovh files for others, add an /etc/default/ovpnherder file containing a list of the ovh files you want it to use (otherwise, it will use all the .ovh files in /etc/openvpn)
* make sure that all of your openvpn config files contain a "management" directive.
* add in "management-client-auth" to your openvpn config files
* if you will not be using passwords to authenticate, but want other features, add "auth-user-pass-optional" (openvpn doesn't provide as much information to the management interface if it doesn't think there's going to be authentication happening)
* start your openvpn services
* start openvpnherder

## Contributing

Right now, the best contribution is trying it out and seeing if it works for you.  If it does, that's great. Let me know.  If it doesn't, any insight as to what might be failing would be helpful. If you know python, and think my code is terrible (likely) but my ideas are OK (also possible), feel free to submit patches. If you think my ideas are terrible, but my code is OK, tell me why so I can think about it.  If you think both my code and ideas are terrible, it's probably not worth your time, feel free to move on.

## License

Released under [GPLv3](LICENSE)

## Contact

I can be reached at j.m.patterson at gmail.

