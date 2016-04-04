# DHCPLite

> A small, simple, configuration-free DHCP server for Windows.

## Background

In 2001, I wrote DHCPLite to unblock development scenarios between Windows and prototype hardware we were developing on.
I came up with the simplest DHCP implementation possible and took all the shortcuts I could - but it was enough to get the job done!
Since then, I've heard from other teams using DHCPLite for scenarios of their own.
And recently, I was asked by some [IoT](https://en.wikipedia.org/wiki/Internet_of_Things) devs to share DHCPLite with that community.
So I dug up the code, cleaned it up a bit, got it compiling with the latest toolset, and am sharing the result here.
I hope you find it useful!

## Overview

For those times when you need a DHCP server but don't have the right hardware or software: there's DHCPLite!
DHCPLite is a small, simple, configuration-free [DHCP (Dynamic Host Configuration Protocol)](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol) server that runs on Windows and will serve IP addresses to any [RFC2131](http://www.ietf.org/rfc/rfc2131.txt)/[2132](http://www.ietf.org/rfc/rfc2132.txt) compliant device.

> **Warning!**
> Do **NOT** run DHCPLite when connected to a network that already has a DHCP server on it.
> DHCPLite was *not* designed to cooperate with other DHCP servers and *will* cause serious problems.

## Implementation Notes

- DHCPLite was designed to work alongside [APIPA (Automatic Private IP Addressing (Auto-IP))](https://en.wikipedia.org/wiki/Link-local_address).
  If the host machine acquired its IP address in this manner, DHCPLite will not serve a new address to the host machine.
  (Other machines on the network will be able to obtain IP addresses from DHCPLite.)
- DHCPLite determines the range of addresses it will hand out based on the current IP address and subnet mask of the non-loopback network interface of the machine on which it is running.
  In the case of a host configured by APIPA, this means an address of the form 169.254.x.x and a range of over 65,000 available addresses.
  In the case of a host with a static IP address, the address and range can be changed by altering the static IP address and subnet mask settings on the machine.
- Once it has assigned an IP address to a specific client, DHCPLite will *always* assign that same address to the client (until DHCPLite is shutdown and restarted).
  This means it is possible to exhaust the available address space with either a large number of machines or a small address space.
- In an attempt to mitigate possible misconfiguration problems, DHCPLite hands out address leases that are valid for only 1 hour.
  Lease renewal is supported, so this should not be a problem for long-running scenarios (as long as DHCPLite is running to issue renewals).
- DHCPLite requires the IP Helper API (implemented in `iphlpapi.dll`).

## Unsupported Scenarios

- Multi-homed host machines (i.e., host machines with more than one active network interface).
  Because the [WinSock API](https://en.wikipedia.org/wiki/Winsock) does not allow an application to disable routing of outbound datagrams (sockopt `SO_DONTROUTE` can be silently ignored), DHCPLite would not be able to ensure all outgoing datagrams used the intended interface.

## Unsupported DHCP Features

- `DHCPDECLINE`, `DHCPRELEASE`, and `DHCPINFORM` messages. (See notes above.)
- Requested IP Address option. (Related to notes above.)
- Unicast to hardware address.
  Because DHCPLite is a Windows client application, it does not have access to the underlying network drivers that would allow it to accomplish this.
  Instead, broadcast messages are used and other DHCP clients are relied upon to ignore spurious DHCP messages.
