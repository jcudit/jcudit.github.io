---
title:  "Advanced `iptables` Matching"
---

Here are a few examples of advanced iptables matching rules.  Note that lines with multiple match rules have the heavier rules ordered last.  This subjects a subset of all traffic to the heavy processing required for operations such as string matching.  The ordering ensures that the least costly match rules shield all traffic from the costly match rules.

## Matching TLS traffic to specific domains

```
iptables -I FORWARD -p tcp --dport 443 ! -f -m state --state ESTABLISHED -m u32 --u32 "0>>22&0x3C@ 12>>26&0x3C@ 0>>24 & 0xFF=0x16 && 0>>22&0x3C@ 12>>26&0x3C@ 2>>24 & 0xFF=0x01" --algo bm -j LOG --log-prefix "TLS Client Hello: "
```

**Match on TCP traffic to port 443 that has already been established and is not a fragment**

```
-p tcp --dport 443 ! -f -m state --state ESTABLISHED
```

**Use the u32 module for byte matching**
```
-m u32 --u32
```

**Fast forward past the IP header**
```
0>>22&0x3C@
```

**Fast forward past the TCP header**
```
12>>26&0x3C@
```

**Match when the first byte of the TCP payload is 0x16 (or decimal 22 signifying a TLS record)**
```
0>>24 & 0xFF=0x16
```

**Match when the above conditions are true as well as having the 6th byte of the TCP payload equalling 0x01 (signifying a ClientHello)**
```
0>>22&0x3C@ 12>>26&0x3C@ 2>>24 & 0xFF=0x01
```

**If a specific domain is needed, iptables can  scan the matched TLS ClientHelllo for the string 'domain'**
```
-m string --string "domain" --algo bm
```

## Forcing AAAA record DNS resolution for specific domains

```
iptables -I INPUT -p udp --dport 53 -m string --hex-string '|<domain name encoded as hex string>0001|' --algo bm -j DROP
```

**Match on DNS traffic (UDP/53)**
```
-p udp --dport 53
```

**Match on the target domain string followed by a DNS Query Type 0x01 (A Record)**
```
-m string --hex-string '|<domain name encoded as hex string>|' --algo bm
```

**Drop these requests**
```
-j DROP
```

Modern browsers should be sending both A and AAAA DNS queries.  By dropping the A queries, the AAAA responses would be the only responses allowed for the target domain thus forcing IPv6 connectivity.
