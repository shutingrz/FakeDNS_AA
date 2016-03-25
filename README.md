# FakeDNS_AA
(metasploit-module) This module provides a DNS service that assert Fake Authoritative Answer.

```sh
[4mmsf[0m [0m> use server/fakedns_aa
[4mmsf[0m auxiliary([1m[31mfakedns_aa[0m) [0m> show options

Module options (auxiliary/server/fakedns_aa):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   FAKEADDR                       no        The address of the fake nameserver to assert Authority
   FAKEHOST      poison.co.jp     yes       The hostname of the fake nameserver to assert Authority
   SRVHOST       0.0.0.0          yes       The local host to listen on.
   SRVPORT       53               yes       The local port to listen on.
   TARGETDOMAIN  *.co.jp          yes       The list of target domain names we want to assert Authority
   TTL           43321            yes       The TTL for the host entry


Auxiliary action:

   Name     Description
   ----     -----------
   Service


[4mmsf[0m auxiliary([1m[31mfakedns_aa[0m) [0m> set FAKEADDR 10.0.0.1
FAKEADDR => 10.0.0.1
[4mmsf[0m auxiliary([1m[31mfakedns_aa[0m) [0m> run
[*] Auxiliary module execution completed
[*] DNS server initializing
[*] DNS server started




#send query (*.co.jp)
shu@shu:~ % dig +norec @127.0.0.1 -t a randomhost.co.jp

; <<>> DiG 9.9.8-P4 <<>> +norec @127.0.0.1 -t a randomhost.co.jp
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;randomhost.co.jp.              IN      A

;; ANSWER SECTION:
randomhost.co.jp.       43321   IN      A       10.0.0.1

;; AUTHORITY SECTION:
co.jp.                  43321   IN      NS      poison.co.jp.

;; ADDITIONAL SECTION:
poison.co.jp.           43321   IN      A       10.0.0.1

;; Query time: 1 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Mar 25 12:36:53 JST 2016
;; MSG SIZE  rcvd: 98

shu@shu:~ % dig +norec @127.0.0.1 -t a rf34f435ht5rhd.co.jp

; <<>> DiG 9.9.8-P4 <<>> +norec @127.0.0.1 -t a rf34f435ht5rhd.co.jp
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6776
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;rf34f435ht5rhd.co.jp.          IN      A

;; ANSWER SECTION:
rf34f435ht5rhd.co.jp.   43321   IN      A       10.0.0.1

;; AUTHORITY SECTION:
co.jp.                  43321   IN      NS      poison.co.jp.

;; ADDITIONAL SECTION:
poison.co.jp.           43321   IN      A       10.0.0.1

;; Query time: 1 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Mar 25 12:37:03 JST 2016
;; MSG SIZE  rcvd: 102




#not *.co.jp
shu@shu:~ % dig +norec @127.0.0.1 -t a gergreg.com

; <<>> DiG 9.9.8-P4 <<>> +norec @127.0.0.1 -t a gergreg.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54839
;; flags: qr; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;gergreg.com.                   IN      A

;; Query time: 1 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Mar 25 12:37:13 JST 2016
;; MSG SIZE  rcvd: 40
```
