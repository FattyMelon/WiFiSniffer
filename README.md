# WiFiSniffer
WiFi Probe Sniff packets and POST to API.

# Instructions:
WiFi Probe can sniff 802.11 packet and post to API by json data.
filter is packet.type == PROBE_REQUEST_TYPE and packet.subtype==PROBE_REQUEST_SUBTYPE

sniff data to json form
data = {
    "data":[
        {
            "rssi":-83,
            "mac":"c4:ca:d9:15:69:10",
            "id":"abcdef",
            "time":"2016-04-17 20:37:27"
        },
        {
            "rssi":-67,
            "mac":"88:25:93:7e:52:15",
            "id":"abcdef",
            "time":"2016-04-17 20:37:27"
        }
    ]
}

#Run Scipt:
you need to put wifi card in monitor mode first
root@OpenWrt:~# python WiFiSniffer.py

#Installation Dependencies
* Python 2.7.0+
* Scapy 2.2.0+
* Requests 2.0.0+