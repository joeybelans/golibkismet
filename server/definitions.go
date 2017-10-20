package server

import "net"

// Kismet client object
type serverConnection struct {
	host string   // Kismet hostname/ip address
	port int      // Kismet port
	conn net.Conn // Kismet connection handler
}

// Kismet interface object
type kismetInterface struct {
	uid      string // Kismet interface UUID
	alias    string // Kismet interface alias
	mac      string // Interface hardware address
	driver   string // Interface driver
	lock     bool   // Lock flag
	velocity int    // Hopping rate (channels/sec)
	packets  int    // Packets collected on interface
	channel  int    // Current channel
	channels []int  // Channel list
}

// Package variables
type KismetVars struct {
	version    string                     // Kismet server version
	startTime  string                     // Kismet start time
	name       string                     // Kismet server name
	responses  chan []byte                // Response channel
	requests   map[int]string             // Request pipeline
	interfaces map[string]kismetInterface // Network interfaces
	server     serverConnection           // Kismet server connection
	debug      bool                       // Debug flag
	dumpfiles  []string                   // Dumpfiles - Need to check if needed
	tstamp     string                     // Last kismet timestamp
	index      int                        // Command index number
	client     map[string][]string        // Client capabilities to enable
	nic        map[string]string          // Interface to add for Kismet Monitoring
}

/*
Capabilities
	KISMET:		version, starttime, servername, dumpfiles, uid
	*PROTOCOLS:	protocols
	*CAPABILITY:	capability, fields
	ERROR:		cmdid, text
	ACK:		cmdid, text
	TERMINATE:	text
	TIME:		timesec
	PACKET:
	STATUS:		text, flags
	PLUGIN:
	SOURCE:		interface, type, username, channel, uuid, packets, hop, velocity, dwell, hop_time_sec, hop_time_usec, channellist, error, warning
	ALERT:		sec, usec, header, bssid, source, dest, other, channel, text
	COMMON:
	TRACKINFO:
	WEPKEY:
	STRING:
	GPS:		lat, lon, alt, spd, heading, fix, connected
	BSSID:		bssid, type, llcpackets, datapackets, cryptpackets, manuf, channel, firsttime, lasttime, atype, rangeip, netmaskip, gatewayip, gpsfixed, minlat, minlon, minalt,
			minspd, maxlat, maxlon, maxalt, maxspd, signal_dbm, noise_dbm, minsignal_dbm, minnoise_dbm, maxsignal_dbm, maxnoise_dbm, signal_rssi, noise_rssi, minsignal_rssi,
			minnoise_rssi, maxsignal_rssi, maxnoise_rssi, bestlat, bestlon, bestalt, agglat, agglon, aggalt, aggpoints, datasize, turbocellnid, turbocellmode, turbocellsat,
			carrierset, maxseenrate, encodingset, decrypted, dupeivpackets, bsstimestamp, cdpdevice, cdpport, fragments, retries, newpackets, freqmhz, datacryptset
	SSID:		mac, checksum, type, ssid, beaconinfo, cryptset, cloaked, firsttime, lasttime, maxrate, beaconrate, packets, beacons, dot11d
	CLIENT:		bssid, mac, type, firsttime, lasttime, manuf, llcpackets, datapackets, cryptpackets, gpsfixed, minlat, minlon, minalt, maxlat, maxlon, maxalt, agglat, agglon, aggalt,
			signal_dbm, noise_dbm, minsignal_dbm, minnoise_dbm, maxsignal_dbm, maxnoise_dbm, signal_rssi, noise_rssi, minsignal_rssi, minnoise_rssi, maxsignal_rssi, maxnoise_rssi,
			bestlat, bestlon, bestalt, atype, ip, gatewayip, datasize, maxseenrate, encodingset, carrierset, decrypted, channel, fragments, retries, newpackets, freqmhz, cdpdevice,
			cdpport, dhcphost, dhcpvendor, datacryptset
	BSSIDSRC:	bssid, uuid, lasttime, numpackets
	CLISRC:		bssid, mac, uuid, lasttime, numpackets, signal_dbm, minsignal_dbm, maxsignal_dbm
	NETTAG:		bssid, tag, value
	CLITAG:		bssid, mac, tag, value
	REMOVE:
	CHANNEL:
	INFO:		networks, packets, rate, numsources, numerrorsources, crypt, dropped, filtered, llcpackets, datapackets
	BATTERY:	percentage, charging, ac, remaining
	CRTIFAIL:
* Do not include in parsers array due to initialization loop
*/
type capability struct {
	available []string
	selected  []string
}

var capabilities = map[string]capability{}
