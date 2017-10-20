package server

import (
	"fmt"
	"log"
	"strings"
)

// Collect Kismet server responses in a blocking state
func (vars *KismetVars) Return() []byte {
	msg := <-vars.responses
	if vars.debug {
		log.Printf("[RETURN DATA]: %v\n", string(msg))
	}
	return msg
}

// Send command to kismet server
// Add the command to the pipeline
// Increase the command index number
func (vars *KismetVars) send(cmd string) {
	vars.requests[vars.index] = cmd
	cmdstr := fmt.Sprintf("!%d ", vars.index) + cmd
	if vars.debug {
		fmt.Println("SEND: " + cmdstr)
	}
	vars.server.conn.Write([]byte(cmdstr + "\n"))
	vars.index++
}

// Enable specified protocol and include the requested fields
func (vars *KismetVars) enable(protocol string, fields []string) {
	var valid bool

	// Store the selected fields, in the order requested, with the capability to correctly parse the responses
	selected := []string{}
	for _, sField := range fields {
		valid = false
		fmt.Printf("PROTOCOLS: %v CAPABILITY: %v\n", protocol, capabilities[protocol])
		for _, aField := range capabilities[protocol].available {
			if sField == aField {
				valid = true
				selected = append(selected, sField)
				break
			}
		}
		if !valid {
			fmt.Println("Field (" + sField + ") is not valid in capability (" + protocol + ")")
			break
		}
	}

	// If all fields are valid for the capability, enable the capability on the server
	if valid {
		capabilities[protocol] = capability{capabilities[protocol].available, selected}
		vars.send("ENABLE " + protocol + " " + strings.Join(fields, ","))
		delete(vars.client, protocol)
	}
}

// Disable the specified protocol
func (vars *KismetVars) disable(protocol string) {
	vars.send("REMOVE " + protocol)
}

// Add network card as kismet source
func (vars *KismetVars) AddSource() {
	for nic, name := range vars.nic {
		cmd := "ADDSOURCE " + nic
		if name != "" {
			cmd = cmd + ":name=" + name
		}
		vars.send(cmd)
	}
}

// Remove network card as kismet source
// WARNING: this causes kismet to sigfault
func (vars *KismetVars) DelSource(nic string) {
	cmd := "DELSOURCE " + vars.interfaces[nic].uid
	vars.send(cmd)
}

// Hop specified channels at the specified velocity (channels/sec) on the specified network card
func (vars *KismetVars) ChannelHop(nic string, velocity int, channels []int) {
	uid := vars.interfaces[nic].uid

	var chArray []string
	for _, value := range channels {
		chArray = append(chArray, string(value))
	}

	vars.send("CHANSOURCE " + uid + " " + strings.Join(chArray, ","))
	vars.send("HOPSOURCE " + uid + " HOP " + string(velocity))
}

// Lock on specified channel on the specified network card
func (vars *KismetVars) ChannelLock(nic string, channel int) {
	vars.send("HOPSOURCE " + vars.interfaces[nic].uid + " LOCK " + string(channel))
}

// Shutdown kismet
func (vars *KismetVars) KillServer() {
	vars.send("SHUTDOWN")
}

// Kismet router for parser functions
func (vars *KismetVars) router(field string) (interface{}, bool) {
	if vars.debug {
		log.Printf("[Kismet-Router]: %v\n", field)
	}
	// Kismet response parsers
	var parsers = map[string]interface{}{
		"KISMET":    vars.parseKISMET,
		"ERROR":     vars.parseERROR,
		"ACK":       vars.parseACK,
		"TERMINATE": vars.parseTERMINATE,
		"TIME":      vars.parseTIME,
		"STATUS":    vars.parseSTATUS,
		"SOURCE":    vars.parseSOURCE,
		"ALERT":     vars.parseALERT,
		"BSSID":     vars.parseBSSID,
		"SSID":      vars.parseSSID,
		"CLIENT":    vars.parseCLIENT,
		"BSSIDSRC":  vars.parseBSSIDSRC,
		"CLISRC":    vars.parseCLISRC,
		"NETTAG":    vars.parseNETTAG,
		"CLITAG":    vars.parseCLITAG,
		"INFO":      vars.parseINFO,
		"GPS":       vars.parseGPS,
	}
	if val, ok := parsers[field]; ok {
		return val, ok
	}
	return nil, false
}

// Enable KismetServer client filters
func Features(opt string) map[string][]string {
	switch opt {
	case "warwalk":
		return map[string][]string{
			"GPS": []string{"lat", "lon", "alt", "spd", "heading", "fix", "connected"},
			"SSID": []string{"mac", "checksum", "type", "ssid", "beaconinfo", "cryptset", "cloaked", "firsttime",
				"lasttime", "maxrate", "beaconrate", "packets", "beacons", "dot11d"},
			"BSSID": []string{"bssid", "type", "llcpackets", "datapackets", "cryptpackets", "manuf", "channel",
				"firsttime", "lasttime", "atype", "rangeip", "netmaskip", "gatewayip", "signal_dbm", "minsignal_dbm", "maxsignal_dbm"},
			"ERROR": []string{"cmdid", "text"},
		}
	case "gps-bssid":
		return map[string][]string{
			"GPS": []string{"lat", "lon", "alt", "spd", "heading", "fix", "connected"},
			"BSSID": []string{"bssid", "type", "llcpackets", "datapackets", "cryptpackets", "manuf", "channel",
				"firsttime", "lasttime", "atype", "rangeip", "netmaskip", "gatewayip", "signal_dbm", "minsignal_dbm", "maxsignal_dbm"},
		}
	default:
		return map[string][]string{
			"INFO":      []string{"packets", "rate", "crypt", "dropped", "filtered", "llcpackets", "datapackets"},
			"STATUS":    []string{"text", "flags"},
			"ERROR":     []string{"cmdid", "text"},
			"ACK":       []string{"cmdid", "text"},
			"TERMINATE": []string{"text"},
			"TIME":      []string{"timesec"},
			"SOURCE": []string{"interface", "type", "username", "channel", "uuid", "packets", "hop", "velocity",
				"dwell", "hop_time_sec", "hop_time_usec", "channellist", "error", "warning"},
			"ALERT": []string{"sec", "usec", "header", "bssid", "source", "dest", "other", "channel", "text"},
			"BSSID": []string{"bssid", "type", "llcpackets", "datapackets", "cryptpackets", "manuf", "channel",
				"firsttime", "lasttime", "atype", "rangeip", "netmaskip", "gatewayip", "signal_dbm", "minsignal_dbm", "maxsignal_dbm"},
			"SSID": []string{"mac", "checksum", "type", "ssid", "beaconinfo", "cryptset", "cloaked", "firsttime",
				"lasttime", "maxrate", "beaconrate", "packets", "beacons", "dot11d"},
			"CLIENT": []string{"bssid", "mac", "type", "firsttime", "lasttime", "manuf", "llcpackets", "datapackets",
				"cryptpackets", "gpsfixed", "minlat", "minlon", "minalt", "maxlat", "maxlon", "maxalt", "agglat", "agglon",
				"aggalt", "signal_dbm", "noise_dbm", "minsignal_dbm", "minnoise_dbm", "maxsignal_dbm", "maxnoise_dbm",
				"signal_rssi", "noise_rssi", "minsignal_rssi", "minnoise_rssi", "maxsignal_rssi", "maxnoise_rssi", "bestlat",
				"bestlon", "bestalt", "atype", "ip", "gatewayip", "datasize", "maxseenrate", "encodingset", "carrierset",
				"decrypted", "channel", "fragments", "retries", "newpackets", "freqmhz", "cdpdevice", "cdpport", "dhcphost",
				"dhcpvendor", "datacryptset"},
			"BSSIDSRC": []string{"bssid", "uuid", "lasttime", "numpackets"},
			"CLISRC":   []string{"bssid", "mac", "uuid", "lasttime", "numpackets", "signal_dbm", "minsignal_dbm", "maxsignal_dbm"},
			"NETTAG":   []string{"bssid", "tag", "value"},
			"GPS":      []string{"lat", "lon", "alt", "spd", "heading", "fix", "connected"},
			"CLITAG":   []string{"bssid", "mac", "tag", "value"},
		}
	}
}
