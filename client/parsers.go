// Manages server connection and data related to kismet server
package client

import (
	"fmt"
	"log"
	"strconv"
)

func (vars *KismetClient) processERROR(obj map[string]string) {
	if vars.debug {
		log.Printf("[processERROR]: %v\n", obj)
	}
	fmt.Println(obj["message"] + ": " + obj["text"])
}

func (vars *KismetClient) processSTATUS(obj map[string]string) {
	if vars.debug {
		log.Printf("[processSTATUS]: %v\n", obj)
	}
	fmt.Println(obj["title"] + ": " + obj["text"])
}

func (vars *KismetClient) processSOURCE(obj map[string]string) {
	if vars.debug {
		log.Printf("[processSOURCE]: %v\n", obj)
	}
	if obj["warning"] != "" {
		fmt.Println("NIC-WARNING: (" + obj["error"] + ") " + obj["warning"])
	}
}

func (vars *KismetClient) processGPS(obj map[string]string) {
	if vars.debug {
		log.Printf("[processGPS]: %v\n", obj)
	}
	vars.GPS.LAT, _ = strconv.ParseFloat(obj["lat"], 32)
	vars.GPS.LON, _ = strconv.ParseFloat(obj["lon"], 32)
	vars.GPS.ALT, _ = strconv.Atoi(obj["alt"])
	vars.GPS.Heading, _ = strconv.Atoi(obj["heading"])
	vars.GPS.SPD, _ = strconv.Atoi(obj["spd"])
	vars.GPS.Fix, _ = strconv.Atoi(obj["fix"])
	vars.GPS.Connected, _ = strconv.ParseBool(obj["connected"])
}

func (vars *KismetClient) processINFO(obj map[string]string) {
	if vars.debug {
		log.Printf("[processINFO]: %v\n", obj)
	}
}

func (vars *KismetClient) processALERT(obj map[string]string) {
	if vars.debug {
		log.Printf("[processALERT]: %v\n", obj)
	}
	fmt.Println(obj["message"] + ": " + obj["text"])
}

func (vars *KismetClient) processBSSIDSRC(obj map[string]string) {
	if vars.debug {
		log.Printf("[processBSSIDSRC]: %v\n", obj)
	}
}

func (vars *KismetClient) processBSSID(obj map[string]string) {
	if vars.debug {
		log.Printf("[processBSSID]: %v\n", obj)
	}
	// Define access point
	var ap AccessPoint
	_, exists := vars.AccessPoints[obj["bssid"]]
	if !exists {
		ap = AccessPoint{"", "", obj["manuf"], 0, 0, 0, 0, obj["rangeip"], obj["netmaskip"], obj["gatewayip"], 0, 0, 0, 0}
		ap.FirstTime, _ = strconv.Atoi(obj["firsttime"])
	} else {
		ap = vars.AccessPoints[obj["bssid"]]
		ap.RangeIP = obj["rangeip"]
		ap.NetmaskIP = obj["netmaskip"]
		ap.GatewayIP = obj["gatewayip"]
	}

	// Update integer fields
	ap.Channel, _ = strconv.Atoi(obj["channel"])
	ap.SignalDBM, _ = strconv.Atoi(obj["signal_dbm"])
	ap.MinSignalDBM, _ = strconv.Atoi(obj["minsignal_dbm"])
	ap.MaxSignalDBM, _ = strconv.Atoi(obj["maxsignal_dbm"])

	llcpackets, _ := strconv.Atoi(obj["llcpackets"])
	datapackets, _ := strconv.Atoi(obj["datapackets"])
	ap.NumPackets = llcpackets + datapackets

	lasttime, _ := strconv.Atoi(obj["lasttime"])
	if ap.LastTime < lasttime {
		ap.LastTime = lasttime
	}

	// Update accessPoints array
	vars.AccessPoints[obj["bssid"]] = ap
}

func (vars *KismetClient) processSSID(obj map[string]string) {
	if vars.debug {
		log.Printf("[processSSID]: %v\n", obj)
	}
	if obj["ssid"] != "" {
		var ssid Network
		_, exists := vars.Networks[obj["ssid"]]
		if !exists {
			ssid = Network{false, false, 0, 0, 0, "", map[string]int{}}
			ssid.FirstTime, _ = strconv.Atoi(obj["firsttime"])
		} else {
			ssid = vars.Networks[obj["ssid"]]
		}

		// Update fields
		ssid.Cloaked = false
		if obj["cloaked"] != "0" {
			ssid.Cloaked = true
		}

		lasttime, _ := strconv.Atoi(obj["lasttime"])
		if ssid.LastTime < lasttime {
			ssid.LastTime = lasttime
		}

		_, exists = ssid.BSSIDs[obj["mac"]]
		if !exists || ssid.BSSIDs[obj["mac"]] < lasttime {
			ssid.BSSIDs[obj["mac"]] = lasttime
		}

		vars.Networks[obj["ssid"]] = ssid

		// Update the access point, if exists
		_, exists = vars.AccessPoints[obj["mac"]]
		if exists {
			ap := vars.AccessPoints[obj["mac"]]
			ap.SSID = obj["ssid"]
			vars.AccessPoints[obj["mac"]] = ap
		}

	}
}

func (vars *KismetClient) processCLISRC(obj map[string]string) {
	if vars.debug {
		log.Printf("[processCLISRC]: %v\n", obj)
	}
}

func (vars *KismetClient) processNETTAG(obj map[string]string) {
	if vars.debug {
		log.Printf("[processNETTAG]: %v\n", obj)
	}
}

func (vars *KismetClient) processCLITAG(obj map[string]string) {
	if vars.debug {
		log.Printf("[processCLITAG]: %v\n", obj)
	}
}

func (vars *KismetClient) processCLIENT(obj map[string]string) {
	if vars.debug {
		log.Printf("[processCLIENT]: %v\n", obj)
	}
	if obj["bssid"] != obj["mac"] {
		var clnt Client
		_, exists := vars.Clients[obj["mac"]]
		if !exists {
			clnt = Client{obj["bssid"], 0, 0, 0, 0, 0, 0}
		} else {
			clnt = vars.Clients[obj["mac"]]
			clnt.BSSID = obj["bssid"]
		}

		if clnt.FirstTime == 0 {
			clnt.FirstTime, _ = strconv.Atoi(obj["firsttime"])
		}

		lasttime, _ := strconv.Atoi(obj["lasttime"])
		if clnt.LastTime < lasttime {
			clnt.LastTime = lasttime
		}

		clnt.SignalDBM, _ = strconv.Atoi(obj["signal_dbm"])
		clnt.MinSignalDBM, _ = strconv.Atoi(obj["minsignal_dbm"])
		clnt.MaxSignalDBM, _ = strconv.Atoi(obj["maxsignal_dbm"])

		llcpackets, _ := strconv.Atoi(obj["llcpackets"])
		datapackets, _ := strconv.Atoi(obj["datapackets"])
		clnt.NumPackets = llcpackets + datapackets

		vars.Clients[obj["mac"]] = clnt
	}
}

func (vars *KismetClient) processTERMINATE(obj map[string]string) {
	if vars.debug {
		log.Printf("[processTERMINATE]: %v\n", obj)
	}
	fmt.Println(obj["message"] + ": " + obj["text"])
}
