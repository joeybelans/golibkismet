package client

import (
	"log"
)

// Initialize the package
func Init(debug bool) *KismetClient {
	return &KismetClient{
		debug:        debug,
		Networks:     make(map[string]Network),
		AccessPoints: make(map[string]AccessPoint),
		Clients:      make(map[string]Client),
		ssids:        make([]string, 0),
	}
}

// Listen for responses from kismet client interface
func (vars *KismetClient) Parser(field string, obj map[string]string) {
	c, found := vars.router(field)
	if found {
		c.(func(map[string]string))(obj)
	} else if vars.debug {
		log.Println("[KClient UNKNOWN Parser]: " + obj["message"])
	}
}

// Kismet response processors
func (vars *KismetClient) router(field string) (interface{}, bool) {
	if vars.debug {
		log.Printf("[KClient-Router]: %v\n", field)
	}
	var processors = map[string]interface{}{
		"ERROR":     vars.processERROR,
		"STATUS":    vars.processSTATUS,
		"SOURCE":    vars.processSOURCE,
		"INFO":      vars.processINFO,
		"ALERT":     vars.processALERT,
		"BSSIDSRC":  vars.processBSSIDSRC,
		"BSSID":     vars.processBSSID,
		"SSID":      vars.processSSID,
		"CLISRC":    vars.processCLISRC,
		"NETTAG":    vars.processNETTAG,
		"CLITAG":    vars.processCLITAG,
		"CLIENT":    vars.processCLIENT,
		"TERMINATE": vars.processTERMINATE,
		"GPS":       vars.processGPS,
	}
	if val, ok := processors[field]; ok {
		return val, ok
	}
	return nil, false
}
