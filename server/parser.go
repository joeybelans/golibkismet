package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

func parseFields(matches [][]string) []string {
	var params []string

	cmd := strings.TrimRight(strings.TrimLeft(matches[0][0], "*"), ":")
	params = append(params, cmd)

	for i := 1; i < len(matches); i++ {
		txt := matches[i][0]
		txt = strings.Trim(txt, "\001")
		txt = strings.TrimSpace(txt)
		params = append(params, txt)
	}

	return params
}

func (vars *KismetVars) parseKISMET(fields []string) {
	if vars.debug {
		log.Printf("[parseKISMET]: %v\n", fields)
	}

	vars.version = fields[1]
	vars.startTime = fields[2]
	vars.name = fields[3]
}

func (vars *KismetVars) parsePROTOCOLS(fields []string) {
	if vars.debug {
		log.Printf("[parsePROTOCOLS]: %v\n", fields)
	}

	var found bool
	for _, protocol := range strings.Split(fields[1], ",") {
		if protocol != "PROTOCOLS" && protocol != "CAPABILITY" {
			_, found = vars.router(protocol)
			if !found && vars.debug {
				fmt.Println("No parser available for protocol: " + protocol)
			} else {
				vars.send("CAPABILITY " + protocol)
			}
		}
	}
}

func (vars *KismetVars) parseCAPABILITY(fields []string) {
	if vars.debug {
		log.Printf("[parseCAPABILITY]: %v\n", fields)
	}

	var available []string
	_, found := vars.router(fields[1])
	if found {
		for _, field := range strings.Split(fields[2], ",") {
			available = append(available, field)
		}
		if vars.debug {
			log.Printf("[CAPABILITY LIST]: %v\n", strings.Join(available, ","))
		}
		capabilities[fields[1]] = capability{available, []string{}}

		// Enable client settings after validating capabilties
		if len(vars.client) > 0 {
			vars.enable(fields[1], vars.client[fields[1]])
		}
	}
}

func (vars *KismetVars) parseTIME(fields []string) {
	if vars.debug {
		log.Printf("[parseTIME]: %v\n", fields)
	}
	vars.tstamp = fields[1]
}

func (vars *KismetVars) parseACK(fields []string) {
	if vars.debug {
		log.Printf("[parseACK]: %v\n", fields)
	}

	i, _ := strconv.Atoi(fields[1])
	delete(vars.requests, i)
	if vars.debug {
		log.Printf("[ACK RECEIVED]: %v\n", fields[1])
		log.Printf("[ACK PIPELINE]: %v\n", vars.requests)
	}
}

func (vars *KismetVars) parseERROR(fields []string) {
	if vars.debug {
		log.Printf("[parseERROR]: %v\n", fields)
	}

	er := map[string]string{"message": "ERROR"}
	for index, field := range capabilities["ERROR"].selected {
		er[field] = fields[index+1]
	}

	i, _ := strconv.Atoi(fields[1])
	delete(vars.requests, i)
	if vars.debug {
		log.Printf("[ERROR ERROR]: %v\n", fields[2])
		log.Printf("[ERROR PIPELINE]: %v\n", vars.requests)
	}

	msg, _ := json.Marshal(er)
	vars.responses <- msg
}

func (vars *KismetVars) parseSTATUS(fields []string) {
	if vars.debug {
		log.Printf("[parseSTATUS]: %v\n", fields)
	}

	status := map[string]string{"message": "STATUS"}
	for index, field := range capabilities["STATUS"].selected {
		status[field] = fields[index+1]
	}

	switch {
	case status["flags"] == "2":
		status["title"] = "STATUS-INFO"

	case fields[2] == "4":
		status["title"] = "STATUS-ERROR"

	default:
		if vars.debug {
			log.Printf("[STATUS-OTHER]: (%v) %v\n", status["flags"], status["test"])
		}
		status["title"] = "STATUS-OTHER"
	}

	msg, _ := json.Marshal(status)
	vars.responses <- msg
}

func (vars *KismetVars) parseSOURCE(fields []string) {
	if vars.debug {
		log.Printf("[parseSOURCE]: %v\n", fields)
	}

	source := map[string]string{"message": "SOURCE"}
	for index, field := range capabilities["SOURCE"].selected {
		source[field] = fields[index+1]
	}

	name := source["interface"]
	velocity, _ := strconv.Atoi(source["velocity"])
	packets, _ := strconv.Atoi(source["packets"])
	channel, _ := strconv.Atoi(source["channel"])
	channels := []int{}
	for _, chStr := range strings.Split(source["channellist"], ",") {
		chInt, _ := strconv.Atoi(chStr)
		channels = append(channels, chInt)
	}

	_, exists := vars.interfaces[name]
	if !exists {
		iface, _ := net.InterfaceByName(fields[1])
		lock := false
		vars.interfaces[name] = kismetInterface{source["uuid"], source["username"], iface.HardwareAddr.String(), source["type"], lock, velocity, packets, channel, channels}
	} else {
		nic := vars.interfaces[name]
		nic.channel = channel
		lock := false
		nic.lock = lock
		nic.velocity = velocity
		nic.packets = packets
		nic.channels = channels
		vars.interfaces[name] = nic
	}

	if source["warning"] != "" {
		msg, _ := json.Marshal(map[string]interface{}{
			"message": "NIC-WARNING",
			"name":    name,
			"index":   source["error"],
			"warning": source["warning"],
		})

		vars.responses <- msg
	}

	msg, _ := json.Marshal(source)
	vars.responses <- msg
}

func (vars *KismetVars) defaultParser(fields []string) {
	capability := map[string]string{"message": fields[0]}
	for index, field := range capabilities[fields[0]].selected {
		capability[field] = fields[index+1]
	}
	msg, _ := json.Marshal(capability)
	vars.responses <- msg
}

func (vars *KismetVars) parseGPS(fields []string) {
	if vars.debug {
		log.Printf("[parseGPS]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseINFO(fields []string) {
	if vars.debug {
		log.Printf("[parseINFO]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseALERT(fields []string) {
	if vars.debug {
		log.Printf("[parseALERT]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseBSSIDSRC(fields []string) {
	if vars.debug {
		log.Printf("[parseBSSIDSRC]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseBSSID(fields []string) {
	if vars.debug {
		log.Printf("[parseBSSID]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseSSID(fields []string) {
	if vars.debug {
		log.Printf("[parseSSID]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseCLISRC(fields []string) {
	if vars.debug {
		log.Printf("[parseCLISRC]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseNETTAG(fields []string) {
	if vars.debug {
		log.Printf("[parseNETTAG]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseCLITAG(fields []string) {
	if vars.debug {
		log.Printf("[parseCLITAG]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseCLIENT(fields []string) {
	if vars.debug {
		log.Printf("[parseCLIENT]: %v\n", fields)
	}

	vars.defaultParser(fields)
}

func (vars *KismetVars) parseTERMINATE(fields []string) {
	if vars.debug {
		log.Println("[parseTERMINATE]: TERMINATE")
	}

	vars.defaultParser(fields)
}
