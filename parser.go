package golibkismet

import (
	"encoding/json"
	"fmt"
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

func parseKISMET(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	Version = fields[1]
	StartTime = fields[2]
	Name = fields[3]
}

func parsePROTOCOLS(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	var found bool
	for _, protocol := range strings.Split(fields[1], ",") {
		if protocol != "PROTOCOLS" && protocol != "CAPABILITY" {
			_, found = parsers[protocol]
			if !found && debug {
				fmt.Println("No parser available for protocol: " + protocol)
			} else {
				send("CAPABILITY " + protocol)
			}
		}
	}
}

func parseCAPABILITY(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	var available []string
	_, found := parsers[fields[1]]
	if found {
		for _, field := range strings.Split(fields[2], ",") {
			available = append(available, field)
		}
		fmt.Println(fields[1] + ": " + strings.Join(available, ","))
		capabilities[fields[1]] = capability{available, []string{}}
	}
}

func parseTIME(fields []string) {
	if debug {
		fmt.Println(fields)
	}
	tstamp = fields[1]
}

func parseACK(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	i, _ := strconv.Atoi(fields[1])
	delete(requests, i)
	if debug {
		fmt.Println("ACK: " + fields[1])
		fmt.Println("PIPELINE:", requests)
	}
}

func parseERROR(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	er := map[string]string{"message": "ERROR"}
	for index, field := range capabilities["ERROR"].selected {
		er[field] = fields[index+1]
	}

	i, _ := strconv.Atoi(fields[1])
	delete(requests, i)
	if debug {
		fmt.Println("ERROR: " + fields[2])
		fmt.Println("PIPELINE:", requests)
	}

	msg, _ := json.Marshal(er)
	Responses <- msg
}

func parseSTATUS(fields []string) {
	if debug {
		fmt.Println(fields)
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
		if debug {
			fmt.Println("STATUS-OTHER: (" + status["flags"] + ") " + status["text"])
		}
		status["title"] = "STATUS-OTHER"
	}

	msg, _ := json.Marshal(status)
	Responses <- msg
}

func parseSOURCE(fields []string) {
	if debug {
		fmt.Println(fields)
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

	_, exists := interfaces[name]
	if !exists {
		iface, _ := net.InterfaceByName(fields[1])
		lock := false
		interfaces[name] = kismetInterface{source["uuid"], source["username"], iface.HardwareAddr.String(), source["type"], lock, velocity, packets, channel, channels}
	} else {
		nic := interfaces[name]
		nic.channel = channel
		lock := false
		nic.lock = lock
		nic.velocity = velocity
		nic.packets = packets
		nic.channels = channels
		interfaces[name] = nic
	}

	if source["warning"] != "" {
		msg, _ := json.Marshal(map[string]interface{}{
			"message": "NIC-WARNING",
			"name":    name,
			"index":   source["error"],
			"warning": source["warning"],
		})

		Responses <- msg
	}

	msg, _ := json.Marshal(source)
	Responses <- msg
}

func defaultParser(fields []string) {
	capability := map[string]string{"message": fields[0]}
	for index, field := range capabilities[fields[0]].selected {
		capability[field] = fields[index+1]
	}
	msg, _ := json.Marshal(capability)
	Responses <- msg
}

func parseINFO(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseALERT(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseBSSIDSRC(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseBSSID(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseSSID(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseCLISRC(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseNETTAG(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseCLITAG(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseCLIENT(fields []string) {
	if debug {
		fmt.Println(fields)
	}

	defaultParser(fields)
}

func parseTERMINATE(fields []string) {
	if debug {
		fmt.Println("TERMINATE")
	}

	defaultParser(fields)
}
