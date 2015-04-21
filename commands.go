package golibkismet

import (
	"fmt"
	"strings"
)

// Send command to kismet server
// Add the command to the pipeline
// Increase the command index number
func send(cmd string) {
	requests[index] = cmd
	cmdstr := fmt.Sprintf("!%d ", index) + cmd
	if debug {
		fmt.Println("SEND: " + cmdstr)
	}
	server.conn.Write([]byte(cmdstr + "\n"))
	index += 1
}

// Enable specified protocol and include the requested fields
func Enable(protocol string, fields []string) {
	var valid bool

	// Store the selected fields, in the order requested, with the capability to correctly parse the responses
	selected := []string{}
	for _, sField := range fields {
		valid = false
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
		send("ENABLE " + protocol + " " + strings.Join(fields, ","))
	}
}

// Disable the specified protocol
func Disable(protocol string) {
	send("REMOVE " + protocol)
}

// Add network card as kismet source
func AddSource(nic string, alias string) {
	cmd := "ADDSOURCE " + nic
	if alias != "" {
		cmd = cmd + ":name=" + alias
	}
	send(cmd)
}

// Remove network card as kismet source
// WARNING: this causes kismet to sigfault
func DelSource(nic string) {
	cmd := "DELSOURCE " + interfaces[nic].uid
	send(cmd)
}

// Hop specified channels at the specified velocity (channels/sec) on the specified network card
func ChannelHop(nic string, velocity int, channels []int) {
	uid := interfaces[nic].uid

	var chArray []string
	for _, value := range channels {
		chArray = append(chArray, string(value))
	}

	send("CHANSOURCE " + uid + " " + strings.Join(chArray, ","))
	send("HOPSOURCE " + uid + " HOP " + string(velocity))
}

// Lock on specified channel on the specified network card
func ChannelLock(nic string, channel int) {
	send("HOPSOURCE " + interfaces[nic].uid + " LOCK " + string(channel))
}

// Shutdown kismet
func KillServer() {
	send("SHUTDOWN")
}
