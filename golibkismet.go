// Kismet client interface
package golibkismet

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"time"
)

/* Steps to intialize the client
- Upon connection, server sends the version, name, and start time
- The server then sends the list of supported capabilities
- Client requests the fields assocaited with each capability
- Server responds with the fields associated with each capability
- Client enables specfic capabilities and the associated fields
- Server then sends messages associated with requested capabilities
*/

// Initialize the package
func init() {
	Version = ""
	StartTime = ""
	Name = ""
	server = serverConnection{"", 0, nil}
	debug = false
	tstamp = ""
	index = 0
}

// Connect to the kismet server and set the debug flag
func Connect(host string, port int, debugFlag bool) {
	// Save the host and port info
	server.host = host
	server.port = port

	// Set debug flag
	debug = debugFlag

	// Establish connection to kismet server
	var err error
	server.conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Fatal("Can't connect to kismet server")
	} else {
		// Process kismet commands/responses
		go listen()

		// Wait until the connection is initialized
		for tstamp == "" {
			time.Sleep(1 * time.Second)
		}
	}
}

// Listen and process kismet data
func listen() {
	// Continuously read data
	scanner := bufio.NewScanner(server.conn)
	re := regexp.MustCompile(`([^ \001]+|\001[^\001]*\001)`)
	for scanner.Scan() {
		status := scanner.Text()

		// Determine response type
		status = strings.TrimSpace(status)
		matches := re.FindAllStringSubmatch(status, -1)
		fields := parseFields(matches)
		c, found := parsers[fields[0]]
		if found {
			c.(func([]string))(fields)
		} else if fields[0] == "PROTOCOLS" {
			parsePROTOCOLS(fields)
		} else if fields[0] == "CAPABILITY" {
			parseCAPABILITY(fields)
		} else if debug {
			fmt.Println("UNKNOWN CMD: " + fields[0])
		}
	}
}
