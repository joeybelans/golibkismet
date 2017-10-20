// Kismet client interface
package server

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
func Init(ldebug bool, host string, port int, client map[string][]string) *KismetVars {
	// Save the host and port info
	server := &serverConnection{
		host: host,
		port: port,
	}
	return &KismetVars{
		version:    "",
		startTime:  "",
		name:       "",
		responses:  make(chan []byte, 5),
		requests:   make(map[int]string),
		interfaces: make(map[string]kismetInterface),
		server:     *server,
		debug:      ldebug,
		dumpfiles:  make([]string, 0),
		tstamp:     "",
		index:      0,
		client:     client,
	}
}

// Connect to the kismet server and set the debug flag
func (vars *KismetVars) Connect() {
	// Establish connection to kismet server
	var err error
	vars.server.conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", vars.server.host, vars.server.port))
	if err != nil {
		log.Fatal("Can't connect to kismet server")
	} else {
		// Process kismet commands/responses
		go vars.listen()

		// Wait until the connection is initialized
		if vars.tstamp == "" {
			time.Sleep(1 * time.Second)
		}
	}
}

// Listen and process kismet data
func (vars *KismetVars) listen() {
	// Continuously read data
	scanner := bufio.NewScanner(vars.server.conn)
	re := regexp.MustCompile(`([^ \001]+|\001[^\001]*\001)`)
	for scanner.Scan() {
		status := scanner.Text()

		// Determine response type
		status = strings.TrimSpace(status)
		matches := re.FindAllStringSubmatch(status, -1)
		fields := parseFields(matches)
		c, found := vars.router(fields[0])
		if found {
			c.(func([]string))(fields)
		} else if fields[0] == "PROTOCOLS" {
			vars.parsePROTOCOLS(fields)
		} else if fields[0] == "CAPABILITY" {
			vars.parseCAPABILITY(fields)
		} else if vars.debug {
			log.Println("[Kismet UNKNOWN CMD]: " + fields[0])
		}
	}
}
