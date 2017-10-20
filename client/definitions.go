package client

// Package variables
type KismetClient struct {
	debug        bool
	Networks     map[string]Network
	AccessPoints map[string]AccessPoint
	Clients      map[string]Client
	GPS          GPS
	ssids        []string
}

// Packet statistics
type packetStats struct {
	Total    int
	Rate     int
	Crypt    int
	Dropped  int
	Filtered int
	Mgmt     int
	Data     int
}

// Access point object
type AccessPoint struct {
	ApType       string
	SSID         string
	Manuf        string
	Channel      int
	FirstTime    int
	LastTime     int
	Atype        int
	RangeIP      string
	NetmaskIP    string
	GatewayIP    string
	SignalDBM    int
	MinSignalDBM int
	MaxSignalDBM int
	NumPackets   int
}

// Wireless network object
type Network struct {
	Inscope    bool
	Cloaked    bool
	FirstTime  int
	LastTime   int
	Maxrate    int
	Encryption string
	BSSIDs     map[string]int
}

// Wireless client object
type Client struct {
	BSSID        string
	FirstTime    int
	LastTime     int
	SignalDBM    int
	MinSignalDBM int
	MaxSignalDBM int
	NumPackets   int
}

// Packet statistics
type GPS struct {
	LAT     float64
	LON     float64
	ALT     int
	SPD     int
	Heading int
	Fix     int
	// satinfo
	// hdop
	// vdop
	Connected bool
}
