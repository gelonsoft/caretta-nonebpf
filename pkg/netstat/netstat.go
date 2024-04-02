package netstat

import (
	"fmt"
	"log"
	"net"
)

// SockAddr represents an ip:port pair
type SockAddr struct {
	IP   net.IP
	Port uint16
}

var nullSockAddr = SockAddr{
	IP:   net.IPv4(0, 0, 0, 0),
	Port: 0,
}

func (s *SockAddr) String() string {
	return fmt.Sprintf("%v:%d", s.IP, s.Port)
}

// SockTabEntry type represents each line of the /proc/net/[tcp|udp]
type SockTabEntry struct {
	//ino        string
	LocalAddr  *SockAddr
	RemoteAddr *SockAddr
	State      SkState
	Role       int
}
type SockHostEntry struct {
	sockTab []SockTabEntry
	ipList  []net.IP
}

// Process holds the PID and process name to which each socket belongs
type Process struct {
	Pid  int
	Name string
}

func (p *Process) String() string {
	return fmt.Sprintf("%d/%s", p.Pid, p.Name)
}

// SkState type represents socket connection state
type SkState uint8

func (s SkState) String() string {
	return skStates[s]
}

// AcceptFn is used to filter socket entries. The value returned indicates
// whether the element is to be appended to the socket list.
type AcceptFn func(*SockTabEntry) bool

// NoopFilter - a test function returning true for all elements
func NoopFilter(*SockTabEntry) bool { return true }

func calcRoles(entries []SockHostEntry) ([]SockTabEntry, error) {
	result := make([]SockTabEntry, 0)
	for _, hostEntry := range entries {
		log.Printf("Start host entry")
		var localIPs = hostEntry.ipList
		var localListens = make([]SockAddr, 0)

		for _, e := range hostEntry.sockTab {
			if e.LocalAddr != nil && e.State.String() == "LISTEN" {
				if e.LocalAddr.IP.Equal(nullSockAddr.IP) {
					for _, localIP := range localIPs {
						localListens = append(localListens, SockAddr{IP: localIP, Port: e.LocalAddr.Port})
						//log.Printf("Append listen #1 entry " + localIP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)))
					}
				} else {
					localListens = append(localListens, *e.LocalAddr)
					//log.Printf("Append listen #2 entry " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)))
				}
			}
		}

		for i := range hostEntry.sockTab {
			e := &hostEntry.sockTab[i]
			if e.State.String() == "LISTEN" {
				continue
			}
			for _, localIpPort := range localListens {
				var isSrcListens = localIpPort.Port == e.LocalAddr.Port && localIpPort.IP.Equal(e.LocalAddr.IP)
				var isDstListens = localIpPort.Port == e.RemoteAddr.Port && localIpPort.IP.Equal(e.RemoteAddr.IP)
				if isSrcListens || isDstListens {
					e.Role = 2
					if isDstListens && !isSrcListens {
						//log.Printf("Before swap role=" + strconv.Itoa(e.Role) + " for " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)) + "->" + e.RemoteAddr.IP.String() + ":" + strconv.Itoa(int(e.RemoteAddr.Port)) + " cause listens " + localIpPort.IP.String() + ":" + strconv.Itoa(int(localIpPort.Port)))
						tempAddr := e.LocalAddr
						e.LocalAddr = e.RemoteAddr
						e.RemoteAddr = tempAddr
						//log.Printf("After swap entry role=" + strconv.Itoa(e.Role) + " for " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)) + "->" + e.RemoteAddr.IP.String() + ":" + strconv.Itoa(int(e.RemoteAddr.Port)) + " cause listens " + localIpPort.IP.String() + ":" + strconv.Itoa(int(localIpPort.Port)))
					} else {
						//log.Printf("Changed role=" + strconv.Itoa(e.Role) + " for " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)) + "->" + e.RemoteAddr.IP.String() + ":" + strconv.Itoa(int(e.RemoteAddr.Port)) + " cause listens " + localIpPort.IP.String() + ":" + strconv.Itoa(int(localIpPort.Port)))
					}
				}
			}
			//log.Printf("Done connection role=" + strconv.Itoa(e.Role) + " for " + e.LocalAddr.IP.String() + ":" + strconv.Itoa(int(e.LocalAddr.Port)) + "->" + e.RemoteAddr.IP.String() + ":" + strconv.Itoa(int(e.RemoteAddr.Port)))
			result = append(result, *e)
		}
	}

	return result, nil
}

// TCPSocks returns a slice of active TCP sockets containing only those
// elements that satisfy the accept function
func TCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	hostEntries, err := osTCPSocks(accept)
	if err != nil {
		return nil, nil
	}
	return calcRoles(hostEntries)
}

// TCP6Socks returns a slice of active TCP IPv4 sockets containing only those
// elements that satisfy the accept function
func TCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	hostEntries, err := osTCP6Socks(accept)
	if err != nil {
		return nil, nil
	}
	return calcRoles(hostEntries)
}

// UDPSocks returns a slice of active UDP sockets containing only those
// elements that satisfy the accept function
func UDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	hostEntries, err := osUDPSocks(accept)
	if err != nil {
		return nil, nil
	}
	return calcRoles(hostEntries)
}

// UDP6Socks returns a slice of active UDP IPv6 sockets containing only those
// elements that satisfy the accept function
func UDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	hostEntries, err := osUDP6Socks(accept)
	if err != nil {
		return nil, nil
	}
	return calcRoles(hostEntries)
}
