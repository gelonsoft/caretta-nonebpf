package caretta

import (
	"encoding/binary"
	"fmt"
	"github.com/gelonsoft/caretta/pkg/netstat"
	"log"
	"net"
)

type Probes struct {
}

var activeThroughput = ConnectionThroughputStats{
	BytesSent:     1,
	BytesReceived: 1,
	IsActive:      1,
}

var inactiveThroughput = ConnectionThroughputStats{
	BytesSent:     1,
	BytesReceived: 1,
	IsActive:      1,
}
var nullSockAddr = &netstat.SockAddr{
	IP:   net.IPv4(0, 0, 0, 0),
	Port: 0,
}
var nullPid = &netstat.Process{
	Pid: -1,
}

func LoadProbes() (Probes, map[ConnectionIdentifier]ConnectionThroughputStats, error) {

	var conns = make(map[ConnectionIdentifier]ConnectionThroughputStats)

	// TCP sockets
	//var socks []netstat.SockTabEntry
	//log.Printf("Started probe")
	socks, err := netstat.TCPSocks(netstat.NoopFilter)

	if err != nil {
		return Probes{}, nil, fmt.Errorf("error query tcp socks - %v", err)
	}
	log.Printf("Probe done, found %d tcp links", len(socks))

	for _, e := range socks {
		conns[ConnectionIdentifier{
			Tuple: ConnectionTuple{
				DstIp:   binary.LittleEndian.Uint32(e.RemoteAddr.IP),
				SrcIp:   binary.LittleEndian.Uint32(e.LocalAddr.IP),
				DstPort: e.RemoteAddr.Port,
				SrcPort: e.LocalAddr.Port,
			},
			Role:     uint32(e.Role),
			LinkType: 0,
		}] = activeThroughput
	}

	socks, err = netstat.TCP6Socks(netstat.NoopFilter)

	if err != nil {
		return Probes{}, nil, fmt.Errorf("error query tcp socks - %v", err)
	}
	log.Printf("Probe done, found %d tcp6 links", len(socks))

	for _, e := range socks {
		conns[ConnectionIdentifier{
			Tuple: ConnectionTuple{
				DstIp:   binary.LittleEndian.Uint32(e.RemoteAddr.IP.To4()),
				SrcIp:   binary.LittleEndian.Uint32(e.LocalAddr.IP.To4()),
				DstPort: e.RemoteAddr.Port,
				SrcPort: e.LocalAddr.Port,
			},
			Role:     uint32(e.Role),
			LinkType: 1,
		}] = activeThroughput
		//log.Printf("ConnectionIdentifier create " + e.RemoteAddr.IP.String() + "<-" + e.LocalAddr.IP.String() + " = " + strconv.Itoa(int(binary.LittleEndian.Uint32(e.RemoteAddr.IP.To4()))) + "<-" + strconv.Itoa(int(binary.LittleEndian.Uint32(e.LocalAddr.IP.To4()))))
	}

	return Probes{}, conns, nil
}

func (objs *Probes) UnloadProbes() error {
	// if any close operation fails, will continue to try closing the rest of the struct,
	// and return the first error
	var resultErr error
	resultErr = nil

	return resultErr
}
