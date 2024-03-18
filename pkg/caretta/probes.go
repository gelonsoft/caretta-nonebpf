package caretta

import (
	"encoding/binary"
	"fmt"
	"github.com/cakturk/go-netstat/netstat"
	"log"
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

func LoadProbes() (Probes, map[ConnectionIdentifier]ConnectionThroughputStats, error) {

	var conns = make(map[ConnectionIdentifier]ConnectionThroughputStats)

	// TCP sockets
	var socks []netstat.SockTabEntry
	log.Printf("Started probe")
	socks, err := netstat.TCPSocks(netstat.NoopFilter)

	if err != nil {
		return Probes{}, nil, fmt.Errorf("error query tcp socks - %v", err)
	}
	log.Printf("Probe done, found %d probes", len(socks))

	for _, e := range socks {
		var conn1 = ConnectionIdentifier{
			Id:  e.UID,
			Pid: uint32(e.Process.Pid),
			Tuple: ConnectionTuple{
				DstIp:   binary.BigEndian.Uint32(e.RemoteAddr.IP),
				SrcIp:   binary.BigEndian.Uint32(e.LocalAddr.IP),
				DstPort: e.RemoteAddr.Port,
				SrcPort: e.LocalAddr.Port,
			},
			Role: ClientConnectionRole,
		}
		log.Printf("Found link: %d p=%d %s:%d->%s:%d", conn1.Id, conn1.Pid, IP(conn1.Tuple.SrcIp).String(), conn1.Tuple.SrcIp, IP(conn1.Tuple.DstIp).String(), conn1.Tuple.DstPort)
		conns[conn1] = activeThroughput
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
