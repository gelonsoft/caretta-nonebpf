package caretta

import (
	"encoding/binary"
	"fmt"
	"github.com/cakturk/go-netstat/netstat"
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
	socks, err := netstat.TCPSocks(netstat.NoopFilter)
	if err != nil {
		return Probes{}, nil, fmt.Errorf("error query tcp socks - %v", err)
	}
	for _, e := range socks {
		var conn1 = ConnectionIdentifier{
			Id:  1,
			Pid: 1,
			Tuple: ConnectionTuple{
				DstIp:   binary.BigEndian.Uint32(e.RemoteAddr.IP),
				SrcIp:   binary.BigEndian.Uint32(e.LocalAddr.IP),
				DstPort: e.RemoteAddr.Port,
				SrcPort: e.LocalAddr.Port,
			},
			Role: ServerConnectionRole,
		}
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
