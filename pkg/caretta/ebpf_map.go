package caretta

import (
	"errors"
)

type IEbpfMapIterator interface {
	Next(interface{}, interface{}) bool
}

type IEbpfMap interface {
	Lookup(interface{}, interface{}) error
	Iterate() IEbpfMapIterator
	Delete(interface{}) error
}

type EbpfMap struct {
	innerMap map[ConnectionIdentifier]ConnectionThroughputStats
}

type EbpfMapIterator struct {
	innerMap map[ConnectionIdentifier]ConnectionThroughputStats
	keys     []ConnectionIdentifier
	count    int
}

func NewEbpfMap() *EbpfMap {
	return &EbpfMap{innerMap: make(map[ConnectionIdentifier]ConnectionThroughputStats)}
}

func (m *EbpfMap) Lookup(conn interface{}, throughput interface{}) error {
	assertedConn, ok := conn.(*ConnectionIdentifier)
	if !ok {
		return errors.New("wrong type for Lookup")
	}
	assertedThroughput, ok := throughput.(*ConnectionThroughputStats)
	if !ok {
		return errors.New("wrong type for Lookup")
	}
	*assertedThroughput, ok = m.innerMap[*assertedConn]
	if !ok {
		return errors.New("Key not in map")
	}
	return nil
}

func (m *EbpfMap) Iterate() IEbpfMapIterator {
	keys := make([]ConnectionIdentifier, 0, len(m.innerMap))
	for ci := range m.innerMap {
		keys = append(keys, ci)
	}

	return &EbpfMapIterator{innerMap: m.innerMap, keys: keys, count: 0}
}

func (m *EbpfMap) Delete(key interface{}) error {
	assertedKey, ok := key.(*ConnectionIdentifier)
	if !ok {
		return errors.New("wrong type in delete")
	}
	delete(m.innerMap, *assertedKey)
	return nil
}

func (m *EbpfMap) Update(key ConnectionIdentifier, value ConnectionThroughputStats) {
	m.innerMap[key] = value
}

func (mi *EbpfMapIterator) Next(conn interface{}, throughput interface{}) bool {
	assertedConn, ok := conn.(*ConnectionIdentifier)
	if !ok {
		return false
	}
	assertedThroughput, ok := throughput.(*ConnectionThroughputStats)
	if !ok {
		return false
	}
	for mi.count < len(mi.keys) {
		*assertedConn = mi.keys[mi.count]
		*assertedThroughput = mi.innerMap[*assertedConn]
		mi.count++
		return true
	}

	return false
}
