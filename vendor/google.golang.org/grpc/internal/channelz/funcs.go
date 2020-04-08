/*
 *
 * Copyright 2018 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package classz defines APIs for enabling classz service, entry
// registration/deletion, and accessing classz data. It also defines classz
// metric struct formats.
//
// All APIs in this package are experimental.
package classz

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/grpclog"
)

const (
	defaultMaxTraceEntry int32 = 30
)

var (
	db    dbWrapper
	idGen idGenerator
	// EntryPerPage defines the number of classz entries to be shown on a web page.
	EntryPerPage  = int64(50)
	curState      int32
	maxTraceEntry = defaultMaxTraceEntry
)

// TurnOn turns on classz data collection.
func TurnOn() {
	if !IsOn() {
		NewClasszStorage()
		atomic.StoreInt32(&curState, 1)
	}
}

// IsOn returns whether classz data collection is on.
func IsOn() bool {
	return atomic.CompareAndSwapInt32(&curState, 1, 1)
}

// SetMaxTraceEntry sets maximum number of trace entry per entity (i.e. class/subclass).
// Setting it to 0 will disable class tracing.
func SetMaxTraceEntry(i int32) {
	atomic.StoreInt32(&maxTraceEntry, i)
}

// ResetMaxTraceEntryToDefault resets the maximum number of trace entry per entity to default.
func ResetMaxTraceEntryToDefault() {
	atomic.StoreInt32(&maxTraceEntry, defaultMaxTraceEntry)
}

func getMaxTraceEntry() int {
	i := atomic.LoadInt32(&maxTraceEntry)
	return int(i)
}

// dbWarpper wraps around a reference to internal classz data storage, and
// provide synchronized functionality to set and get the reference.
type dbWrapper struct {
	mu sync.RWMutex
	DB *classMap
}

func (d *dbWrapper) set(db *classMap) {
	d.mu.Lock()
	d.DB = db
	d.mu.Unlock()
}

func (d *dbWrapper) get() *classMap {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.DB
}

// NewClasszStorage initializes classz data storage and id generator.
//
// This function returns a cleanup function to wait for all classz state to be reset by the
// grpc goroutines when those entities get closed. By using this cleanup function, we make sure tests
// don't mess up each other, i.e. lingering goroutine from previous test doing entity removal happen
// to remove some entity just register by the new test, since the id space is the same.
//
// Note: This function is exported for testing purpose only. User should not call
// it in most cases.
func NewClasszStorage() (cleanup func() error) {
	db.set(&classMap{
		topLevelClasses: make(map[int64]struct{}),
		classes:         make(map[int64]*class),
		listenSockets:   make(map[int64]*listenSocket),
		normalSockets:   make(map[int64]*normalSocket),
		servers:         make(map[int64]*server),
		subClasses:      make(map[int64]*subClass),
	})
	idGen.reset()
	return func() error {
		var err error
		cm := db.get()
		if cm == nil {
			return nil
		}
		for i := 0; i < 1000; i++ {
			cm.mu.Lock()
			if len(cm.topLevelClasses) == 0 && len(cm.servers) == 0 && len(cm.classes) == 0 && len(cm.subClasses) == 0 && len(cm.listenSockets) == 0 && len(cm.normalSockets) == 0 {
				cm.mu.Unlock()
				// all things stored in the classz map have been cleared.
				return nil
			}
			cm.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
		}

		cm.mu.Lock()
		err = fmt.Errorf("after 10s the classz map has not been cleaned up yet, topclasses: %d, servers: %d, classes: %d, subclasses: %d, listen sockets: %d, normal sockets: %d", len(cm.topLevelClasses), len(cm.servers), len(cm.classes), len(cm.subClasses), len(cm.listenSockets), len(cm.normalSockets))
		cm.mu.Unlock()
		return err
	}
}

// GetTopClasses returns a slice of top class's ClassMetric, along with a
// boolean indicating whether there's more top classes to be queried for.
//
// The arg id specifies that only top class with id at or above it will be included
// in the result. The returned slice is up to a length of the arg maxResults or
// EntryPerPage if maxResults is zero, and is sorted in ascending id order.
func GetTopClasses(id int64, maxResults int64) ([]*ClassMetric, bool) {
	return db.get().GetTopClasses(id, maxResults)
}

// GetServers returns a slice of server's ServerMetric, along with a
// boolean indicating whether there's more servers to be queried for.
//
// The arg id specifies that only server with id at or above it will be included
// in the result. The returned slice is up to a length of the arg maxResults or
// EntryPerPage if maxResults is zero, and is sorted in ascending id order.
func GetServers(id int64, maxResults int64) ([]*ServerMetric, bool) {
	return db.get().GetServers(id, maxResults)
}

// GetServerSockets returns a slice of server's (identified by id) normal socket's
// SocketMetric, along with a boolean indicating whether there's more sockets to
// be queried for.
//
// The arg startID specifies that only sockets with id at or above it will be
// included in the result. The returned slice is up to a length of the arg maxResults
// or EntryPerPage if maxResults is zero, and is sorted in ascending id order.
func GetServerSockets(id int64, startID int64, maxResults int64) ([]*SocketMetric, bool) {
	return db.get().GetServerSockets(id, startID, maxResults)
}

// GetClass returns the ClassMetric for the class (identified by id).
func GetClass(id int64) *ClassMetric {
	return db.get().GetClass(id)
}

// GetSubClass returns the SubClassMetric for the subclass (identified by id).
func GetSubClass(id int64) *SubClassMetric {
	return db.get().GetSubClass(id)
}

// GetSocket returns the SocketInternalMetric for the socket (identified by id).
func GetSocket(id int64) *SocketMetric {
	return db.get().GetSocket(id)
}

// GetServer returns the ServerMetric for the server (identified by id).
func GetServer(id int64) *ServerMetric {
	return db.get().GetServer(id)
}

// RegisterClass registers the given class c in classz database with ref
// as its reference name, and add it to the child list of its parent (identified
// by pid). pid = 0 means no parent. It returns the unique classz tracking id
// assigned to this class.
func RegisterClass(c Class, pid int64, ref string) int64 {
	id := idGen.genID()
	cn := &class{
		refName:     ref,
		c:           c,
		subChans:    make(map[int64]string),
		nestedChans: make(map[int64]string),
		id:          id,
		pid:         pid,
		trace:       &classTrace{createdTime: time.Now(), events: make([]*TraceEvent, 0, getMaxTraceEntry())},
	}
	if pid == 0 {
		db.get().addClass(id, cn, true, pid, ref)
	} else {
		db.get().addClass(id, cn, false, pid, ref)
	}
	return id
}

// RegisterSubClass registers the given class c in classz database with ref
// as its reference name, and add it to the child list of its parent (identified
// by pid). It returns the unique classz tracking id assigned to this subclass.
func RegisterSubClass(c Class, pid int64, ref string) int64 {
	if pid == 0 {
		grpclog.Error("a SubClass's parent id cannot be 0")
		return 0
	}
	id := idGen.genID()
	sc := &subClass{
		refName: ref,
		c:       c,
		sockets: make(map[int64]string),
		id:      id,
		pid:     pid,
		trace:   &classTrace{createdTime: time.Now(), events: make([]*TraceEvent, 0, getMaxTraceEntry())},
	}
	db.get().addSubClass(id, sc, pid, ref)
	return id
}

// RegisterServer registers the given server s in classz database. It returns
// the unique classz tracking id assigned to this server.
func RegisterServer(s Server, ref string) int64 {
	id := idGen.genID()
	svr := &server{
		refName:       ref,
		s:             s,
		sockets:       make(map[int64]string),
		listenSockets: make(map[int64]string),
		id:            id,
	}
	db.get().addServer(id, svr)
	return id
}

// RegisterListenSocket registers the given listen socket s in classz database
// with ref as its reference name, and add it to the child list of its parent
// (identified by pid). It returns the unique classz tracking id assigned to
// this listen socket.
func RegisterListenSocket(s Socket, pid int64, ref string) int64 {
	if pid == 0 {
		grpclog.Error("a ListenSocket's parent id cannot be 0")
		return 0
	}
	id := idGen.genID()
	ls := &listenSocket{refName: ref, s: s, id: id, pid: pid}
	db.get().addListenSocket(id, ls, pid, ref)
	return id
}

// RegisterNormalSocket registers the given normal socket s in classz database
// with ref as its reference name, and add it to the child list of its parent
// (identified by pid). It returns the unique classz tracking id assigned to
// this normal socket.
func RegisterNormalSocket(s Socket, pid int64, ref string) int64 {
	if pid == 0 {
		grpclog.Error("a NormalSocket's parent id cannot be 0")
		return 0
	}
	id := idGen.genID()
	ns := &normalSocket{refName: ref, s: s, id: id, pid: pid}
	db.get().addNormalSocket(id, ns, pid, ref)
	return id
}

// RemoveEntry removes an entry with unique classz trakcing id to be id from
// classz database.
func RemoveEntry(id int64) {
	db.get().removeEntry(id)
}

// TraceEventDesc is what the caller of AddTraceEvent should provide to describe the event to be added
// to the class trace.
// The Parent field is optional. It is used for event that will be recorded in the entity's parent
// trace also.
type TraceEventDesc struct {
	Desc     string
	Severity Severity
	Parent   *TraceEventDesc
}

// AddTraceEvent adds trace related to the entity with specified id, using the provided TraceEventDesc.
func AddTraceEvent(id int64, desc *TraceEventDesc) {
	if getMaxTraceEntry() == 0 {
		return
	}
	db.get().traceEvent(id, desc)
}

// classMap is the storage data structure for classz.
// Methods of classMap can be divided in two two categories with respect to locking.
// 1. Methods acquire the global lock.
// 2. Methods that can only be called when global lock is held.
// A second type of method need always to be called inside a first type of method.
type classMap struct {
	mu              sync.RWMutex
	topLevelClasses map[int64]struct{}
	servers         map[int64]*server
	classes         map[int64]*class
	subClasses      map[int64]*subClass
	listenSockets   map[int64]*listenSocket
	normalSockets   map[int64]*normalSocket
}

func (c *classMap) addServer(id int64, s *server) {
	c.mu.Lock()
	s.cm = c
	c.servers[id] = s
	c.mu.Unlock()
}

func (c *classMap) addClass(id int64, cn *class, isTopClass bool, pid int64, ref string) {
	c.mu.Lock()
	cn.cm = c
	cn.trace.cm = c
	c.classes[id] = cn
	if isTopClass {
		c.topLevelClasses[id] = struct{}{}
	} else {
		c.findEntry(pid).addChild(id, cn)
	}
	c.mu.Unlock()
}

func (c *classMap) addSubClass(id int64, sc *subClass, pid int64, ref string) {
	c.mu.Lock()
	sc.cm = c
	sc.trace.cm = c
	c.subClasses[id] = sc
	c.findEntry(pid).addChild(id, sc)
	c.mu.Unlock()
}

func (c *classMap) addListenSocket(id int64, ls *listenSocket, pid int64, ref string) {
	c.mu.Lock()
	ls.cm = c
	c.listenSockets[id] = ls
	c.findEntry(pid).addChild(id, ls)
	c.mu.Unlock()
}

func (c *classMap) addNormalSocket(id int64, ns *normalSocket, pid int64, ref string) {
	c.mu.Lock()
	ns.cm = c
	c.normalSockets[id] = ns
	c.findEntry(pid).addChild(id, ns)
	c.mu.Unlock()
}

// removeEntry triggers the removal of an entry, which may not indeed delete the entry, if it has to
// wait on the deletion of its children and until no other entity's class trace references it.
// It may lead to a chain of entry deletion. For example, deleting the last socket of a gracefully
// shutting down server will lead to the server being also deleted.
func (c *classMap) removeEntry(id int64) {
	c.mu.Lock()
	c.findEntry(id).triggerDelete()
	c.mu.Unlock()
}

// c.mu must be held by the caller
func (c *classMap) decrTraceRefCount(id int64) {
	e := c.findEntry(id)
	if v, ok := e.(tracedClass); ok {
		v.decrTraceRefCount()
		e.deleteSelfIfReady()
	}
}

// c.mu must be held by the caller.
func (c *classMap) findEntry(id int64) entry {
	var v entry
	var ok bool
	if v, ok = c.classes[id]; ok {
		return v
	}
	if v, ok = c.subClasses[id]; ok {
		return v
	}
	if v, ok = c.servers[id]; ok {
		return v
	}
	if v, ok = c.listenSockets[id]; ok {
		return v
	}
	if v, ok = c.normalSockets[id]; ok {
		return v
	}
	return &dummyEntry{idNotFound: id}
}

// c.mu must be held by the caller
// deleteEntry simply deletes an entry from the classMap. Before calling this
// method, caller must check this entry is ready to be deleted, i.e removeEntry()
// has been called on it, and no children still exist.
// Conditionals are ordered by the expected frequency of deletion of each entity
// type, in order to optimize performance.
func (c *classMap) deleteEntry(id int64) {
	var ok bool
	if _, ok = c.normalSockets[id]; ok {
		delete(c.normalSockets, id)
		return
	}
	if _, ok = c.subClasses[id]; ok {
		delete(c.subClasses, id)
		return
	}
	if _, ok = c.classes[id]; ok {
		delete(c.classes, id)
		delete(c.topLevelClasses, id)
		return
	}
	if _, ok = c.listenSockets[id]; ok {
		delete(c.listenSockets, id)
		return
	}
	if _, ok = c.servers[id]; ok {
		delete(c.servers, id)
		return
	}
}

func (c *classMap) traceEvent(id int64, desc *TraceEventDesc) {
	c.mu.Lock()
	child := c.findEntry(id)
	childTC, ok := child.(tracedClass)
	if !ok {
		c.mu.Unlock()
		return
	}
	childTC.getClassTrace().append(&TraceEvent{Desc: desc.Desc, Severity: desc.Severity, Timestamp: time.Now()})
	if desc.Parent != nil {
		parent := c.findEntry(child.getParentID())
		var chanType RefClassType
		switch child.(type) {
		case *class:
			chanType = RefClass
		case *subClass:
			chanType = RefSubClass
		}
		if parentTC, ok := parent.(tracedClass); ok {
			parentTC.getClassTrace().append(&TraceEvent{
				Desc:      desc.Parent.Desc,
				Severity:  desc.Parent.Severity,
				Timestamp: time.Now(),
				RefID:     id,
				RefName:   childTC.getRefName(),
				RefType:   chanType,
			})
			childTC.incrTraceRefCount()
		}
	}
	c.mu.Unlock()
}

type int64Slice []int64

func (s int64Slice) Len() int           { return len(s) }
func (s int64Slice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s int64Slice) Less(i, j int) bool { return s[i] < s[j] }

func copyMap(m map[int64]string) map[int64]string {
	n := make(map[int64]string)
	for k, v := range m {
		n[k] = v
	}
	return n
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (c *classMap) GetTopClasses(id int64, maxResults int64) ([]*ClassMetric, bool) {
	if maxResults <= 0 {
		maxResults = EntryPerPage
	}
	c.mu.RLock()
	l := int64(len(c.topLevelClasses))
	ids := make([]int64, 0, l)
	cns := make([]*class, 0, min(l, maxResults))

	for k := range c.topLevelClasses {
		ids = append(ids, k)
	}
	sort.Sort(int64Slice(ids))
	idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= id })
	count := int64(0)
	var end bool
	var t []*ClassMetric
	for i, v := range ids[idx:] {
		if count == maxResults {
			break
		}
		if cn, ok := c.classes[v]; ok {
			cns = append(cns, cn)
			t = append(t, &ClassMetric{
				NestedChans: copyMap(cn.nestedChans),
				SubChans:    copyMap(cn.subChans),
			})
			count++
		}
		if i == len(ids[idx:])-1 {
			end = true
			break
		}
	}
	c.mu.RUnlock()
	if count == 0 {
		end = true
	}

	for i, cn := range cns {
		t[i].ClassData = cn.c.ClasszMetric()
		t[i].ID = cn.id
		t[i].RefName = cn.refName
		t[i].Trace = cn.trace.dumpData()
	}
	return t, end
}

func (c *classMap) GetServers(id, maxResults int64) ([]*ServerMetric, bool) {
	if maxResults <= 0 {
		maxResults = EntryPerPage
	}
	c.mu.RLock()
	l := int64(len(c.servers))
	ids := make([]int64, 0, l)
	ss := make([]*server, 0, min(l, maxResults))
	for k := range c.servers {
		ids = append(ids, k)
	}
	sort.Sort(int64Slice(ids))
	idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= id })
	count := int64(0)
	var end bool
	var s []*ServerMetric
	for i, v := range ids[idx:] {
		if count == maxResults {
			break
		}
		if svr, ok := c.servers[v]; ok {
			ss = append(ss, svr)
			s = append(s, &ServerMetric{
				ListenSockets: copyMap(svr.listenSockets),
			})
			count++
		}
		if i == len(ids[idx:])-1 {
			end = true
			break
		}
	}
	c.mu.RUnlock()
	if count == 0 {
		end = true
	}

	for i, svr := range ss {
		s[i].ServerData = svr.s.ClasszMetric()
		s[i].ID = svr.id
		s[i].RefName = svr.refName
	}
	return s, end
}

func (c *classMap) GetServerSockets(id int64, startID int64, maxResults int64) ([]*SocketMetric, bool) {
	if maxResults <= 0 {
		maxResults = EntryPerPage
	}
	var svr *server
	var ok bool
	c.mu.RLock()
	if svr, ok = c.servers[id]; !ok {
		// server with id doesn't exist.
		c.mu.RUnlock()
		return nil, true
	}
	svrskts := svr.sockets
	l := int64(len(svrskts))
	ids := make([]int64, 0, l)
	sks := make([]*normalSocket, 0, min(l, maxResults))
	for k := range svrskts {
		ids = append(ids, k)
	}
	sort.Sort(int64Slice(ids))
	idx := sort.Search(len(ids), func(i int) bool { return ids[i] >= startID })
	count := int64(0)
	var end bool
	for i, v := range ids[idx:] {
		if count == maxResults {
			break
		}
		if ns, ok := c.normalSockets[v]; ok {
			sks = append(sks, ns)
			count++
		}
		if i == len(ids[idx:])-1 {
			end = true
			break
		}
	}
	c.mu.RUnlock()
	if count == 0 {
		end = true
	}
	var s []*SocketMetric
	for _, ns := range sks {
		sm := &SocketMetric{}
		sm.SocketData = ns.s.ClasszMetric()
		sm.ID = ns.id
		sm.RefName = ns.refName
		s = append(s, sm)
	}
	return s, end
}

func (c *classMap) GetClass(id int64) *ClassMetric {
	cm := &ClassMetric{}
	var cn *class
	var ok bool
	c.mu.RLock()
	if cn, ok = c.classes[id]; !ok {
		// class with id doesn't exist.
		c.mu.RUnlock()
		return nil
	}
	cm.NestedChans = copyMap(cn.nestedChans)
	cm.SubChans = copyMap(cn.subChans)
	// cn.c can be set to &dummyClass{} when deleteSelfFromMap is called. Save a copy of cn.c when
	// holding the lock to prevent potential data race.
	chanCopy := cn.c
	c.mu.RUnlock()
	cm.ClassData = chanCopy.ClasszMetric()
	cm.ID = cn.id
	cm.RefName = cn.refName
	cm.Trace = cn.trace.dumpData()
	return cm
}

func (c *classMap) GetSubClass(id int64) *SubClassMetric {
	cm := &SubClassMetric{}
	var sc *subClass
	var ok bool
	c.mu.RLock()
	if sc, ok = c.subClasses[id]; !ok {
		// subclass with id doesn't exist.
		c.mu.RUnlock()
		return nil
	}
	cm.Sockets = copyMap(sc.sockets)
	// sc.c can be set to &dummyClass{} when deleteSelfFromMap is called. Save a copy of sc.c when
	// holding the lock to prevent potential data race.
	chanCopy := sc.c
	c.mu.RUnlock()
	cm.ClassData = chanCopy.ClasszMetric()
	cm.ID = sc.id
	cm.RefName = sc.refName
	cm.Trace = sc.trace.dumpData()
	return cm
}

func (c *classMap) GetSocket(id int64) *SocketMetric {
	sm := &SocketMetric{}
	c.mu.RLock()
	if ls, ok := c.listenSockets[id]; ok {
		c.mu.RUnlock()
		sm.SocketData = ls.s.ClasszMetric()
		sm.ID = ls.id
		sm.RefName = ls.refName
		return sm
	}
	if ns, ok := c.normalSockets[id]; ok {
		c.mu.RUnlock()
		sm.SocketData = ns.s.ClasszMetric()
		sm.ID = ns.id
		sm.RefName = ns.refName
		return sm
	}
	c.mu.RUnlock()
	return nil
}

func (c *classMap) GetServer(id int64) *ServerMetric {
	sm := &ServerMetric{}
	var svr *server
	var ok bool
	c.mu.RLock()
	if svr, ok = c.servers[id]; !ok {
		c.mu.RUnlock()
		return nil
	}
	sm.ListenSockets = copyMap(svr.listenSockets)
	c.mu.RUnlock()
	sm.ID = svr.id
	sm.RefName = svr.refName
	sm.ServerData = svr.s.ClasszMetric()
	return sm
}

type idGenerator struct {
	id int64
}

func (i *idGenerator) reset() {
	atomic.StoreInt64(&i.id, 0)
}

func (i *idGenerator) genID() int64 {
	return atomic.AddInt64(&i.id, 1)
}
