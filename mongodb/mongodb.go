// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package mongodb

import (
	"fmt"
	"github.com/gofrs/uuid"
	"reflect"
	"strings"
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/monitoring"

	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
)

var debugf = logp.MakeDebug("mongodb")

type mongodbPlugin struct {
	// config
	ports        []int
	sendRequest  bool
	sendResponse bool
	maxDocs      int
	maxDocLength int

	requests           *common.Cache
	responses          *common.Cache
	transactionTimeout time.Duration

	results protos.Reporter
	watcher procs.ProcessesWatcher
}

type transactionKey struct {
	tcp common.HashableTCPTuple
	id  int
}

var (
	unmatchedRequests = monitoring.NewInt(nil, "mongodb.unmatched_requests")
)

func init() {
	protos.Register("mongodb", New)
}

func New(
	testMode bool,
	results protos.Reporter,
	watcher procs.ProcessesWatcher,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &mongodbPlugin{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := p.init(results, watcher, &config); err != nil {
		return nil, err
	}
	return p, nil
}

func (mongodb *mongodbPlugin) init(results protos.Reporter, watcher procs.ProcessesWatcher, config *mongodbConfig) error {
	debugf("Init a MongoDB protocol parser")
	mongodb.setFromConfig(config)

	mongodb.requests = common.NewCache(
		mongodb.transactionTimeout,
		protos.DefaultTransactionHashSize)
	mongodb.requests.StartJanitor(mongodb.transactionTimeout)
	mongodb.responses = common.NewCache(
		mongodb.transactionTimeout,
		protos.DefaultTransactionHashSize)
	mongodb.responses.StartJanitor(mongodb.transactionTimeout)
	mongodb.results = results
	mongodb.watcher = watcher

	return nil
}

func (mongodb *mongodbPlugin) setFromConfig(config *mongodbConfig) {
	mongodb.ports = config.Ports
	mongodb.sendRequest = config.SendRequest
	mongodb.sendResponse = config.SendResponse
	mongodb.maxDocs = config.MaxDocs
	mongodb.maxDocLength = config.MaxDocLength
	mongodb.transactionTimeout = config.TransactionTimeout
}

func (mongodb *mongodbPlugin) GetPorts() []int {
	return mongodb.ports
}

func (mongodb *mongodbPlugin) ConnectionTimeout() time.Duration {
	return mongodb.transactionTimeout
}

func (mongodb *mongodbPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseMongodb exception")
	debugf("Parse method triggered")

	conn := ensureMongodbConnection(private, tcptuple)
	conn = mongodb.doParse(conn, pkt, tcptuple, dir)
	if conn.IsEmpty() {
		return nil
	}
	return conn
}

func ensureMongodbConnection(private protos.ProtocolData, tcptuple *common.TCPTuple) *mongodbConnectionData {
	if private == nil {
		id, err := uuid.NewV4()
		if err != nil {
			panic(err)
		}
		priv := initPrivData(id, tcptuple)
		return priv
	}

	priv, ok := private.(*mongodbConnectionData)
	if !ok {
		id, err := uuid.NewV4()
		if err != nil {
			panic(err)
		}
		priv = initPrivData(id, tcptuple)
		logp.Warn("mongodb connection data type error, create new one")
		return priv
	}

	if priv == nil {
		debugf("Unexpected: mongodb connection data not set, create new one")
		return &mongodbConnectionData{}
	}

	return priv
}

func (mongodb *mongodbPlugin) doParse(
	conn *mongodbConnectionData,
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
) *mongodbConnectionData {
	st := conn.streams[dir]
	if st == nil {
		st = newStream(pkt, tcptuple)
		conn.streams[dir] = st
		debugf("new stream: %p (dir=%v, len=%v)", st, dir, len(pkt.Payload))
	} else {
		// concatenate bytes
		st.data = append(st.data, pkt.Payload...)
		if len(st.data) > tcp.TCPMaxDataInStream {
			debugf("Stream data too large, dropping TCP stream")
			conn.streams[dir] = nil
			return conn
		}
	}

	for len(st.data) > 0 {
		if st.message == nil {
			st.message = &mongodbMessage{ts: pkt.Ts}
		}
		ok, complete := mongodbMessageParser(st, conn, mongodb, tcptuple)
		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			conn.streams[dir] = nil
			debugf("Ignore Mongodb message. Drop tcp stream. Try parsing with the next segment")
			return conn
		}

		if !complete {
			// wait for more data
			debugf("MongoDB wait for more data before parsing message")
			break
		}

		// all ok, go to next level and reset stream for new message
		debugf("MongoDB message complete")
		mongodb.handleMongodb(conn, st.message, tcptuple, dir)
		st.PrepareForNewMessage()
	}

	return conn
}

func newStream(pkt *protos.Packet, tcptuple *common.TCPTuple) *stream {
	s := &stream{
		tcptuple: tcptuple,
		data:     pkt.Payload,
		message:  &mongodbMessage{ts: pkt.Ts},
	}
	return s
}

func (mongodb *mongodbPlugin) handleMongodb(
	conn *mongodbConnectionData,
	m *mongodbMessage,
	tcptuple *common.TCPTuple,
	dir uint8,
) {

	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = mongodb.watcher.FindProcessesTupleTCP(tcptuple.IPPort())

	if m.isResponse {
		debugf("MongoDB response message")
		mongodb.onResponse(conn, m)
	} else {
		debugf("MongoDB request message")
		mongodb.onRequest(conn, m)
	}
}

func (mongodb *mongodbPlugin) onRequest(conn *mongodbConnectionData, msg *mongodbMessage) {
	//publish request only transaction
	if !awaitsReply(msg.opCode) {
		mongodb.onTransComplete(msg, nil, conn)
		return
	}

	id := msg.requestID
	key := transactionKey{tcp: msg.tcpTuple.Hashable(), id: id}
	// try to find matching response potentially inserted before
	if v := mongodb.responses.Delete(key); v != nil {
		resp := v.(*mongodbMessage)
		mongodb.onTransComplete(msg, resp, conn)
		return
	}
	// insert into cache for correlation
	old := mongodb.requests.Put(key, msg)
	if old != nil {
		debugf("Two requests without a Response. Dropping old request")
		unmatchedRequests.Add(1)
	}
	//trans.sessionId = priv.tcpSession.SessionId
}

func (mongodb *mongodbPlugin) onResponse(conn *mongodbConnectionData, msg *mongodbMessage) {
	id := msg.responseTo
	key := transactionKey{tcp: msg.tcpTuple.Hashable(), id: id}

	// try to find matching request
	if v := mongodb.requests.Delete(key); v != nil {
		requ := v.(*mongodbMessage)
		mongodb.onTransComplete(requ, msg, conn)
		return
	}

	// insert into cache for correlation
	mongodb.responses.Put(key, msg)
}

func (mongodb *mongodbPlugin) onTransComplete(requ, resp *mongodbMessage, conn *mongodbConnectionData) {
	trans := newTransaction(requ, resp, conn)
	debugf("Mongodb transaction completed: %s", trans.mongodb)

	mongodb.publishTransaction(trans)
}

func newTransaction(requ, resp *mongodbMessage, conn *mongodbConnectionData) *transaction {
	trans := &transaction{}
	trans.mongodb = common.MapStr{}
	trans.mongodb.Update(common.MapStr{
		"method":        "",
		"affected_rows": "",
		"insert_id":     "",
		"num_rows":      "",
		"num_fields":    "",
		"fields":        []string{},
		"tables":        "",
		"dbname":        "",
		"status":        "",
		"error_code":    "",
		"error_message": "",
	})
	// fill request
	if requ != nil {
		trans.event = requ.event
		trans.method = requ.method
		trans.sessionId = conn.tcpSession.SessionId
		trans.cmdline = requ.cmdlineTuple
		trans.ts = requ.ts
		trans.src, trans.dst = common.MakeEndpointPair(requ.tcpTuple.BaseTuple, requ.cmdlineTuple)
		if requ.direction == tcp.TCPDirectionReverse {
			trans.src, trans.dst = trans.dst, trans.src
		}
		trans.params = requ.params
		if requ.query != nil {
			trans.addQuery = requ.query
		}
		trans.body = requ.body
		trans.resource = requ.resource
		trans.bytesIn = requ.messageLength
		conn.tcpSession.RequestBytes += uint64(requ.messageLength)
		trans.documents = requ.documents
		trans.clientArch = requ.clientArch
		trans.clientOS = requ.clientOS
		trans.clientVersion = requ.clientVersion
		trans.serverVersion = conn.tcpSession.ServerVersion
		trans.clientProgram = requ.clientProgram
		trans.error = requ.error
		conn.tcpSession.QueryTimes += 1
		if requ.isError {
			trans.isError = true
			trans.mongodb.Update(common.MapStr{
				"error_code":     requ.errorCode,
				"error_message":  requ.errorInfo,
				"error_severity": "",
			})
			//resp.query = ""
		} else {
			trans.mongodb["status"] = common.OK_STATUS
		}

		id, err := uuid.NewV4()
		if err != nil {
			panic(err)
		}
		trans.transId = id.String()

	}

	// fill response
	if resp != nil {
		for k, v := range resp.event {
			trans.event[k] = v
		}

		trans.documents = resp.documents

		trans.endTime = resp.ts
		trans.bytesOut = resp.messageLength
		conn.tcpSession.ResponseBytes += uint64(resp.messageLength)
		trans.error = resp.error
		if resp.isError {
			trans.isError = true
			trans.mongodb.Update(common.MapStr{
				"error_code":     resp.errorCode,
				"error_message":  resp.errorInfo,
				"error_severity": "",
			})
			//resp.query = ""
		} else {
			trans.mongodb["status"] = common.OK_STATUS
		}
		if resp.isLoginSuc {
			trans.isLoginSuc = true

		}
	}

	return trans
}

func (mongodb *mongodbPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {
	return private, true
}

func (mongodb *mongodbPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	priv, ok := private.(*mongodbConnectionData)
	if !ok {
		logp.Debug("mongodb", "发布事务消息: 解析失败")
		return nil
	}
	switch dir {
	case 0:
		priv.tcpSession.Dir0Close = true
		priv.tcpSession.FinishType = "clientclose"
	case 1:
		priv.tcpSession.Dir1Close = true
		if priv.tcpSession.FinishType == "" {
			priv.tcpSession.FinishType = "serverclose"
		}
	}
	if !priv.tcpSession.Dir0Close || !priv.tcpSession.Dir1Close {
		// 双向管道有一方还未发送fin包
		return priv
	}
	mongodb.publishSession(tcptuple, priv, "")
	return private
}

func copyMapWithoutKey(d map[string]interface{}, key string) map[string]interface{} {
	res := map[string]interface{}{}
	for k, v := range d {
		if k != key {
			res[k] = v
		}
	}
	return res
}

func reconstructQuery(t *transaction, full bool) (query string) {
	//fmt.Println("this is method ", t.method)
	if isNormalMethod(t) {

		query += "db"
		table, _ := t.event["table"]
		query += fmt.Sprintf(".%s", table)

	}
	query += t.resource + "." + t.method + "("
	if len(t.params) > 0 {
		var err error
		var params string
		if !full {
			// remove the actual data.
			// TO-DO: review if we need to add other commands here
			if t.method == "insert" {
				params, err = doc2str(copyMapWithoutKey(t.params, "insert"))
				params, err = doc2str(copyMapWithoutKey(copyMapWithoutKey(t.params, "insert"), "lsid"))
			} else if t.method == "update" {
				params, err = doc2str(copyMapWithoutKey(t.params, "updates"))
				params, err = doc2str(copyMapWithoutKey(copyMapWithoutKey(t.params, "updates"), "lsid"))
			} else if t.method == "findandmodify" {
				params, err = doc2str(copyMapWithoutKey(t.params, "update"))
			} else if t.method == "find" {
				params, err = doc2str(copyMapWithoutKey(t.params, "find"))
				params, err = doc2str(copyMapWithoutKey(copyMapWithoutKey(t.params, "find"), "lsid"))
			}
		} else {

			params, err = doc2str(t.params)
		}
		if err != nil {
			debugf("Error marshaling params: %v", err)
		} else {
			query += params
		}
	}
	//if t.body != "" {
	//	query += t.body
	//}
	if t.addQuery != nil {
		for _, item := range t.addQuery {
			query += item

		}
	}
	query += ")"
	//if t.event["limit"] != nil {
	//	skipNum, _ := t.event["skip"]
	//	query += fmt.Sprintf(".skip(%d)", skipNum)
	//}
	//if t.event["limit"] != nil {
	//	limitNum, _ := t.event["limit"]
	//	query += fmt.Sprintf(".limit(%d)", limitNum)
	//}
	skip, _ := t.event["numberToSkip"].(int)
	if skip > 0 {
		query += fmt.Sprintf(".skip(%d)", skip)
	}

	limit, _ := t.event["numberToReturn"].(int)
	if limit > 0 && limit < 0x7fffffff {
		query += fmt.Sprintf(".limit(%d)", limit)
	}
	//fmt.Println("this is finial query", query)
	return
}

func (mongodb *mongodbPlugin) publishTransaction(t *transaction) {
	if mongodb.results == nil {
		debugf("Try to publish transaction with null results")
		return
	}
	logp.Debug("mongodb", "发布事务消息")
	evt, pbf := pb.NewBeatEvent(t.ts)
	pbf.SetSource(&t.src)
	pbf.AddIP(t.src.IP)
	pbf.SetDestination(&t.dst)
	pbf.AddIP(t.dst.IP)
	pbf.Source.Bytes = int64(t.bytesIn)
	pbf.Destination.Bytes = int64(t.bytesOut)
	pbf.Event.Dataset = "mongodb"
	pbf.Event.Start = t.ts
	pbf.Event.End = t.endTime
	pbf.Network.Transport = "tcp"
	pbf.Network.Protocol = pbf.Event.Dataset

	fields := evt.Fields
	fields["type"] = pbf.Event.Dataset
	if t.error == "" {
		fields["status"] = common.OK_STATUS
	} else {
		t.event["error"] = t.error
		fields["status"] = common.ERROR_STATUS
	}
	//fields["mongodb"] = t.event
	if t.isLoginSuc {
		fields["method"] = ""
	} else {
		fields["method"] = t.method
	}

	fields["sqldb"] = t.mongodb
	fields["nosqldb"] = protos.NosqlDB{}
	//fields["resource"] = t.resource
	if t.isLoginSuc {
		fields["query"] = "登录"
	} else {
		fields["query"] = reconstructQuery(t, false)
	}

	fields["transid"] = t.transId
	fields["topic"] = "trans"
	fields["session"] = protos.Session{
		SessionId: t.sessionId,
	}

	fields["cveinfo"] = protos.CveInfo{
		Id: "",
	}
	fields["clientinfo"] = protos.ClientInfo{
		Dbuser:         t.dbUser,
		InitDbName:     t.InitDbName,
		Program:        t.clientProgram,
		Version:        t.clientVersion,
		Os:             t.clientOS,
		Username:       "无",
		Hostname:       "无",
		Arch:           t.clientArch,
		ClientEncoding: t.ClientEncoding,
	}
	fields["serverinfo"] = protos.ServerInfo{
		Program:        "mongodb",
		Version:        t.serverVersion,
		Os:             "无",
		Hostname:       "无",
		Arch:           "无",
		ServerEncoding: t.ServerEncoding,
	}

	if t.isError {
		fields["status"] = common.ERROR_STATUS
	} else {
		fields["status"] = common.OK_STATUS
	}
	if mongodb.sendRequest {
		fields["request"] = reconstructQuery(t, true)
	}
	if mongodb.sendResponse {
		if len(t.documents) > 0 {
			// response field needs to be a string
			docs := make([]string, 0, len(t.documents))
			for i, doc := range t.documents {
				if mongodb.maxDocs > 0 && i >= mongodb.maxDocs {
					docs = append(docs, "[...]")
					break
				}
				str, err := doc2str(doc)
				if err != nil {
					logp.Warn("Failed to JSON marshal document from Mongo: %v (error: %v)", doc, err)
				} else {
					if mongodb.maxDocLength > 0 && len(str) > mongodb.maxDocLength {
						str = str[:mongodb.maxDocLength] + " ..."
					}
					docs = append(docs, str)
				}
			}
			fields["response"] = strings.Join(docs, "\n")
		}
	}
	mongodb.results(evt)
}
func (mongodb *mongodbPlugin) publishSession(tuple *common.TCPTuple, priv *mongodbConnectionData, closeType string) {
	src, dst := common.MakeEndpointPair(priv.tcpSession.TcpTuple.BaseTuple, nil)
	now := time.Now()
	evt, pbf := pb.NewBeatEvent(now)
	pbf.SetSource(&src)
	//pbf.AddIP(t.src.IP)
	pbf.SetDestination(&dst)
	//pbf.AddIP(t.dst.IP)

	fields := evt.Fields
	fields["type"] = "mongodb"
	fields["start"] = priv.tcpSession.Start
	fields["end"] = now
	fields["is_crypto"] = priv.tcpSession.IsCrypto
	fields["crypto_ver"] = priv.tcpSession.TLSVersion
	fields["crypto_count"] = priv.tcpSession.TLSPacketCount

	fields["session_id"] = priv.tcpSession.SessionId
	fields["querytimes"] = priv.tcpSession.QueryTimes
	fields["req_bytes"] = priv.tcpSession.RequestBytes
	fields["res_bytes"] = priv.tcpSession.ResponseBytes
	fields["finish_type"] = priv.tcpSession.FinishType
	if closeType != "" {
		fields["finish_type"] = closeType
	}
	fields["protocoltype"] = "mongodb"
	fields["clientinfo"] = protos.ClientInfo{
		Dbuser:   priv.tcpSession.DbUser,
		Program:  priv.tcpSession.ClientProgram,
		Version:  priv.tcpSession.ClientVersion,
		Os:       priv.tcpSession.ClientOS,
		Username: priv.tcpSession.ClientUsername,
		Hostname: priv.tcpSession.ClientHostname,
		Arch:     priv.tcpSession.ClientArch,
	}
	fields["serverinfo"] = protos.ServerInfo{
		Program:  "mongodb",
		Version:  priv.tcpSession.ServerVersion,
		Os:       priv.tcpSession.ServerOS,
		Hostname: priv.tcpSession.ServerHostname,
		Arch:     priv.tcpSession.ServerArch,
	}

	fields["topic"] = "session"
	mongodb.results(evt)
	logp.Debug("mongodb", "发布会话消息, session_id: %s", priv.tcpSession.SessionId)
}

func initPrivData(id uuid.UUID, tcptuple *common.TCPTuple) *mongodbConnectionData {

	return &mongodbConnectionData{
		tcpSession: &tcp.TCPSession{
			TcpTuple:       tcptuple,
			Dir1Close:      false,
			Dir0Close:      false,
			SessionId:      id.String(),
			Start:          time.Now(),
			QueryTimes:     0,
			RequestBytes:   0,
			ResponseBytes:  0,
			AllPacketCount: 0,
			TLSVersion:     "无",
			TLSPacketCount: 0,
			DbUser:         "无",
			ClientProgram:  "无",
			ClientVersion:  "无",
			ClientOS:       "无",
			ClientUsername: "无",
			ClientHostname: "无",
			ClientArch:     "无",
			ServerProgram:  "无",
			ServerVersion:  "无",
			ServerOS:       "无",
			ServerHostname: "无",
			ServerArch:     "无",
			FinishType:     "无",
			InitDbName:     "无",
			ClientEncoding: "无",
			ServerEncoding: "无",
		},
	}
}

// TCP会话超时调用
func (mongodb *mongodbPlugin) ExpiredTCP(tuple *common.TCPTuple, private protos.ProtocolData) {
	priv, ok := private.(*mongodbConnectionData)
	if !ok {
		logp.Debug("mongodb", "发布会话消息: 解析失败")
		return
	}
	mongodb.publishSession(tuple, priv, "timeout")
}

func (s mongodbConnectionData) IsEmpty() bool {
	return reflect.DeepEqual(s, mongodbConnectionData{})
}

//ADD function
func isNormalMethod(t *transaction) bool {
	return t.method == "find" || t.method == "insert" || t.method == "update" || t.method == "delete" || t.method == "create"
}

//END
