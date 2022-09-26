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

package kingbase

import (
	"errors"
	"github.com/elastic/beats/v7/packetbeat/protos/ssl"
	"github.com/gofrs/uuid"
	"strings"
	"time"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/monitoring"

	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"

	"go.uber.org/zap"
)

type pgsqlPlugin struct {
	log, debug, detail *logp.Logger
	isDebug, isDetail  bool

	// config
	ports        []int
	maxStoreRows int
	maxRowLength int
	sendRequest  bool
	sendResponse bool

	transactions       *common.Cache
	transactionTimeout time.Duration

	results protos.Reporter
	watcher procs.ProcessesWatcher

	// function pointer for mocking
	handlePgsql func(pgsql *pgsqlPlugin, m *pgsqlMessage, tcp *common.TCPTuple,
		dir uint8, raw_msg []byte, priv pgsqlPrivateData)
}

type pgsqlMessage struct {
	start         int
	end           int
	isSSLResponse bool
	isSSLRequest  bool
	toExport      bool

	ts             time.Time
	isRequest      bool
	query          string
	size           uint64
	fields         []string
	fieldsFormat   []byte
	rows           [][]string
	numberOfRows   int
	numberOfFields int
	isOK           bool
	isError        bool
	errorInfo      string
	errorCode      string
	errorSeverity  string
	notes          []string

	direction    uint8
	tcpTuple     common.TCPTuple
	cmdlineTuple *common.ProcessTuple
	dbUser       string
	//add field
	dateStyle                  string
	MajorVersion, MinorVersion string
	ServerVersion              string
	tables                     string
	tablesList                 []string
	affectedRows               uint64
}
type pgsqlMsg struct {
	MajorVersion, MinorVersion, ServerVersion string
}

type pgsqlTransaction struct {
	tuple    common.TCPTuple
	src      common.Endpoint
	dst      common.Endpoint
	ts       time.Time
	endTime  time.Time
	query    string
	method   string
	bytesOut uint64
	bytesIn  uint64
	notes    []string
	isError  bool

	pgsql common.MapStr

	requestRaw                                                                                                                                        string
	responseRaw                                                                                                                                       string
	transId                                                                                                                                           string // 事务唯一id
	sessionId                                                                                                                                         string // 会话id
	serverVersion, serverOS, serverHostname, serverArch, serverProgram                                                                                string // 数据库程序版本
	dbUser, clientProgram, clientVersion, clientOS, clientArch, clientPID, clientUsername, clientHostname, InitDbName, ClientEncoding, ServerEncoding string
	tables                                                                                                                                            []string
}

type pgsqlStream struct {
	data []byte

	parseOffset       int
	parseState        int
	seenSSLRequest    bool
	expectSSLResponse bool

	message *pgsqlMessage
}

const (
	pgsqlStartState = iota
	pgsqlGetDataState
	pgsqlExtendedQueryState
)

const (
	sslRequest = iota
	startupMessage
	cancelRequest
)

var (
	errInvalidLength = errors.New("invalid length")
)

var (
	unmatchedResponses = monitoring.NewInt(nil, "kingbase.unmatched_responses")
)

func init() {
	protos.Register("kingbase", New)
}

func New(
	testMode bool,
	results protos.Reporter,
	watcher procs.ProcessesWatcher,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &pgsqlPlugin{}
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

func (pgsql *pgsqlPlugin) init(results protos.Reporter, watcher procs.ProcessesWatcher, config *pgsqlConfig) error {
	pgsql.setFromConfig(config)

	pgsql.log = logp.NewLogger("kingbase")
	pgsql.debug = logp.NewLogger("kingbase", zap.AddCallerSkip(1))
	pgsql.detail = logp.NewLogger("kingbasedetailed", zap.AddCallerSkip(1))
	pgsql.isDebug, pgsql.isDetail = logp.IsDebug("pgsql"), logp.IsDebug("kingbasedetailed")

	pgsql.transactions = common.NewCache(
		pgsql.transactionTimeout,
		protos.DefaultTransactionHashSize)
	pgsql.transactions.StartJanitor(pgsql.transactionTimeout)
	pgsql.handlePgsql = handlePgsql
	pgsql.results = results
	pgsql.watcher = watcher

	return nil
}

func (pgsql *pgsqlPlugin) setFromConfig(config *pgsqlConfig) {
	pgsql.ports = config.Ports
	pgsql.maxRowLength = config.MaxRowLength
	pgsql.maxStoreRows = config.MaxRows
	pgsql.sendRequest = config.SendRequest
	pgsql.sendResponse = config.SendResponse
	pgsql.transactionTimeout = config.TransactionTimeout
}

func (pgsql *pgsqlPlugin) getTransaction(k common.HashableTCPTuple) []*pgsqlTransaction {
	v := pgsql.transactions.Get(k)
	if v != nil {
		return v.([]*pgsqlTransaction)
	}
	return nil
}

//go:inline
func (pgsql *pgsqlPlugin) debugf(format string, v ...interface{}) {
	if pgsql.isDebug {
		pgsql.debug.Debugf(format, v...)
	}
}

//go:inline
func (pgsql *pgsqlPlugin) detailf(format string, v ...interface{}) {
	if pgsql.isDetail {
		pgsql.detail.Debugf(format, v...)
	}
}

func (pgsql *pgsqlPlugin) GetPorts() []int {
	return pgsql.ports
}

func (stream *pgsqlStream) prepareForNewMessage() {
	stream.data = stream.data[stream.message.end:]
	stream.parseState = pgsqlStartState
	stream.parseOffset = 0
	stream.message = nil
}

// Extract the method from a SQL query
func getQueryMethod(q string) string {
	index := strings.Index(q, " ")
	var method string
	if index > 0 {
		method = strings.ToUpper(q[:index])
	} else {
		method = strings.ToUpper(q)
	}
	return method
}

type pgsqlPrivateData struct {
	data       [2]*pgsqlStream
	tcpSession *tcp.TCPSession
	pgsqlMsg   *pgsqlMsg
}

func (pgsql *pgsqlPlugin) ConnectionTimeout() time.Duration {
	return pgsql.transactionTimeout
}

func (pgsql *pgsqlPlugin) Parse(pkt *protos.Packet, tcptuple *common.TCPTuple,
	dir uint8, private protos.ProtocolData) protos.ProtocolData {

	defer logp.Recover("ParsePgsql exception")

	priv := pgsqlPrivateData{}
	if private != nil {
		var ok bool
		priv, ok = private.(pgsqlPrivateData)
		if !ok {
			id, err := uuid.NewV4()
			if err != nil {
				panic(err)
			}
			priv = initPrivData(id, tcptuple)

		}
	} else {
		id, err := uuid.NewV4()
		if err != nil {
			panic(err)
		}
		priv = initPrivData(id, tcptuple)
	}

	if priv.data[dir] == nil {
		priv.data[dir] = &pgsqlStream{
			data:    pkt.Payload,
			message: &pgsqlMessage{ts: pkt.Ts},
		}
		pgsql.detailf("New stream created")
	} else {
		// concatenate bytes
		priv.data[dir].data = append(priv.data[dir].data, pkt.Payload...)
		pgsql.detailf("Len data: %d cap data: %d", len(priv.data[dir].data), cap(priv.data[dir].data))
		if len(priv.data[dir].data) > tcp.TCPMaxDataInStream {
			pgsql.debugf("Stream data too large, dropping TCP stream")
			priv.data[dir] = nil
			return priv
		}
	}

	stream := priv.data[dir]

	if priv.data[1-dir] != nil && priv.data[1-dir].seenSSLRequest {
		stream.expectSSLResponse = true
	}

	for len(stream.data) > 0 {

		if stream.message == nil {
			stream.message = &pgsqlMessage{ts: pkt.Ts}
		}
		if !priv.tcpSession.IsCrypto {
			ok, complete := pgsql.pgsqlMessageParser(priv, dir)

			if !ok {
				// drop this tcp stream. Will retry parsing with the next
				// segment in it
				priv.data[dir] = nil
				pgsql.debugf("Ignore Postgresql message. Drop tcp stream. Try parsing with the next segment")
				return priv
			}

			if complete {

				// all ok, ship it
				msg := stream.data[stream.message.start:stream.message.end]

				if stream.message.isSSLRequest {
					// SSL request
					stream.seenSSLRequest = true
				} else if stream.message.isSSLResponse {
					// SSL request answered
					stream.expectSSLResponse = false
					priv.data[1-dir].seenSSLRequest = false
				} else {
					if stream.message.toExport {
						pgsql.handlePgsql(pgsql, stream.message, tcptuple, dir, msg, priv)
					}
				}

				// and reset message
				stream.prepareForNewMessage()

			} else {
				// wait for more data
				break
			}
		} else {
			sslHeader := ssl.SSLHeaderParse(stream.data[:5])

			priv.tcpSession.TLSVersion = sslHeader.Version
			priv.tcpSession.TLSPacketCount += 1

			stream.data = stream.data[len(stream.data):]
			break
		}
	}
	return priv
}

func messageHasEnoughData(msg *pgsqlMessage) bool {
	if msg == nil {
		return false
	}
	if msg.isSSLRequest || msg.isSSLResponse {
		return false
	}
	if msg.isRequest {
		return len(msg.query) > 0
	}
	return len(msg.rows) > 0
}

// Called when there's a drop packet
func (pgsql *pgsqlPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInPgsqlStream exception")

	if private == nil {
		return private, false
	}
	pgsqlData, ok := private.(pgsqlPrivateData)
	if !ok {
		return private, false
	}
	if pgsqlData.data[dir] == nil {
		return pgsqlData, false
	}

	// If enough data was received, send it to the
	// next layer but mark it as incomplete.
	stream := pgsqlData.data[dir]
	if messageHasEnoughData(stream.message) {
		pgsql.debugf("Message not complete, but sending to the next layer")
		m := stream.message
		m.toExport = true
		m.end = stream.parseOffset
		if m.isRequest {
			m.notes = append(m.notes, "Packet loss while capturing the request")
		} else {
			m.notes = append(m.notes, "Packet loss while capturing the response")
		}

		msg := stream.data[stream.message.start:stream.message.end]
		pgsql.handlePgsql(pgsql, stream.message, tcptuple, dir, msg, pgsqlData)

		// and reset message
		stream.prepareForNewMessage()
	}
	return pgsqlData, true
}

func (pgsql *pgsqlPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {
	priv, ok := private.(pgsqlPrivateData)
	if !ok {
		logp.Debug("pgsql", "发布事务消息: 解析失败")
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
	pgsql.publishSession(tcptuple, priv, "")
	return private
}

var handlePgsql = func(pgsql *pgsqlPlugin, m *pgsqlMessage, tcptuple *common.TCPTuple,
	dir uint8, raw_msg []byte, priv pgsqlPrivateData) {

	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = pgsql.watcher.FindProcessesTupleTCP(tcptuple.IPPort())
	if m.isRequest {
		pgsql.receivedPgsqlRequest(m, priv, dir)
	} else {
		pgsql.receivedPgsqlResponse(m, priv)
	}
}

func (pgsql *pgsqlPlugin) receivedPgsqlRequest(msg *pgsqlMessage, priv pgsqlPrivateData, dir uint8) {
	tuple := msg.tcpTuple

	// parse the query, as it might contain a list of pgsql command
	// separated by ';'
	queries := pgsqlQueryParser(msg.query)

	pgsql.debugf("%d) :%s", len(queries), queries)
	transList := pgsql.getTransaction(tuple.Hashable())
	if transList == nil {
		transList = []*pgsqlTransaction{}
	}

	for _, query := range queries {
		id, err := uuid.NewV4()

		if err != nil {
			panic(err)
		}

		trans := &pgsqlTransaction{
			tuple:   tuple,
			transId: id.String(),
		}

		//msg.tablesList = parseTables(query)

		trans.tables = msg.tablesList

		trans.ts = msg.ts
		trans.src, trans.dst = common.MakeEndpointPair(msg.tcpTuple.BaseTuple, msg.cmdlineTuple)

		if msg.direction == tcp.TCPDirectionReverse {
			trans.src, trans.dst = trans.dst, trans.src
		}

		trans.pgsql = common.MapStr{}
		trans.query = query
		trans.method = getQueryMethod(query)
		if trans.method == "登录" {
			trans.method = ""
		}
		trans.bytesIn = msg.size
		trans.notes = msg.notes
		trans.requestRaw = query

		trans.sessionId = priv.tcpSession.SessionId
		trans.dbUser = priv.tcpSession.DbUser
		trans.clientProgram = priv.tcpSession.ClientProgram
		trans.InitDbName = priv.tcpSession.InitDbName
		trans.ClientEncoding = priv.tcpSession.ClientEncoding
		trans.ServerEncoding = priv.tcpSession.ServerEncoding
		trans.clientVersion = priv.pgsqlMsg.MajorVersion
		trans.serverVersion = priv.tcpSession.ServerVersion
		//trans.clientOS = priv.tcpSession.ClientOS
		//trans.clientUsername = priv.tcpSession.ClientUsername
		//trans.clientHostname = priv.tcpSession.ClientHostname
		//trans.clientArch = priv.tcpSession.ClientArch
		//trans.serverProgram = priv.tcpSession.ServerProgram
		//trans.serverOS = priv.tcpSession.ServerOS
		//trans.serverHostname = priv.tcpSession.ServerHostname
		transList = append(transList, trans)

	}
	// 更新会话字段
	priv.tcpSession.QueryTimes += 1
	priv.tcpSession.RequestBytes += msg.size

	pgsql.transactions.Put(tuple.Hashable(), transList)
}

func (pgsql *pgsqlPlugin) receivedPgsqlResponse(msg *pgsqlMessage, priv pgsqlPrivateData) {
	tuple := msg.tcpTuple
	transList := pgsql.getTransaction(tuple.Hashable())
	if transList == nil || len(transList) == 0 {
		pgsql.debugf("Response from unknown transaction. Ignoring.")
		unmatchedResponses.Add(1)
		return
	}

	// extract the first transaction from the array
	trans := pgsql.removeTransaction(transList, tuple, 0)

	// check if the request was received
	if trans.pgsql == nil {
		pgsql.debugf("Response from unknown transaction. Ignoring.")
		unmatchedResponses.Add(1)
		return
	}

	trans.pgsql.Update(common.MapStr{
		"method":        trans.method,
		"affected_rows": msg.affectedRows,
		"insert_id":     "",
		"num_rows":      msg.numberOfRows,
		"num_fields":    msg.numberOfFields,
		"fields":        []string{},
		"tables":        trans.tables,
		"dbname":        trans.InitDbName,
		"status":        "",
		"error_code":    "",
		"error_message": "",
	})
	if msg.isError {
		trans.pgsql.Update(common.MapStr{
			"error_code":     msg.errorCode,
			"error_message":  msg.errorInfo,
			"error_severity": msg.errorSeverity,
		})
		trans.query = ""
	} else {
		trans.pgsql["status"] = common.OK_STATUS
	}
	trans.bytesOut = msg.size
	//trans.path = msg.tables
	trans.isError = msg.isError
	trans.endTime = msg.ts
	priv.tcpSession.ResponseBytes += msg.size
	trans.responseRaw = common.DumpInCSVFormat(msg.fields, msg.rows)
	trans.serverVersion = priv.tcpSession.ServerVersion
	trans.ServerEncoding = priv.tcpSession.ServerEncoding

	trans.notes = append(trans.notes, msg.notes...)

	pgsql.publishTransaction(trans)

	pgsql.debugf("Postgres transaction completed: %s\n%s", trans.pgsql, trans.responseRaw)
}

func (pgsql *pgsqlPlugin) publishTransaction(t *pgsqlTransaction) {
	if pgsql.results == nil {
		return
	}
	logp.Debug("kingbase", "发布事务消息, trans_id: %s", t.transId)
	evt, pbf := pb.NewBeatEvent(t.ts)
	pbf.SetSource(&t.src)
	pbf.SetDestination(&t.dst)
	pbf.Source.Bytes = int64(t.bytesIn)
	pbf.Destination.Bytes = int64(t.bytesOut)
	pbf.Event.Start = t.ts
	pbf.Event.End = t.endTime
	pbf.Event.Dataset = "kingbase"
	pbf.Network.Transport = "tcp"
	pbf.Network.Protocol = pbf.Event.Dataset
	pbf.Error.Message = t.notes

	fields := evt.Fields
	fields["type"] = pbf.Event.Dataset
	fields["method"] = t.method
	fields["query"] = t.query
	fields["sqldb"] = t.pgsql
	fields["nosqldb"] = protos.NosqlDB{}
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
		Os:             "无",
		Username:       "无",
		Hostname:       "无",
		Arch:           "无",
		ClientEncoding: t.ClientEncoding,
	}
	fields["serverinfo"] = protos.ServerInfo{
		Program:        "kingbase",
		Version:        t.serverVersion,
		Os:             "无",
		Hostname:       "无",
		Arch:           "无",
		ServerEncoding: t.ServerEncoding,
	}
	//if len(t.path) > 0 {
	//	fields["path"] = t.path
	//
	//}
	//if len(t.params) > 0 {
	//	fields["params"] = t.params
	//}

	if t.isError {
		fields["status"] = common.ERROR_STATUS
	} else {
		fields["status"] = common.OK_STATUS
	}
	if pgsql.sendRequest {
		fields["request"] = t.requestRaw
	}
	if pgsql.sendResponse {
		fields["response"] = t.responseRaw
	}

	pgsql.results(evt)
}

func (pgsql *pgsqlPlugin) removeTransaction(transList []*pgsqlTransaction,
	tuple common.TCPTuple, index int) *pgsqlTransaction {

	trans := transList[index]
	transList = append(transList[:index], transList[index+1:]...)
	if len(transList) == 0 {
		pgsql.transactions.Delete(trans.tuple.Hashable())
	} else {
		pgsql.transactions.Put(tuple.Hashable(), transList)
	}

	return trans
}
func initPrivData(id uuid.UUID, tcptuple *common.TCPTuple) pgsqlPrivateData {
	return pgsqlPrivateData{
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
		pgsqlMsg: &pgsqlMsg{
			MinorVersion: "无",
			MajorVersion: "无",
		},
	}
}

// TCP会话超时调用
func (pgsql *pgsqlPlugin) ExpiredTCP(tuple *common.TCPTuple, private protos.ProtocolData) {
	priv, ok := private.(pgsqlPrivateData)
	if !ok {
		logp.Debug("pgsql", "发布会话消息: 解析失败")
		return
	}

	pgsql.publishSession(tuple, priv, "timeout")
}
func (pgsql *pgsqlPlugin) publishSession(tuple *common.TCPTuple, priv pgsqlPrivateData, closeType string) {
	logp.Debug("pgsql", "发布会话消息, session_id: %s", priv.tcpSession.SessionId)

	src, dst := common.MakeEndpointPair(priv.tcpSession.TcpTuple.BaseTuple, nil)
	now := time.Now()
	evt, pbf := pb.NewBeatEvent(now)

	pbf.SetSource(&src)
	//pbf.AddIP(t.src.IP)
	pbf.SetDestination(&dst)
	//pbf.AddIP(t.dst.IP)

	fields := evt.Fields
	fields["type"] = "kingbase"
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
	fields["protocoltype"] = "kingbase"
	fields["clientinfo"] = protos.ClientInfo{
		Dbuser:     priv.tcpSession.DbUser,
		Program:    priv.tcpSession.ClientProgram,
		InitDbName: priv.tcpSession.InitDbName,
		Version:    priv.pgsqlMsg.MajorVersion,
		Os:         priv.tcpSession.ClientOS,
		Username:   priv.tcpSession.ClientUsername,
		Hostname:   priv.tcpSession.ClientHostname,
		Arch:       priv.tcpSession.ClientArch,
	}
	fields["serverinfo"] = protos.ServerInfo{
		Program:        "kingbase",
		Version:        priv.tcpSession.ServerVersion,
		Os:             priv.tcpSession.ServerOS,
		Hostname:       priv.tcpSession.ServerHostname,
		Arch:           priv.tcpSession.ServerArch,
		ServerEncoding: priv.tcpSession.ServerEncoding,
	}

	fields["topic"] = "session"
	pgsql.results(evt)
}

//func parseTables( str string) []string {
//	isBase :=false
//	tabList:= make([]string,0)
//	arr :=strings.Split(str," ")
//	for _, item := range arr {
//		a:=strings.ToLower(item)
//		if isBase {
//		isExist:=	strings.Contains(item,"(")
//			if isExist {
//				index :=strings.Index(item,"(")
//				item = item[:index-1]
//			}
//
//			tabList = append(tabList,item)
//
//			isBase =!isBase
//		}
//		if a =="from" || a=="join" || a=="into" || a=="update" || a=="table"  {
//			isBase =!isBase
//		}
//
//	}
//	return tabList
//}
