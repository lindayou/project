package sqlserver

import (
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/monitoring"
	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
	"github.com/gofrs/uuid"
	"go.uber.org/zap"
	"strings"
	"time"
)

var (
	unmatchedResponses = monitoring.NewInt(nil, "sqlserver.unmatched_responses")
)

func init() {
	protos.Register("sqlserver", New)
}

func New(
	testMode bool,
	results protos.Reporter,
	watcher procs.ProcessesWatcher,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &sqlserverPlugin{}
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

func (sqlserver *sqlserverPlugin) init(results protos.Reporter, watcher procs.ProcessesWatcher, config *sqlserverConfig) error {
	sqlserver.setFromConfig(config)

	sqlserver.log = logp.NewLogger("sqlserver")
	sqlserver.debug = logp.NewLogger("sqlserver", zap.AddCallerSkip(1))
	sqlserver.detail = logp.NewLogger("sqlserverdetailed", zap.AddCallerSkip(1))
	sqlserver.isDebug, sqlserver.isDetail = logp.IsDebug("sqlserver"), logp.IsDebug("sqlserverdetailed")

	sqlserver.transactions = common.NewCache(
		sqlserver.transactionTimeout,
		protos.DefaultTransactionHashSize)
	sqlserver.transactions.StartJanitor(sqlserver.transactionTimeout)
	sqlserver.handleSqlserver = handleSqlserver
	sqlserver.results = results
	sqlserver.watcher = watcher

	return nil
}
func (sqlserver *sqlserverPlugin) setFromConfig(config *sqlserverConfig) {
	sqlserver.ports = config.Ports
	sqlserver.maxRowLength = config.MaxRowLength
	sqlserver.maxStoreRows = config.MaxRows
	sqlserver.sendRequest = config.SendRequest
	sqlserver.sendResponse = config.SendResponse
	sqlserver.transactionTimeout = config.TransactionTimeout
}
func (sqlserver *sqlserverPlugin) getTransaction(k common.HashableTCPTuple) []*sqlserverTransaction {
	v := sqlserver.transactions.Get(k)
	if v != nil {
		return v.([]*sqlserverTransaction)
	}
	return nil
}

//go:inline
func (sqlserver *sqlserverPlugin) debugf(format string, v ...interface{}) {
	if sqlserver.isDebug {
		sqlserver.debug.Debugf(format, v...)
	}
}

//go:inline
func (sqlserver *sqlserverPlugin) detailf(format string, v ...interface{}) {
	if sqlserver.isDetail {
		sqlserver.detail.Debugf(format, v...)
	}
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

// Parse a list of commands separated by semicolon from the query
func sqlserverQueryParser(query string) []string {
	array := strings.Split(query, ";")

	queries := []string{}

	for _, q := range array {
		qt := strings.TrimSpace(q)
		if len(qt) > 0 {
			queries = append(queries, qt)
		}
	}
	return queries
}
func (sqlserver *sqlserverPlugin) GetPorts() []int {
	return sqlserver.ports
}
func (stream *sqlserverStream) prepareForNewMessage() {
	stream.data = stream.data[stream.message.size-1:]
	//stream.parseState = sqlserverStartState
	stream.parseOffset = 0
	stream.message = nil
}

var handleSqlserver = func(sqlserver *sqlserverPlugin, m *sqlserverMessage, tcptuple *common.TCPTuple,
	dir uint8, raw_msg []byte, priv sqlserverPrivateData) {

	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = sqlserver.watcher.FindProcessesTupleTCP(tcptuple.IPPort())
	if m.isRequest {
		sqlserver.receivedSqlserverRequest(m, priv, dir)
	} else {
		sqlserver.receivedSqlserverResponse(m, priv)
	}
}

func (sqlserver *sqlserverPlugin) receivedSqlserverRequest(msg *sqlserverMessage, priv sqlserverPrivateData, dir uint8) {
	tuple := msg.tcpTuple
	m := priv.data[dir].message
	// parse the query, as it might contain a list of sqlserver command
	// separated by ';'

	transList := sqlserver.getTransaction(tuple.Hashable())
	if transList == nil {
		transList = []*sqlserverTransaction{}
	}

	id, err := uuid.NewV4()

	if err != nil {
		panic(err)
	}

	trans := &sqlserverTransaction{
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

	trans.sqlserver = common.MapStr{}
	trans.query = m.query
	trans.method = getQueryMethod(m.query)
	if trans.method == "登录" {
		trans.method = ""
	}
	trans.bytesIn = m.size
	trans.notes = m.notes
	trans.requestRaw = m.query

	trans.sessionId = priv.tcpSession.SessionId
	trans.dbUser = priv.tcpSession.DbUser
	trans.clientProgram = priv.tcpSession.ClientProgram
	trans.InitDbName = priv.tcpSession.InitDbName
	trans.ClientEncoding = priv.tcpSession.ClientEncoding
	trans.ServerEncoding = priv.tcpSession.ServerEncoding
	trans.clientVersion = priv.tcpSession.ClientVersion
	//trans.serverVersion = priv.tcpSession.ServerVersion
	//trans.clientOS = priv.tcpSession.ClientOS
	//trans.clientUsername = priv.tcpSession.ClientUsername
	//trans.clientHostname = priv.tcpSession.ClientHostname
	//trans.clientArch = priv.tcpSession.ClientArch
	//trans.serverProgram = priv.tcpSession.ServerProgram
	//trans.serverOS = priv.tcpSession.ServerOS
	//trans.serverHostname = priv.tcpSession.ServerHostname
	transList = append(transList, trans)

	// 更新会话字段
	priv.tcpSession.QueryTimes += 1
	priv.tcpSession.RequestBytes += msg.size

	sqlserver.transactions.Put(tuple.Hashable(), transList)
}

func (sqlserver *sqlserverPlugin) receivedSqlserverResponse(msg *sqlserverMessage, priv sqlserverPrivateData) {
	tuple := msg.tcpTuple
	transList := sqlserver.getTransaction(tuple.Hashable())
	if transList == nil || len(transList) == 0 {
		sqlserver.debugf("Response from unknown transaction. Ignoring.")
		unmatchedResponses.Add(1)
		return
	}

	// extract the first transaction from the array
	trans := sqlserver.removeTransaction(transList, tuple, 0)

	// check if the request was received
	if trans.sqlserver == nil {
		sqlserver.debugf("Response from unknown transaction. Ignoring.")
		unmatchedResponses.Add(1)
		return
	}
	if strings.ToLower(trans.method) == "select" {
		msg.affectedRows = 0
	}
	trans.sqlserver.Update(common.MapStr{
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
		trans.sqlserver.Update(common.MapStr{
			"error_code":     msg.errorCode,
			"error_message":  msg.errorInfo,
			"error_severity": msg.errorSeverity,
		})

	} else {
		trans.sqlserver["status"] = common.OK_STATUS
	}
	trans.bytesOut = msg.size
	//trans.path = msg.tables
	trans.isError = msg.isError
	trans.endTime = msg.ts
	priv.tcpSession.ResponseBytes += msg.size
	trans.responseRaw = common.DumpInCSVFormat(msg.fields, msg.rows)
	trans.serverVersion = priv.tcpSession.ServerVersion
	trans.ServerEncoding = priv.tcpSession.ServerEncoding
	trans.serverHostname = priv.tcpSession.ServerHostname
	trans.notes = append(trans.notes, msg.notes...)
	sqlserver.publishTransaction(trans)

	sqlserver.debugf("Sqlserver transaction completed: %s\n%s", trans.sqlserver, trans.responseRaw)
}

func (sqlserver *sqlserverPlugin) Parse(pkt *protos.Packet, tcptuple *common.TCPTuple,
	dir uint8, private protos.ProtocolData) protos.ProtocolData {
	defer logp.Recover("ParseSqlserver exception")
	priv := sqlserverPrivateData{}
	if private != nil {
		var ok bool
		priv, ok = private.(sqlserverPrivateData)
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

		priv.data[dir] = &sqlserverStream{
			data:    pkt.Payload,
			message: &sqlserverMessage{ts: pkt.Ts},
		}
		sqlserver.detailf("New stream created")
	} else {

		// 1这是0x00返回的包或者是  reallength <length
		//2.如果是0x00，直接拼接，然后将  首个status改成1
		priv.data[dir].data = append(priv.data[dir].data, pkt.Payload...)

		// 前一个包status =0  本包中前一个分片
		// concatenate bytes
		_, status, _ := handleNextPacket(pkt.Payload)
		//
		//if priv.data[dir].message.symbol && typ != 0x04 {
		//	priv.data[dir].message.length += len(pkt.Payload)
		//	priv.data[dir].data = append(priv.data[dir].data, pkt.Payload...)
		//
		//	if priv.data[dir].message.length == priv.data[dir].message.totalLen {
		//		fmt.Println("i change 0x01 in first", priv.data[dir].message.length, priv.data[dir].message.totalLen)
		//		priv.data[dir].data[1] = 0x01
		//	}
		//} else
		//1.本包中的一个包(不是最后一个包)的片段()  2.是最后一个包中的第一个片段3.最后一个包的其片段

		//_, totalLen, _ := handleInitialMsg(pkt.Payload)
		//if len(pkt.Payload) < totalLen {
		//	return priv
		//}
		if status == 0x01 {

			//priv.data[dir].message.symbol = true
			//找到总长度
			//_, _, totalLen := handleInitialMsg(pkt.Payload)
			//priv.data[dir].message.totalLen = int(totalLen)
			//priv.data[dir].message.length += len(pkt.Payload)
			//赋值第一次长度
			//if priv.data[dir].message.length == priv.data[dir].message.totalLen {
			//	fmt.Println("i change 0x01 in second ", priv.data[dir].message.length, priv.data[dir].message.totalLen)
			//}
			//正常的一个相应包status 为0x01  这里预防多个相应包为0x00的情况 收到0x01 就再次更新status

			priv.data[dir].data[1] = 0x01
		}

		sqlserver.detailf("Len data: %d cap data: %d", len(priv.data[dir].data), cap(priv.data[dir].data))
		if len(priv.data[dir].data) > tcp.TCPMaxDataInStream {
			sqlserver.debugf("Stream data too large, dropping TCP stream")
			priv.data[dir] = nil
			return priv
		}
	}

	stream := priv.data[dir]

	for len(stream.data) > 0 {

		if stream.message == nil {
			stream.message = &sqlserverMessage{ts: pkt.Ts}
		}

		ok, complete := sqlserver.sqlserverMessageParser(priv, dir)

		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			priv.data[dir] = nil
			sqlserver.debugf("Ignore Sqlserver message. Drop tcp stream. Try parsing with the next segment")
			return priv
		}

		if complete {

			// all ok, ship it
			msg := stream.data[:]
			if stream.message.toExport {
				sqlserver.handleSqlserver(sqlserver, stream.message, tcptuple, dir, msg, priv)
			}

			// and reset message
			stream.prepareForNewMessage()

		} else {
			// wait for more data
			break
		}
	}
	return priv
}

func (sqlserver *sqlserverPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {
	priv, ok := private.(sqlserverPrivateData)
	if !ok {
		logp.Debug("sqlserver", "发布事务消息: 解析失败")
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
	sqlserver.publishSession(tcptuple, priv, "")
	return private
}

// Called when there's a drop packet
func (sqlserver *sqlserverPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInSqlserverStream exception")

	if private == nil {
		return private, false
	}
	sqlserverData, ok := private.(sqlserverPrivateData)
	if !ok {
		return private, false
	}
	if sqlserverData.data[dir] == nil {
		return sqlserverData, false
	}

	// If enough data was received, send it to the
	// next layer but mark it as incomplete.
	//stream := sqlserverData.data[dir]
	//if messageHasEnoughData(stream.message) {
	//	sqlserver.debugf("Message not complete, but sending to the next layer")
	//	m := stream.message
	//	m.toExport = true
	//	m.end = stream.parseOffset
	//	if m.isRequest {
	//		m.notes = append(m.notes, "Packet loss while capturing the request")
	//	} else {
	//		m.notes = append(m.notes, "Packet loss while capturing the response")
	//	}
	//
	//	msg := stream.data[stream.message.start:stream.message.end]
	//	sqlserver.handlesqlserver(sqlserver, stream.message, tcptuple, dir, msg, sqlserverData)
	//
	//	// and reset message
	//	stream.prepareForNewMessage()
	//}
	return sqlserverData, true
}
func (sqlserver *sqlserverPlugin) ConnectionTimeout() time.Duration {
	return sqlserver.transactionTimeout
}

func initPrivData(id uuid.UUID, tcptuple *common.TCPTuple) sqlserverPrivateData {
	return sqlserverPrivateData{
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
		sqlserverMsg: &sqlserverMsg{},
	}
}

func (sqlserver *sqlserverPlugin) publishTransaction(t *sqlserverTransaction) {
	if sqlserver.results == nil {
		return
	}

	logp.Debug("sqlserver", "发布事务消息, trans_id: %s", t.transId)
	evt, pbf := pb.NewBeatEvent(t.ts)
	pbf.SetSource(&t.src)
	pbf.SetDestination(&t.dst)
	pbf.Source.Bytes = int64(t.bytesIn)
	pbf.Destination.Bytes = int64(t.bytesOut)
	pbf.Event.Start = t.ts
	pbf.Event.End = t.endTime
	pbf.Event.Dataset = "sqlserver"
	pbf.Network.Transport = "tcp"
	pbf.Network.Protocol = pbf.Event.Dataset
	pbf.Error.Message = t.notes

	fields := evt.Fields
	fields["type"] = pbf.Event.Dataset
	fields["method"] = t.method
	fields["query"] = t.query
	fields["sqldb"] = t.sqlserver
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
		Program:        "sqlserver",
		Version:        t.serverVersion,
		Os:             "无",
		Hostname:       t.serverHostname,
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
	if sqlserver.sendRequest {
		fields["request"] = t.requestRaw
	}
	if sqlserver.sendResponse {
		fields["response"] = t.responseRaw
	}

	sqlserver.results(evt)
}

func (sqlserver *sqlserverPlugin) removeTransaction(transList []*sqlserverTransaction,
	tuple common.TCPTuple, index int) *sqlserverTransaction {

	trans := transList[index]
	transList = append(transList[:index], transList[index+1:]...)
	if len(transList) == 0 {
		sqlserver.transactions.Delete(trans.tuple.Hashable())
	} else {
		sqlserver.transactions.Put(tuple.Hashable(), transList)
	}

	return trans
}

// TCP会话超时调用
func (sqlserver *sqlserverPlugin) ExpiredTCP(tuple *common.TCPTuple, private protos.ProtocolData) {
	priv, ok := private.(sqlserverPrivateData)
	if !ok {
		logp.Debug("sqlserver", "发布会话消息: 解析失败")
		return
	}

	sqlserver.publishSession(tuple, priv, "timeout")
}
func (sqlserver *sqlserverPlugin) publishSession(tuple *common.TCPTuple, priv sqlserverPrivateData, closeType string) {
	logp.Debug("sqlserver", "发布会话消息, session_id: %s", priv.tcpSession.SessionId)

	src, dst := common.MakeEndpointPair(priv.tcpSession.TcpTuple.BaseTuple, nil)
	now := time.Now()
	evt, pbf := pb.NewBeatEvent(now)

	pbf.SetSource(&src)
	//pbf.AddIP(t.src.IP)
	pbf.SetDestination(&dst)
	//pbf.AddIP(t.dst.IP)

	fields := evt.Fields
	fields["type"] = "sqlserver"
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
	fields["protocoltype"] = "sqlserver"
	fields["clientinfo"] = protos.ClientInfo{
		Dbuser:     priv.tcpSession.DbUser,
		Program:    priv.tcpSession.ClientProgram,
		InitDbName: priv.tcpSession.InitDbName,
		//Version:    priv.sqlserverMsg
		Os:       priv.tcpSession.ClientOS,
		Username: priv.tcpSession.ClientUsername,
		Hostname: priv.tcpSession.ClientHostname,
		Arch:     priv.tcpSession.ClientArch,
	}
	fields["serverinfo"] = protos.ServerInfo{
		Program:        "sqlserver",
		Version:        priv.tcpSession.ServerVersion,
		Os:             priv.tcpSession.ServerOS,
		Hostname:       priv.tcpSession.ServerHostname,
		Arch:           priv.tcpSession.ServerArch,
		ServerEncoding: priv.tcpSession.ServerEncoding,
	}

	fields["topic"] = "session"
	sqlserver.results(evt)
}
