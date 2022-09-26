package oracle

import (
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/monitoring"
	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/ssl"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
	"github.com/gofrs/uuid"
	"go.uber.org/zap"
	"strings"
	"time"
)

var (
	unmatchedResponses = monitoring.NewInt(nil, "oracle.unmatched_responses")
)

func init() {
	protos.Register("oracle", New)
}
func New(
	testMode bool,
	results protos.Reporter,
	watcher procs.ProcessesWatcher,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &oraclePlugin{}
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

func (oracle *oraclePlugin) init(results protos.Reporter, watcher procs.ProcessesWatcher, config *oracleConfig) error {
	oracle.setFromConfig(config)

	oracle.log = logp.NewLogger("sqlserver")
	oracle.debug = logp.NewLogger("sqlserver", zap.AddCallerSkip(1))
	oracle.detail = logp.NewLogger("sqlserverdetailed", zap.AddCallerSkip(1))
	oracle.isDebug, oracle.isDetail = logp.IsDebug("sqlserver"), logp.IsDebug("sqlserverdetailed")

	oracle.transactions = common.NewCache(
		oracle.transactionTimeout,
		protos.DefaultTransactionHashSize)
	oracle.transactions.StartJanitor(oracle.transactionTimeout)
	oracle.handleOracle = handleOracle
	oracle.results = results
	oracle.watcher = watcher

	return nil
}
func (oralce *oraclePlugin) setFromConfig(config *oracleConfig) {
	oralce.ports = config.Ports
	oralce.maxRowLength = config.MaxRowLength
	oralce.maxStoreRows = config.MaxRows
	oralce.sendRequest = config.SendRequest
	oralce.sendResponse = config.SendResponse
	oralce.transactionTimeout = config.TransactionTimeout
}
func (oralce *oraclePlugin) getTransaction(k common.HashableTCPTuple) []*oracleTransaction {
	v := oralce.transactions.Get(k)
	if v != nil {
		return v.([]*oracleTransaction)
	}
	return nil
}

//go:inline
func (oracle *oraclePlugin) debugf(format string, v ...interface{}) {
	if oracle.isDebug {
		oracle.debug.Debugf(format, v...)
	}
}

//go:inline
func (oracle *oraclePlugin) detailf(format string, v ...interface{}) {
	if oracle.isDetail {
		oracle.detail.Debugf(format, v...)
	}
}
func (oracle *oraclePlugin) GetPorts() []int {
	return oracle.ports
}

func (stream *oracleStream) prepareForNewMessage() {
	stream.data = stream.data[stream.message.size-1:]
	//stream.parseState = sqlserverStartState
	stream.parseOffset = 0
	stream.message = nil
}

var handleOracle = func(oracle *oraclePlugin, m *oracleMessage, tcptuple *common.TCPTuple,
	dir uint8, raw_msg []byte, priv oraclePrivateData) {

	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = oracle.watcher.FindProcessesTupleTCP(tcptuple.IPPort())
	if m.isRequest {
		oracle.receivedSqlserverRequest(m, priv, dir)
	} else {
		oracle.receivedSqlserverResponse(m, priv)
	}
}

func (oracle *oraclePlugin) receivedSqlserverRequest(msg *oracleMessage, priv oraclePrivateData, dir uint8) {
	tuple := msg.tcpTuple
	m := priv.data[dir].message
	// parse the query, as it might contain a list of sqlserver command
	// separated by ';'

	transList := oracle.getTransaction(tuple.Hashable())
	if transList == nil {
		transList = []*oracleTransaction{}
	}

	id, err := uuid.NewV4()

	if err != nil {
		panic(err)
	}

	trans := &oracleTransaction{
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

	trans.oracle = common.MapStr{}
	trans.query = m.query
	//trans.method = getQueryMethod(m.query)
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

	oracle.transactions.Put(tuple.Hashable(), transList)
}

func (oracle *oraclePlugin) receivedSqlserverResponse(msg *oracleMessage, priv oraclePrivateData) {
	tuple := msg.tcpTuple
	transList := oracle.getTransaction(tuple.Hashable())
	if transList == nil || len(transList) == 0 {
		oracle.debugf("Response from unknown transaction. Ignoring.")
		unmatchedResponses.Add(1)
		return
	}

	// extract the first transaction from the array
	trans := oracle.removeTransaction(transList, tuple, 0)

	// check if the request was received
	if trans.oracle == nil {
		oracle.debugf("Response from unknown transaction. Ignoring.")
		unmatchedResponses.Add(1)
		return
	}
	if strings.ToLower(trans.method) == "select" {
		msg.affectedRows = 0
	}
	trans.oracle.Update(common.MapStr{
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
		trans.oracle.Update(common.MapStr{
			"error_code":     msg.errorCode,
			"error_message":  msg.errorInfo,
			"error_severity": msg.errorSeverity,
		})

	} else {
		trans.oracle["status"] = common.OK_STATUS
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
	oracle.publishTransaction(trans)

	oracle.debugf("Sqlserver transaction completed: %s\n%s", trans.oracle, trans.responseRaw)
}

func (oracle *oraclePlugin) Parse(pkt *protos.Packet, tcptuple *common.TCPTuple,
	dir uint8, private protos.ProtocolData) protos.ProtocolData {

	defer logp.Recover("ParseOracle exception")

	priv := oraclePrivateData{}
	if private != nil {
		var ok bool
		priv, ok = private.(oraclePrivateData)
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
		priv.data[dir] = &oracleStream{
			data:    pkt.Payload,
			message: &oracleMessage{ts: pkt.Ts},
		}
		oracle.detailf("New stream created")
	} else {
		// concatenate bytes
		priv.data[dir].data = append(priv.data[dir].data, pkt.Payload...)
		oracle.detailf("Len data: %d cap data: %d", len(priv.data[dir].data), cap(priv.data[dir].data))
		if len(priv.data[dir].data) > tcp.TCPMaxDataInStream {
			oracle.debugf("Stream data too large, dropping TCP stream")
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
			stream.message = &oracleMessage{ts: pkt.Ts}
		}
		if !priv.tcpSession.IsCrypto {
			ok, complete := oracle.oracleMessageParser(priv, dir)

			if !ok {
				// drop this tcp stream. Will retry parsing with the next
				// segment in it
				priv.data[dir] = nil
				oracle.debugf("Ignore Postgresql message. Drop tcp stream. Try parsing with the next segment")
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
						oracle.handleOracle(oracle, stream.message, tcptuple, dir, msg, priv)
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
func (oracle *oraclePlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {
	priv, ok := private.(oraclePrivateData)
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
	oracle.publishSession(tcptuple, priv, "")
	return private
}
func (oracle *oraclePlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	defer logp.Recover("GapInOracleStream exception")

	if private == nil {
		return private, false
	}
	oracleData, ok := private.(oraclePrivateData)
	if !ok {
		return private, false
	}
	if oracleData.data[dir] == nil {
		return oracleData, false
	}

	// If enough data was received, send it to the
	// next layer but mark it as incomplete.

	//stream := oracleData.data[dir]
	//if messageHasEnoughData(stream.message) {
	//	oracle.debugf("Message not complete, but sending to the next layer")
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
	//	oracle.handleOracle(oracle, stream.message, tcptuple, dir, msg, oracleData)
	//
	//	// and reset message
	//	stream.prepareForNewMessage()
	//}
	return oracleData, true
}
func (oracle *oraclePlugin) ConnectionTimeout() time.Duration {
	return oracle.transactionTimeout
}
func initPrivData(id uuid.UUID, tcptuple *common.TCPTuple) oraclePrivateData {
	return oraclePrivateData{
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
		oracleMsg: &oracleMsg{},
	}
}
func (oracle *oraclePlugin) publishTransaction(t *oracleTransaction) {
	if oracle.results == nil {
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
	fields["sqldb"] = t.oracle
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
	if oracle.sendRequest {
		fields["request"] = t.requestRaw
	}
	if oracle.sendResponse {
		fields["response"] = t.responseRaw
	}

	oracle.results(evt)
}
func (oracle *oraclePlugin) removeTransaction(transList []*oracleTransaction,
	tuple common.TCPTuple, index int) *oracleTransaction {

	trans := transList[index]
	transList = append(transList[:index], transList[index+1:]...)
	if len(transList) == 0 {
		oracle.transactions.Delete(trans.tuple.Hashable())
	} else {
		oracle.transactions.Put(tuple.Hashable(), transList)
	}

	return trans
}

// TCP会话超时调用
func (oracle *oraclePlugin) ExpiredTCP(tuple *common.TCPTuple, private protos.ProtocolData) {
	priv, ok := private.(oraclePrivateData)
	if !ok {
		logp.Debug("sqlserver", "发布会话消息: 解析失败")
		return
	}

	oracle.publishSession(tuple, priv, "timeout")
}
func (oracle *oraclePlugin) publishSession(tuple *common.TCPTuple, priv oraclePrivateData, closeType string) {
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
	oracle.results(evt)
}
