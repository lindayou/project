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

package redis

import (
	"bytes"
	"github.com/gofrs/uuid"
	"strings"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/monitoring"

	"github.com/elastic/beats/v7/packetbeat/pb"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/applayer"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
)

type stream struct {
	applayer.Stream
	parser   parser
	tcptuple *common.TCPTuple
}

type redisConnectionData struct {
	streams    [2]*stream
	requests   MessageQueue
	responses  MessageQueue
	tcpSession *tcp.TCPSession
}

// Redis protocol plugin
type redisPlugin struct {
	// config
	ports              []int
	sendRequest        bool
	sendResponse       bool
	transactionTimeout time.Duration
	queueConfig        MessageQueueConfig

	watcher procs.ProcessesWatcher
	results protos.Reporter
}

var (
	debugf  = logp.MakeDebug("redis")
	isDebug = false
)

var (
	unmatchedResponses = monitoring.NewInt(nil, "redis.unmatched_responses")
	unmatchedRequests  = monitoring.NewInt(nil, "redis.unmatched_requests")
)

func init() {
	protos.Register("redis", New)
}

func New(
	testMode bool,
	results protos.Reporter,
	watcher procs.ProcessesWatcher,
	cfg *common.Config,
) (protos.Plugin, error) {
	p := &redisPlugin{}
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

func (redis *redisPlugin) init(results protos.Reporter, watcher procs.ProcessesWatcher, config *redisConfig) error {
	redis.setFromConfig(config)

	redis.results = results
	redis.watcher = watcher
	isDebug = logp.IsDebug("redis")

	return nil
}

func (redis *redisPlugin) setFromConfig(config *redisConfig) {
	redis.ports = config.Ports
	redis.sendRequest = config.SendRequest
	redis.sendResponse = config.SendResponse
	redis.transactionTimeout = config.TransactionTimeout
	redis.queueConfig = config.QueueLimits
}

func (redis *redisPlugin) GetPorts() []int {
	return redis.ports
}

func (s *stream) PrepareForNewMessage() {
	parser := &s.parser
	s.Stream.Reset()
	parser.reset()
}

func (redis *redisPlugin) ConnectionTimeout() time.Duration {
	return redis.transactionTimeout
}

func (redis *redisPlugin) Parse(
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
	private protos.ProtocolData,
) protos.ProtocolData {
	defer logp.Recover("ParseRedis exception")

	conn := redis.ensureRedisConnection(private, tcptuple)
	conn = redis.doParse(conn, pkt, tcptuple, dir)
	if conn == nil {
		return nil
	}
	return conn
}
func (redis *redisPlugin) newConnectionData() *redisConnectionData {
	return &redisConnectionData{
		requests:  NewMessageQueue(redis.queueConfig),
		responses: NewMessageQueue(redis.queueConfig),
	}
}

func (redis *redisPlugin) ensureRedisConnection(private protos.ProtocolData, tcptuple *common.TCPTuple) *redisConnectionData {
	if private == nil {
		id, err := uuid.NewV4()
		if err != nil {
			panic(err)
		}
		return &redisConnectionData{
			requests:   NewMessageQueue(redis.queueConfig),
			responses:  NewMessageQueue(redis.queueConfig),
			tcpSession: initTcpSession(id, tcptuple),
		}
		//return redis.newConnectionData()
	}

	priv, ok := private.(*redisConnectionData)
	if !ok {
		logp.Warn("redis connection data type error, create new one")
		id, err := uuid.NewV4()
		if err != nil {
			panic(err)
		}

		return &redisConnectionData{
			requests:   NewMessageQueue(redis.queueConfig),
			responses:  NewMessageQueue(redis.queueConfig),
			tcpSession: initTcpSession(id, tcptuple),
		}
	}
	if priv == nil {
		logp.Warn("Unexpected: redis connection data not set, create new one")
		return redis.newConnectionData()
	}

	return priv
}

func (redis *redisPlugin) doParse(
	conn *redisConnectionData,
	pkt *protos.Packet,
	tcptuple *common.TCPTuple,
	dir uint8,
) *redisConnectionData {

	st := conn.streams[dir]
	if st == nil {
		st = newStream(pkt.Ts, tcptuple)
		conn.streams[dir] = st
		if isDebug {
			debugf("new stream: %p (dir=%v, len=%v)", st, dir, len(pkt.Payload))
		}
	}

	if err := st.Append(pkt.Payload); err != nil {
		if isDebug {
			debugf("%v, dropping TCP stream: ", err)
		}
		return nil
	}
	if isDebug {
		debugf("stream add data: %p (dir=%v, len=%v)", st, dir, len(pkt.Payload))
	}

	for st.Buf.Len() > 0 {
		if st.parser.message == nil {
			st.parser.message = newMessage(pkt.Ts)
		}

		ok, complete := st.parser.parse(&st.Buf, conn)
		if !ok {
			// drop this tcp stream. Will retry parsing with the next
			// segment in it
			conn.streams[dir] = nil
			if isDebug {
				debugf("Ignore Redis message. Drop tcp stream. Try parsing with the next segment")
			}
			return conn
		}

		if !complete {
			// wait for more data
			break
		}

		msg := st.parser.message

		if isDebug {
			if msg.isRequest {
				debugf("REDIS (%p) request message: %s", conn, msg.message)
			} else {
				debugf("REDIS (%p) response message: %s", conn, msg.message)
			}
		}

		// all ok, go to next level and reset stream for new message
		redis.handleRedis(conn, msg, tcptuple, dir)
		st.PrepareForNewMessage()
	}

	return conn
}

func newStream(ts time.Time, tcptuple *common.TCPTuple) *stream {
	s := &stream{
		tcptuple: tcptuple,
	}
	s.parser.message = newMessage(ts)
	s.Stream.Init(tcp.TCPMaxDataInStream)
	return s
}

func newMessage(ts time.Time) *redisMessage {
	return &redisMessage{ts: ts}
}

func (redis *redisPlugin) handleRedis(
	conn *redisConnectionData,
	m *redisMessage,
	tcptuple *common.TCPTuple,
	dir uint8,
) {
	m.tcpTuple = *tcptuple
	m.direction = dir
	m.cmdlineTuple = redis.watcher.FindProcessesTupleTCP(tcptuple.IPPort())

	if m.isRequest {
		// wait for response
		if evicted := conn.requests.Append(m); evicted > 0 {
			unmatchedRequests.Add(int64(evicted))
		}
	} else {
		if evicted := conn.responses.Append(m); evicted > 0 {
			unmatchedResponses.Add(int64(evicted))
		}
		redis.correlate(conn)
	}
}

func (redis *redisPlugin) correlate(conn *redisConnectionData) {
	// drop responses with missing requests
	if conn.requests.IsEmpty() {
		//running
		for !conn.responses.IsEmpty() {
			//running
			debugf("Response from unknown transaction. Ignoring")
			unmatchedResponses.Add(1)
			conn.responses.Pop()
		}
		return
	}
	// merge requests with responses into transactions
	for !conn.responses.IsEmpty() && !conn.requests.IsEmpty() {

		conn.tcpSession.QueryTimes += 1
		// remove conn.re.head (nil)
		requ, okReq := conn.requests.Pop().(*redisMessage)
		resp, okResp := conn.responses.Pop().(*redisMessage)
		if isAuth(string(requ.message)) && isAuthOk(string(resp.message)) {
			event := redis.newTransaction(requ, resp, conn)
			redis.results(event)
		}
		if !okReq || !okResp {
			logp.Err("invalid type found in message queue")
			continue
		}
		if redis.results != nil {
			event := redis.newTransaction(requ, resp, conn)
			redis.results(event)
		}
	}
}

func (redis *redisPlugin) newTransaction(requ, resp *redisMessage, conn *redisConnectionData) beat.Event {
	source, destination := common.MakeEndpointPair(requ.tcpTuple.BaseTuple, requ.cmdlineTuple)
	src, dst := &source, &destination
	if requ.direction == tcp.TCPDirectionReverse {
		src, dst = dst, src
	}

	evt, pbf := pb.NewBeatEvent(requ.ts)
	pbf.SetSource(src)
	pbf.SetDestination(dst)
	pbf.Source.Bytes = int64(requ.size)
	pbf.Destination.Bytes = int64(resp.size)
	pbf.Event.Dataset = "redis"
	pbf.Event.Start = requ.ts
	pbf.Event.End = resp.ts
	pbf.Network.Transport = "tcp"
	pbf.Network.Protocol = pbf.Event.Dataset

	fields := evt.Fields
	fields["type"] = pbf.Event.Dataset
	resp.redis = common.MapStr{}
	if isAuth(string(requ.message)) && isAuthOk(string(resp.message)) && !resp.isFirst {
		fields["method"] = ""
		resp.redis.Update(common.MapStr{
			"method": "",
		})
	} else {
		fields["method"] = common.NetString(bytes.ToUpper(requ.method))
		resp.redis.Update(common.MapStr{
			"method": common.NetString(bytes.ToUpper(requ.method)),
		})
	}

	//fields["resource"] = requ.path
	if isAuth(string(requ.message)) && isAuthOk(string(resp.message)) && !resp.isFirst {
		fields["query"] = "登录"
		resp.isFirst = true
	} else {
		fields["query"] = requ.message
	}

	//add field
	fields["clientinfo"] = protos.ClientInfo{
		Dbuser:         "无",
		InitDbName:     "无",
		Program:        "无",
		Version:        "无",
		Os:             "无",
		Username:       "无",
		Hostname:       "无",
		Arch:           "无",
		ClientEncoding: "无",
	}
	fields["cveinfo"] = protos.CveInfo{
		Id: "",
	}
	fields["serverinfo"] = protos.ServerInfo{
		Program:        "redis",
		Version:        conn.tcpSession.ServerVersion,
		Os:             conn.tcpSession.ServerOS,
		Hostname:       "无",
		Arch:           conn.tcpSession.ServerArch,
		ServerEncoding: "",
	}
	fields["session"] = protos.Session{
		SessionId: conn.tcpSession.SessionId,
	}
	fields["nosqldb"] = protos.NosqlDB{}

	fields["topic"] = "trans"
	id, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	fields["transid"] = id.String()

	resp.redis.Update(common.MapStr{
		//"method":        common.NetString(bytes.ToUpper(requ.method)),
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
	//end

	if resp.isError {
		evt.PutValue("status", common.ERROR_STATUS)
		//evt.PutValue("redis.error", resp.message)
		resp.redis.Update(common.MapStr{
			"error_code":     "",
			"error_message":  resp.message,
			"error_severity": "",
		})
	} else {
		evt.PutValue("status", common.OK_STATUS)
		//evt.PutValue("redis.return_value", resp.message)
	}
	fields["sqldb"] = resp.redis

	if redis.sendRequest {
		fields["request"] = requ.message
	}
	if redis.sendResponse {
		fields["response"] = resp.message
	}

	//pbf.Event.Action = "redis." + strings.ToLower(string(requ.method))
	if resp.isError {
		pbf.Event.Outcome = "failure"
	}

	return evt
}

//add field
func isAuth(m string) bool {
	m = strings.ToLower(m)
	return strings.HasPrefix(m, "auth")
}

func isAuthOk(m string) bool {
	m = strings.ToLower(m)
	return m == "ok"
}

//done
func (redis *redisPlugin) GapInStream(tcptuple *common.TCPTuple, dir uint8,
	nbytes int, private protos.ProtocolData) (priv protos.ProtocolData, drop bool) {

	// tsg: being packet loss tolerant is probably not very useful for Redis,
	// because most requests/response tend to fit in a single packet.

	if private == nil {
		return private, false
	}
	redisData, ok := private.(*redisConnectionData)
	if !ok {
		return private, false
	}
	if redisData.requests.head != nil {
		return redisData, false
	}
	return private, true
}

func (redis *redisPlugin) ReceivedFin(tcptuple *common.TCPTuple, dir uint8,
	private protos.ProtocolData) protos.ProtocolData {

	// TO-DO: check if we have pending data that we can send up the stack
	priv, ok := private.(*redisConnectionData)
	if !ok {
		logp.Debug("redis", "发布事务消息: 解析失败")
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
	redis.publishSession(tcptuple, *priv, "")
	return private
}

//ADD FIELD
func initTcpSession(id uuid.UUID, tcptuple *common.TCPTuple) *tcp.TCPSession {
	return &tcp.TCPSession{
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
	}
}

//END

//ADD FIELD
func (redis *redisPlugin) publishSession(tuple *common.TCPTuple, priv redisConnectionData, closeType string) {
	src, dst := common.MakeEndpointPair(priv.tcpSession.TcpTuple.BaseTuple, nil)
	now := time.Now()
	evt, pbf := pb.NewBeatEvent(now)
	pbf.SetSource(&src)
	//pbf.AddIP(t.src.IP)
	pbf.SetDestination(&dst)
	//pbf.AddIP(t.dst.IP)

	fields := evt.Fields
	fields["type"] = "redis"
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
	fields["protocoltype"] = "redis"
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
		Program:  "redis",
		Version:  priv.tcpSession.ServerVersion,
		Os:       priv.tcpSession.ServerOS,
		Hostname: priv.tcpSession.ServerHostname,
		Arch:     priv.tcpSession.ServerArch,
	}

	fields["topic"] = "session"
	redis.results(evt)
	logp.Debug("redis", "发布会话消息, session_id: %s", priv.tcpSession.SessionId)
}

//END

//ADD FIELD
// TCP会话超时调用
func (redis *redisPlugin) ExpiredTCP(tuple *common.TCPTuple, private protos.ProtocolData) {
	priv, ok := private.(*redisConnectionData)
	if !ok {
		logp.Debug("mongodb", "发布会话消息: 解析失败")
		return
	}
	redis.publishSession(tuple, *priv, "timeout")
}

//END
