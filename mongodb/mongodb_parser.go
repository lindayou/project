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
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"

	"gopkg.in/mgo.v2/bson"
)

var (
	unknownOpcodes = map[opCode]struct{}{}
	mutex          sync.Mutex
)

type Client struct {
	Application Application
	Driver      Driver
	Os          Os
	Platform    string
}
type WriteError struct {
	Code     int
	ErrMsg   string
	Index    int64
	Key      Key
	KeyValue Key
}
type Key struct {
	_id float64
}
type Application struct {
	Name string
}
type Driver struct {
	Name, Version string
}
type Os struct {
	Architecture string
	Name         string
	Version      string
}

func mongodbMessageParser(s *stream, conn *mongodbConnectionData, mongodb *mongodbPlugin, tcptuple *common.TCPTuple) (bool, bool) {
	d := newDecoder(s.data)
	length, err := d.readInt32()
	if err != nil {
		// Not even enough data to parse length of message
		return true, false
	}

	if length > len(s.data) {
		// Not yet reached the end of message
		return true, false
	}
	// Tell decoder to only consider current message
	d.truncate(length)

	// fill up the header common to all messages
	// see http://docs.mongodb.org/meta-driver/latest/legacy/mongodb-wire-protocol/#standard-message-header
	s.message.messageLength = length

	s.message.requestID, _ = d.readInt32()
	s.message.responseTo, _ = d.readInt32()
	code, _ := d.readInt32()
	//fmt.Println("this is code", code)
	opCode := opCode(code)

	if !validOpcode(opCode) {
		mutex.Lock()
		defer mutex.Unlock()
		if _, reported := unknownOpcodes[opCode]; !reported {
			logp.Err("Unknown operation code: %d (%v)", opCode, opCode)
			unknownOpcodes[opCode] = struct{}{}
		}
		return false, false
	}

	s.message.opCode = opCode
	s.message.isResponse = false // default is that the message is a request. If not opReplyParse will set this to false
	s.message.expectsResponse = false
	debugf("opCode = %d (%v)", s.message.opCode, s.message.opCode)

	// then split depending on operation type
	s.message.event = common.MapStr{}
	//change
	s.message.tcpTuple = *tcptuple
	s.message.cmdlineTuple = mongodb.watcher.FindProcessesTupleTCP(tcptuple.IPPort())
	switch s.message.opCode {
	case opReply:
		s.message.isResponse = true
		return opReplyParse(d, s.message, conn)
	case opMsgLegacy:
		s.message.method = "msg"
		return opMsgLegacyParse(d, s.message)
	case opUpdate:
		s.message.method = "update"
		return opUpdateParse(d, s.message)
	case opInsert:
		s.message.method = "insert"
		return opInsertParse(d, s.message)
	case opQuery:
		s.message.expectsResponse = true
		return opQueryParse(d, s.message, conn)
	case opGetMore:
		s.message.method = "getMore"
		s.message.expectsResponse = true
		return opGetMoreParse(d, s.message)
	case opDelete:
		s.message.method = "delete"
		return opDeleteParse(d, s.message)
	case opKillCursor:
		s.message.method = "killCursors"
		return opKillCursorsParse(d, s.message)
	case opMsg:
		s.message.method = "msg"
		var ok, complete bool
		for {
			if d.i < s.message.messageLength {
				ok, complete = opMsgParse(d, s.message, mongodb, conn)
			} else {
				break
			}

		}

		return ok, complete
	}

	return false, false
}

// see http://docs.mongodb.org/meta-driver/latest/legacy/mongodb-wire-protocol/#op-reply
func opReplyParse(d *decoder, m *mongodbMessage, conn *mongodbConnectionData) (bool, bool) {
	_, err := d.readInt32() // ignore flags for now
	m.event["cursorId"], err = d.readInt64()
	m.event["startingFrom"], err = d.readInt32()

	numberReturned, err := d.readInt32()
	m.event["numberReturned"] = numberReturned

	debugf("Prepare to read %d document from reply", m.event["numberReturned"])

	documents := make([]interface{}, numberReturned)
	for i := 0; i < numberReturned; i++ {
		var document bson.M
		document, err = d.readDocument()

		//if v, isFirst := document["maxWireVersion"]; isFirst {
		//	m, isTrue := v.(int)
		//	if isTrue {
		//		conn.tcpSession.ServerVersion = strconv.Itoa(m)
		//
		//	}
		//}

		// Check if the result is actually an error
		if i == 0 {
			if mongoError, present := document["$err"]; present {
				m.error, err = doc2str(mongoError)
			}

			if writeErrors, present := document["writeErrors"]; present {
				m.error, err = doc2str(writeErrors)
			}
		}

		documents[i] = document
	}
	m.documents = documents

	if err != nil {
		logp.Err("An error occurred while parsing OP_REPLY message: %s", err)
		return false, false
	}
	return true, true
}

func opMsgLegacyParse(d *decoder, m *mongodbMessage) (bool, bool) {
	var err error
	m.event["message"], err = d.readCStr()
	if err != nil {
		logp.Err("An error occurred while parsing OP_MSG message: %s", err)
		return false, false
	}
	return true, true
}

func opUpdateParse(d *decoder, m *mongodbMessage) (bool, bool) {
	_, err := d.readInt32() // always ZERO, a slot reserved in the protocol for future use
	m.event["fullCollectionName"], err = d.readCStr()
	_, err = d.readInt32() // ignore flags for now

	m.event["selector"], err = d.readDocumentStr()
	m.event["update"], err = d.readDocumentStr()

	if err != nil {
		logp.Err("An error occurred while parsing OP_UPDATE message: %s", err)
		return false, false
	}

	return true, true
}

func opInsertParse(d *decoder, m *mongodbMessage) (bool, bool) {
	_, err := d.readInt32() // ignore flags for now
	m.event["fullCollectionName"], err = d.readCStr()

	// TO-DO parse bson documents
	// Not too bad if it is not done, as all recent mongodb clients send insert as a command over a query instead of this
	// Find an old client to generate a pcap with legacy protocol ?

	if err != nil {
		logp.Err("An error occurred while parsing OP_INSERT message: %s", err)
		return false, false
	}

	return true, true
}

func extractDocuments(query map[string]interface{}) []interface{} {
	docsVi, present := query["documents"]
	if !present {
		return []interface{}{}
	}

	docs, ok := docsVi.([]interface{})
	if !ok {
		return []interface{}{}
	}
	return docs
}

// Try to guess whether this key:value pair found in
// the query represents a command.
func isDatabaseCommand(key string, val interface{}) bool {
	nameExists := false
	for _, cmd := range databaseCommands {
		if strings.EqualFold(cmd, key) {
			nameExists = true
			break
		}
	}
	if !nameExists {
		return false
	}
	// value should be either a string or the value 1
	_, ok := val.(string)
	num, _ := val.(float64)
	if ok || num == 1 {
		return true
	}
	return false
}

func opQueryParse(d *decoder, m *mongodbMessage, conn *mongodbConnectionData) (bool, bool) {
	_, err := d.readInt32() // ignore flags for now
	fullCollectionName, err := d.readCStr()
	m.event["fullCollectionName"] = fullCollectionName

	m.event["numberToSkip"], err = d.readInt32()
	m.event["numberToReturn"], err = d.readInt32()

	query, err := d.readDocument()
	if v, isFirst := query["client"]; isFirst {
		val, _ := json.Marshal(v)
		var client Client
		_ = json.Unmarshal(val, &client)
		m.clientProgram = client.Application.Name
		m.clientOS = client.Os.Name
		m.clientArch = client.Os.Architecture
		m.clientVersion = client.Driver.Version

	}

	if d.i < len(d.in) {
		m.event["returnFieldsSelector"], err = d.readDocumentStr()
	}

	// Actual method is either a 'find' or a command passing through a query
	if strings.HasSuffix(fullCollectionName, ".$cmd") {
		m.method = "otherCommand"
		m.resource = fullCollectionName
		for key, val := range query {
			debugf("key=%v val=%s", key, val)
			if isDatabaseCommand(key, val) {
				debugf("is db command")
				col, ok := val.(string)
				if ok {
					// replace $cmd with the actual collection name
					m.resource = fullCollectionName[:len(fullCollectionName)-4] + col
				}
				delete(query, key)
				m.method = key
			}
		}
	} else {
		m.method = "find"
		m.resource = fullCollectionName
	}

	m.params = query

	if err != nil {
		logp.Err("An error occurred while parsing OP_QUERY message: %s", err)
		return false, false
	}

	return true, true
}

func opGetMoreParse(d *decoder, m *mongodbMessage) (bool, bool) {
	_, err := d.readInt32() // always ZERO, a slot reserved in the protocol for future use
	m.event["fullCollectionName"], err = d.readCStr()
	m.event["numberToReturn"], err = d.readInt32()
	m.event["cursorId"], err = d.readInt64()

	if err != nil {
		logp.Err("An error occurred while parsing OP_GET_MORE message: %s", err)
		return false, false
	}
	return true, true
}

func opDeleteParse(d *decoder, m *mongodbMessage) (bool, bool) {
	_, err := d.readInt32() // always ZERO, a slot reserved in the protocol for future use
	m.event["fullCollectionName"], err = d.readCStr()
	_, err = d.readInt32() // ignore flags for now

	m.event["selector"], err = d.readDocumentStr()

	if err != nil {
		logp.Err("An error occurred while parsing OP_DELETE message: %s", err)
		return false, false
	}

	return true, true
}

func opKillCursorsParse(d *decoder, m *mongodbMessage) (bool, bool) {
	// TO-DO ? Or not, content is not very interesting.
	return true, true
}

func opMsgParse(d *decoder, m *mongodbMessage, mongodb *mongodbPlugin, conn *mongodbConnectionData) (bool, bool) {
	// ignore flagbits
	if !m.isContinue {
		_, err := d.readInt32()
		if err != nil {
			logp.Err("An error occurred while parsing OP_MSG message: %s", err)
			return false, false
		}

	}
	// read sections
	kind, err := d.readByte()
	if err != nil {
		logp.Err("An error occurred while parsing OP_MSG message: %s", err)
		return false, false
	}
	switch msgKind(kind) {
	case msgKindBody:
		document, err := d.readDocument()
		if err != nil {
			logp.Err("An error occurred while parsing OP_MSG message: %s", err)
			return false, false
		}
		m.params = document
		str, err := doc2str(document)
		if err != nil {
			logp.Warn("Failed to JSON marshal document from Mongo: %v (error: %v)", str, err)
		} else {
			m.body = str
		}

		id := m.responseTo
		key := transactionKey{tcp: m.tcpTuple.Hashable(), id: id}

		// try to find matching request
		if v := mongodb.requests.Get(key); v != nil {
			m.isResponse = true
		}

		err = dealErrAndMsg(m, conn, document)
		if err != nil {
			logp.Err("An error occurred while parsing OP_MSG message in dealErrAndMsg: %s", err)
		}
		m.documents = []interface{}{document}
		if d.i < m.messageLength {
			m.isContinue = true
		}

	case msgKindDocumentSequence:

		start := d.i
		size, err := d.readInt32()
		if err != nil {
			logp.Err("An error occurred while parsing OP_MSG message: %s", err)
			return false, false
		}
		cstring, err := d.readCStr()
		if err != nil {
			logp.Err("An error occurred while parsing OP_MSG message: %s", err)
			return false, false
		}
		m.event["message"] = cstring
		var documents []interface{}
		for d.i < start+size {
			document, err := d.readDocument()

			if err != nil {
				logp.Err("An error occurred while parsing OP_MSG message: %s", err)
				return false, false
			}
			documents = append(documents, document)

			if len(documents) > 0 {

				docs := make([]string, 0, len(documents))
				for _, doc := range documents {

					str, err := doc2str(doc)
					if err != nil {
						logp.Warn("Failed to JSON marshal document from Mongo: %v (error: %v)", doc, err)
					} else {

						docs = append(docs, str)
					}
				}
				m.query = docs
			}

		}

		m.documents = documents

	default:
		logp.Err("Unknown message kind: %v", kind)
		return false, false
	}

	return true, true
}

// NOTE: The following functions are inspired by the source of the go-mgo/mgo project
// https://github.com/go-mgo/mgo/blob/v2/bson/decode.go

type decoder struct {
	in []byte
	i  int
}

func newDecoder(in []byte) *decoder {
	return &decoder{in, 0}
}

func (d *decoder) truncate(length int) {
	d.in = d.in[:length]
}

func (d *decoder) readCStr() (string, error) {
	start := d.i
	end := start
	l := len(d.in)
	for ; end != l; end++ {
		if d.in[end] == '\x00' {
			break
		}
	}
	d.i = end + 1
	if d.i > l {
		return "", errors.New("cstring not finished")
	}
	return string(d.in[start:end]), nil
}

func (d *decoder) readByte() (byte, error) {
	i := d.i
	d.i++
	if d.i > len(d.in) {
		return 0, errors.New("Read byte failed")
	}
	return d.in[i], nil
}

func (d *decoder) readInt32() (int, error) {
	b, err := d.readBytes(4)

	if err != nil {
		return 0, err
	}

	return int((uint32(b[0]) << 0) |
		(uint32(b[1]) << 8) |
		(uint32(b[2]) << 16) |
		(uint32(b[3]) << 24)), nil
}

func (d *decoder) readInt64() (int, error) {
	b, err := d.readBytes(8)

	if err != nil {
		return 0, err
	}

	return int((uint64(b[0]) << 0) |
		(uint64(b[1]) << 8) |
		(uint64(b[2]) << 16) |
		(uint64(b[3]) << 24) |
		(uint64(b[4]) << 32) |
		(uint64(b[5]) << 40) |
		(uint64(b[6]) << 48) |
		(uint64(b[7]) << 56)), nil
}

func (d *decoder) readDocument() (bson.M, error) {
	start := d.i
	documentLength, err := d.readInt32()
	d.i = start + documentLength
	if len(d.in) < d.i {
		return nil, errors.New("document out of bounds")
	}

	documentMap := bson.M{}

	debugf("Parse %d bytes document from remaining %d bytes", documentLength, len(d.in)-start)
	err = bson.Unmarshal(d.in[start:d.i], documentMap)
	if err != nil {
		debugf("Unmarshall error %v", err)
		return nil, err
	}
	return documentMap, err
}

func doc2str(documentMap interface{}) (string, error) {
	document, err := json.Marshal(documentMap)
	return string(document), err
}

func (d *decoder) readDocumentStr() (string, error) {
	documentMap, err := d.readDocument()
	document, err := doc2str(documentMap)
	return document, err
}

func (d *decoder) readBytes(length int32) ([]byte, error) {
	start := d.i
	d.i += int(length)
	if d.i > len(d.in) {
		return *new([]byte), errors.New("No byte to read")
	}
	return d.in[start : start+int(length)], nil
}
func dealErrAndMsg(m *mongodbMessage, conn *mongodbConnectionData, document bson.M) error {
	var err error
	if mongoError, present := document["$err"]; present {
		m.isError = true
		m.error, err = doc2str(mongoError)
		if err != nil {
			return err
		}
		m.errorInfo = m.error
	}

	if writeErrors, present := document["writeErrors"]; present {
		m.isError = true

		m.error, err = doc2str(writeErrors)
		val, err := json.Marshal(writeErrors)
		if err != nil {
			logp.Err("An error occurred while parsing OP_MSG message: %s", err)
			return err

		}
		var wrErr []WriteError
		err = json.Unmarshal(val, &wrErr)
		m.errorInfo = wrErr[0].ErrMsg
		m.errorCode = strconv.Itoa(wrErr[0].Code)

	}

	if errMessage, isFirst := document["errmsg"]; isFirst {
		m.isError = true
		if errMsg, isTrue := errMessage.(string); isTrue {
			m.errorInfo = errMsg
		}
		m.isResponse = true
		errCode, _ := document["code"]
		if errorCode, isTrue := errCode.(int); isTrue {
			m.errorCode = strconv.Itoa(errorCode)
		}

		codeName, _ := document["codeName"]
		if errName, isTrue := codeName.(string); isTrue {
			m.error = errName
		}

	}
	loginVer, a := document["version"]
	_, b := document["versionArray"]

	if a && b {
		m.isLoginSuc = true
		if version, isString := loginVer.(string); isString {
			m.serverVersion = version
			conn.tcpSession.ServerVersion = version
		}
	}
	insertTab, isInsert := document["insert"]
	if isInsert {
		m.method = "insert"
		m.event["table"] = insertTab
	}
	findTab, isFind := document["find"]
	if isFind {
		m.method = "find"
		m.event["table"] = findTab
	}
	deleteTab, isDelete := document["delete"]
	if isDelete {
		m.method = "delete"
		m.event["table"] = deleteTab
	}
	updateTab, isUpdate := document["update"]
	if isUpdate {
		m.method = "update"
		m.event["table"] = updateTab
	}
	createTab, isCreate := document["create"]
	if isCreate {
		m.method = "create"
		m.event["table"] = createTab
	}

	limitNum, isLimit := document["limit"]
	if isLimit {
		m.event["limit"] = limitNum
	}
	skipNum, isSkip := document["skip"]
	if isSkip {
		m.event["skip"] = skipNum
	}

	return nil
}
