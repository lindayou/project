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

package highgo

import (
	"bytes"
	"errors"
	"strconv"
	"strings"

	"github.com/elastic/beats/v7/libbeat/common"
)

var (
	errInvalidString     = errors.New("invalid pgsql string")
	errEmptyFieldsBuffer = errors.New("empty fields buffer")
	errNoFieldName       = errors.New("can not read column field")
	errFieldBufferShort  = errors.New("field buffer to small for field count")
	errFieldBufferBig    = errors.New("field count to small for field buffer size")
)

func (pgsql *pgsqlPlugin) pgsqlMessageParser(priv pgsqlPrivateData, dir uint8) (bool, bool) {
	pgsql.debugf("pgsqlMessageParser, off=%v", priv.data[dir].parseOffset)

	var ok, complete bool

	switch priv.data[dir].parseState {
	case pgsqlStartState:
		ok, complete = pgsql.parseMessageStart(priv, dir)

	case pgsqlGetDataState:
		ok, complete = pgsql.parseMessageData(priv.data[dir])
	case pgsqlExtendedQueryState:
		ok, complete = pgsql.parseMessageExtendedQuery(priv.data[dir])
	default:
		pgsql.log.Error("Pgsql invalid parser state")
	}

	pgsql.detailf("pgsqlMessageParser return: ok=%v, complete=%v, off=%v",
		ok, complete, priv.data[dir].parseOffset)

	return ok, complete
}

func (pgsql *pgsqlPlugin) parseMessageStart(priv pgsqlPrivateData, dir uint8) (bool, bool) {
	pgsql.detailf("parseMessageStart")

	m := priv.data[dir].message
	dataArr := priv.data[dir]

	for len(dataArr.data[dataArr.parseOffset:]) >= 5 {
		isSpecial, length, command := pgsql.isSpecialCommand(dataArr.data[dataArr.parseOffset:])
		if !isSpecial {
			return pgsql.parseCommand(priv, dir)
		}
		//如果是startMessage  解析登录包
		if command == startupMessage {
			//协议主要版本
			dataStartUp := dataArr.data[dataArr.parseOffset:]
			offset := 0
			// 包长度
			//pkgLen := BytesNtohl(dataStartUp[offset: offset + 4])
			offset += 4
			// 协议主版本
			majorVersion := Bytes2(dataStartUp[offset : offset+2])
			priv.pgsqlMsg.MajorVersion = strconv.Itoa(int(majorVersion))
			offset += 2
			// 协议次版本
			minorVersion := Bytes2(dataStartUp[offset : offset+2])
			priv.pgsqlMsg.MinorVersion = strconv.Itoa(int(minorVersion))
			offset += 2

			// 循环解析键值对
			pkgMap := make(map[string]string)

			for len(dataStartUp[offset:]) >= 0 {
				index := bytes.IndexByte(dataStartUp[offset:], 0x00)
				if index <= 0 {
					break
				}
				key := string(dataStartUp[offset : offset+index])
				offset = offset + index + 1

				index = bytes.IndexByte(dataStartUp[offset:], 0x00)
				if index <= 0 {
					break
				}
				val := string(dataStartUp[offset : offset+index])
				offset = offset + index + 1
				pkgMap[key] = val

			}

			for i, item := range pkgMap {
				switch i {
				case "user":
					priv.tcpSession.DbUser = item
				case "database":
					priv.tcpSession.InitDbName = item
				case "client_encoding":
					priv.tcpSession.ClientEncoding = item
				case "datestyle":
					m.dateStyle = item
				case "application_name":
					priv.tcpSession.ClientProgram = item
				}
			}
			m.start = dataArr.parseOffset
			dataArr.parseOffset += length
			m.end = dataArr.parseOffset
			m.size = uint64(m.end - m.start)
			m.isRequest = true
			m.toExport = true
			m.query = "登录"
			return true, true

		}

		// In case of Commands: StartupMessage, SSLRequest, CancelRequest that don't have
		// their type in the first byte

		// check buffer available
		if len(dataArr.data[dataArr.parseOffset:]) <= length {
			pgsql.detailf("Wait for more data 1")
			return true, false
		}

		// ignore non SSLRequest commands
		if command != sslRequest && command != startupMessage {
			priv.data[dir].parseOffset += length
			continue
		}

		// if SSLRequest is received, expect for one byte reply (S or N)
		m.start = dataArr.parseOffset
		dataArr.parseOffset += length
		m.end = dataArr.parseOffset
		m.isSSLRequest = true
		m.size = uint64(m.end - m.start)

		return true, true
	}
	return true, false
}
func BytesNtohl(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 |
		uint32(b[2])<<8 | uint32(b[3])
}
func Bytes2(b []byte) uint32 {
	return uint32(b[0])<<8 | uint32(b[1])
}

func (pgsql *pgsqlPlugin) parseCommand(priv pgsqlPrivateData, dir uint8) (bool, bool) {
	// read type
	typ := byte(priv.data[dir].data[priv.data[dir].parseOffset])
	if priv.data[dir].expectSSLResponse {
		// SSLRequest was received in the other stream
		if typ == 'N' {
			m := priv.data[dir].message

			// one byte reply to SSLRequest
			pgsql.debugf("Reply for SSLRequest %c", typ)
			m.start = priv.data[dir].parseOffset
			priv.data[dir].parseOffset++
			m.end = priv.data[dir].parseOffset
			m.isSSLResponse = true
			m.size = uint64(m.end - m.start)

			return true, true
		} else if typ == 'S' {
			m := priv.data[dir].message
			pgsql.debugf("检测到SSL连接，跳过")
			priv.tcpSession.IsCrypto = true
			// one byte reply to SSLRequest
			pgsql.debugf("Reply for SSLRequest %c", typ)
			m.start = priv.data[dir].parseOffset
			priv.data[dir].parseOffset++
			m.end = priv.data[dir].parseOffset
			m.isSSLResponse = true
			m.size = uint64(m.end - m.start)

			return false, true
		}
	}

	// read length
	length := readLength(priv.data[dir].data[priv.data[dir].parseOffset+1:])
	if length < 4 {
		// length should include the size of itself (int32)
		pgsql.detailf("Invalid pgsql command length.")
		return false, false
	}
	if len(priv.data[dir].data[priv.data[dir].parseOffset:]) <= length {
		pgsql.debugf("Wait for more data")
		return true, false
	}

	pgsql.debugf("Pgsql type %c, length=%d", typ, length)
	switch typ {
	case 'Q':
		return pgsql.parseSimpleQuery(priv.data[dir], length)
	case 'T':
		return pgsql.parseRowDescription(priv.data[dir], length)
	case 'I':
		return pgsql.parseEmptyQueryResponse(priv.data[dir])
	case 'C':
		return pgsql.parseCommandComplete(priv.data[dir], length)
	case 'Z':
		return pgsql.parseReadyForQuery(priv.data[dir], length)
	case 'E':
		return pgsql.parseErrorResponse(priv.data[dir], length)
	case 'P':
		return pgsql.parseExtReq(priv.data[dir], length)
	case '1':
		return pgsql.parseExtResp(priv.data[dir], length)
	case 'S':
		return pgsql.parseServersion(priv.data[dir], length, priv)
	//case 'R':
	//  return pgsql.isAuthSuccess(priv.data[dir], length)

	default:
		if !pgsqlValidType(typ) {
			pgsql.detailf("invalid frame type: '%c'", typ)
			return false, false
		}
		return pgsql.parseSkipMessage(priv.data[dir], length)
	}
}

func (pgsql *pgsqlPlugin) parseSimpleQuery(s *pgsqlStream, length int) (bool, bool) {
	m := s.message
	m.start = s.parseOffset
	m.isRequest = true
	s.parseOffset++ //type
	s.parseOffset += length
	m.end = s.parseOffset
	m.size = uint64(m.end - m.start)

	query, err := pgsqlString(s.data[m.start+5:], length-4)
	if err != nil {
		return false, false
	}

	m.query = query

	m.toExport = true
	pgsql.detailf("Simple Query: %s", m.query)
	return true, true
}

func (pgsql *pgsqlPlugin) parseRowDescription(s *pgsqlStream, length int) (bool, bool) {
	// RowDescription
	m := s.message
	m.start = s.parseOffset
	m.isRequest = false
	m.isOK = true
	m.toExport = true

	err := pgsql.parseFields(s, s.data[s.parseOffset+5:s.parseOffset+length+1])
	if err != nil {
		pgsql.detailf("parseFields failed with: %v", err)
		return false, false
	}
	pgsql.detailf("Fields: %s", m.fields)

	s.parseOffset++         //type
	s.parseOffset += length //length
	s.parseState = pgsqlGetDataState
	return pgsql.parseMessageData(s)
}

// Parse a list of commands separated by semicolon from the query
func pgsqlQueryParser(query string) []string {
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

func (pgsql *pgsqlPlugin) parseEmptyQueryResponse(s *pgsqlStream) (bool, bool) {
	// EmptyQueryResponse, appears as a response for empty queries
	// substitutes CommandComplete

	m := s.message

	pgsql.detailf("EmptyQueryResponse")
	m.start = s.parseOffset
	m.isOK = true
	m.isRequest = false
	m.toExport = true
	s.parseOffset += 5 // type + length
	m.end = s.parseOffset
	m.size = uint64(m.end - m.start)

	return true, true
}

func (pgsql *pgsqlPlugin) parseCommandComplete(s *pgsqlStream, length int) (bool, bool) {
	// CommandComplete -> Successful response

	m := s.message
	m.start = s.parseOffset
	m.isRequest = false
	m.isOK = true
	m.toExport = true

	s.parseOffset++ //type
	name, err := pgsqlString(s.data[s.parseOffset+4:], length-4)
	if err != nil {
		return false, false
	}
	tagArr := strings.Split(name, " ")
	if strings.ToLower(tagArr[0]) == "insert" || strings.ToLower(tagArr[0]) == "update" || strings.ToLower(tagArr[0]) == "delete" {
		affectRow, _ := strconv.ParseUint((tagArr[len(tagArr)-1]), 0, 64)
		m.affectedRows = affectRow
	}

	pgsql.detailf("CommandComplete length=%d, tag=%s", length, name)

	s.parseOffset += length
	m.end = s.parseOffset
	m.size = uint64(m.end - m.start)

	return true, true
}

func (pgsql *pgsqlPlugin) parseReadyForQuery(s *pgsqlStream, length int) (bool, bool) {
	// ReadyForQuery -> backend ready for a new query cycle
	m := s.message
	m.start = s.parseOffset
	m.size = uint64(m.end - m.start)

	s.parseOffset++ // type
	s.parseOffset += length
	m.end = s.parseOffset

	return true, true
}

func (pgsql *pgsqlPlugin) parseErrorResponse(s *pgsqlStream, length int) (bool, bool) {
	// ErrorResponse
	pgsql.detailf("ErrorResponse")

	m := s.message
	m.start = s.parseOffset
	m.isRequest = false
	m.isError = true
	m.toExport = true

	s.parseOffset++ //type
	pgsql.parseError(s, s.data[s.parseOffset+4:s.parseOffset+length])

	s.parseOffset += length //length
	m.end = s.parseOffset
	m.size = uint64(m.end - m.start)

	return true, true
}

func (pgsql *pgsqlPlugin) parseExtReq(s *pgsqlStream, length int) (bool, bool) {
	// Ready for query -> Parse for an extended query request
	pgsql.detailf("Parse")

	m := s.message
	m.start = s.parseOffset
	m.isRequest = true

	s.parseOffset++ //type
	s.parseOffset += length
	m.end = s.parseOffset
	m.size = uint64(m.end - m.start)
	m.toExport = true

	query, err := common.ReadString(s.data[m.start+6:])
	if err != nil {
		pgsql.detailf("Invalid extended query request")
		return false, false
	}
	m.query = query
	pgsql.detailf("Parse in an extended query request: %s", m.query)

	// Ignore SET statement
	if strings.HasPrefix(m.query, "SET ") {
		m.toExport = false
	}
	s.parseState = pgsqlExtendedQueryState
	return pgsql.parseMessageExtendedQuery(s)
}

func (pgsql *pgsqlPlugin) parseExtResp(s *pgsqlStream, length int) (bool, bool) {
	// Sync -> Parse completion for an extended query response
	pgsql.detailf("ParseCompletion")

	m := s.message
	m.start = s.parseOffset
	m.isRequest = false
	m.isOK = true
	m.toExport = true

	s.parseOffset++ //type
	s.parseOffset += length
	pgsql.detailf("Parse completion in an extended query response")
	s.parseState = pgsqlGetDataState
	return pgsql.parseMessageData(s)
}

func (pgsql *pgsqlPlugin) parseSkipMessage(s *pgsqlStream, length int) (bool, bool) {
	// TO-DO: add info from NoticeResponse in case there are warning messages for a query
	// ignore command
	s.parseOffset++ //type
	s.parseOffset += length

	m := s.message
	m.end = s.parseOffset
	m.size = uint64(m.end - m.start)

	// ok and complete, but ignore
	m.toExport = false
	return true, true
}

func (pgsql *pgsqlPlugin) parseFields(s *pgsqlStream, buf []byte) error {
	m := s.message

	if len(buf) < 2 {
		return errEmptyFieldsBuffer
	}

	// read field count (int16)
	off := 2
	fieldCount := readCount(buf)

	fields := []string{}
	fieldsFormat := []byte{}

	for i := 0; i < fieldCount; i++ {
		if len(buf) <= off {
			return errFieldBufferShort
		}

		// read field name (null terminated string)
		fieldName, err := common.ReadString(buf[off:])
		if err != nil {
			return errNoFieldName
		}
		fields = append(fields, fieldName)
		m.numberOfFields++
		off += len(fieldName) + 1

		// read Table OID (int32)
		off += 4

		// read Column Index (int16)
		off += 2

		// read Type OID (int32)
		off += 4

		// read column length (int16)
		off += 2

		// read type modifier (int32)
		off += 4

		// read format (int16)
		if len(buf) < off+2 {
			return errFieldBufferShort
		}
		format := common.BytesNtohs(buf[off : off+2])
		off += 2
		fieldsFormat = append(fieldsFormat, byte(format))
	}

	if off < len(buf) {
		return errFieldBufferBig
	}

	m.fields = fields
	m.fieldsFormat = fieldsFormat
	if m.numberOfFields != fieldCount {
		pgsql.log.Errorf("Missing fields from RowDescription. Expected %d. Received %d",
			fieldCount, m.numberOfFields)
	}
	return nil
}

func (pgsql *pgsqlPlugin) parseError(s *pgsqlStream, buf []byte) {
	m := s.message
	off := 0
	for off < len(buf) {
		// read field type(byte1)
		typ := buf[off]
		if typ == 0 {
			break
		}

		// read field value(string)
		val, err := common.ReadString(buf[off+1:])
		if err != nil {
			pgsql.log.Error("Failed to read the column field")
			break
		}
		off += len(val) + 2

		switch typ {
		case 'M':
			m.errorInfo = val
		case 'C':
			m.errorCode = val
		case 'S':
			m.errorSeverity = val
		}
	}
	pgsql.detailf("%s %s %s", m.errorSeverity, m.errorCode, m.errorInfo)
}

func (pgsql *pgsqlPlugin) parseMessageData(s *pgsqlStream) (bool, bool) {
	pgsql.detailf("parseMessageData")

	// The response to queries that return row sets contains:
	// RowDescription
	// zero or more DataRow
	// CommandComplete
	// ReadyForQuery

	m := s.message

	for len(s.data[s.parseOffset:]) > 5 {
		// read type
		typ := byte(s.data[s.parseOffset])

		// read message length
		length := readLength(s.data[s.parseOffset+1:])
		if length < 4 {
			// length should include the size of itself (int32)
			pgsql.detailf("Invalid pgsql command length.")
			return false, false
		}
		if len(s.data[s.parseOffset:]) <= length {
			// wait for more
			pgsql.detailf("Wait for more data")
			return true, false
		}

		switch typ {
		case 'D':
			err := pgsql.parseDataRow(s, s.data[s.parseOffset+5:s.parseOffset+length+1])
			if err != nil {
				return false, false
			}
			s.parseOffset++
			s.parseOffset += length
		case 'C':
			// CommandComplete

			// skip type
			s.parseOffset++

			name, err := pgsqlString(s.data[s.parseOffset+4:], length-4)
			if err != nil {
				pgsql.detailf("pgsql string invalid")
				return false, false
			}

			pgsql.detailf("CommandComplete length=%d, tag=%s", length, name)
			s.parseOffset += length
			m.end = s.parseOffset
			m.size = uint64(m.end - m.start)
			s.parseState = pgsqlStartState

			pgsql.detailf("Rows: %s", m.rows)

			return true, true
		case '2':
			// Parse completion -> Bind completion for an extended query response

			// skip type
			s.parseOffset++
			s.parseOffset += length
			s.parseState = pgsqlStartState
		case 'T':
			return pgsql.parseRowDescription(s, length)
		default:
			// shouldn't happen -> return error
			pgsql.log.Warnf("Pgsql parser expected data message, but received command of type %v", typ)
			s.parseState = pgsqlStartState
			return false, false
		}
	}

	return true, false
}

func (pgsql *pgsqlPlugin) parseDataRow(s *pgsqlStream, buf []byte) error {
	m := s.message

	// read field count (int16)
	off := 2
	fieldCount := readCount(buf)

	rows := []string{}
	rowLength := 0

	for i := 0; i < fieldCount; i++ {
		if len(buf) <= off {
			return errFieldBufferShort
		}

		// read column length (int32)
		columnLength := int(BytesEx(buf[off:]))
		if columnLength < 0 {
			off += 4
			continue
		}
		off += 4

		if columnLength > 0 && columnLength > len(buf[off:]) {
			pgsql.log.Errorf("Pgsql invalid column_length=%v, buffer_length=%v, i=%v",
				columnLength, len(buf[off:]), i)
			return errInvalidLength
		}

		// read column value (byten)
		var columnValue []byte
		if m.fieldsFormat[i] == 0 {
			// field value in text format
			if columnLength > 0 {
				columnValue = buf[off : off+columnLength]
				off += columnLength
			}
		}

		if rowLength < pgsql.maxRowLength {
			if rowLength+len(columnValue) > pgsql.maxRowLength {
				columnValue = columnValue[:pgsql.maxRowLength-rowLength]
			}
			rows = append(rows, string(columnValue))
			rowLength += len(columnValue)
		}

		pgsql.detailf("Value %s, length=%d, off=%d", string(columnValue), columnLength, off)
	}

	if off < len(buf) {
		return errFieldBufferBig
	}

	m.numberOfRows++
	if len(m.rows) < pgsql.maxStoreRows {
		m.rows = append(m.rows, rows)
	}

	return nil
}
func BytesEx(b []byte) int32 {
	return int32(b[0])<<24 | int32(b[1])<<16 |
		int32(b[2])<<8 | int32(b[3])
}

func (pgsql *pgsqlPlugin) parseMessageExtendedQuery(s *pgsqlStream) (bool, bool) {
	pgsql.detailf("parseMessageExtendedQuery")

	// An extended query request contains:
	// Parse
	// Bind
	// Describe
	// Execute
	// Sync

	m := s.message

	for len(s.data[s.parseOffset:]) >= 5 {
		// read type
		typ := byte(s.data[s.parseOffset])

		// read message length
		length := readLength(s.data[s.parseOffset+1:])
		if length < 4 {
			// length should include the size of itself (int32)
			pgsql.detailf("Invalid pgsql command length.")
			return false, false
		}
		if len(s.data[s.parseOffset:]) <= length {
			// wait for more
			pgsql.detailf("Wait for more data")
			return true, false
		}

		switch typ {
		case 'B':
			// Parse -> Bind

			// skip type
			s.parseOffset++
			s.parseOffset += length
			//TO-DO: pgsql.parseBind(s)
		case 'D':
			// Bind -> Describe

			// skip type
			s.parseOffset++
			s.parseOffset += length
			//TO-DO: pgsql.parseDescribe(s)
		case 'E':
			// Bind(or Describe) -> Execute

			// skip type
			s.parseOffset++
			s.parseOffset += length
			//TO-DO: pgsql.parseExecute(s)
		case 'S':
			// Execute -> Sync

			// skip type
			s.parseOffset++
			s.parseOffset += length
			m.end = s.parseOffset
			m.size = uint64(m.end - m.start)
			s.parseState = pgsqlStartState

			return true, true
		default:
			// shouldn't happen -> return error
			pgsql.log.Warnf("Pgsql parser expected extended query message, but received command of type %v", typ)
			s.parseState = pgsqlStartState
			return false, false
		}
	}

	return true, false
}

func (pgsql *pgsqlPlugin) isSpecialCommand(data []byte) (bool, int, int) {
	if len(data) < 8 {
		// 8 bytes required
		return false, 0, 0
	}

	// read length
	length := readLength(data[0:])

	// read command identifier
	code := int(common.BytesNtohl(data[4:]))

	if length == 16 && code == 80877102 {
		// Cancel Request
		pgsql.debugf("Cancel Request, length=%d", length)
		return true, length, cancelRequest
	} else if length == 8 && code == 80877103 {
		// SSL Request
		pgsql.debugf("SSL Request, length=%d", length)
		return true, length, sslRequest
	} else if code == 196608 {
		// Startup Message
		pgsql.debugf("Startup Message, length=%d", length)

		return true, length, startupMessage
	}
	return false, 0, 0
}

// length field in pgsql counts total length of length field + payload, not
// including the message identifier. => Always check buffer size >= length + 1
func readLength(b []byte) int {
	return int(common.BytesNtohl(b))
}

func readCount(b []byte) int {
	return int(common.BytesNtohs(b))
}

func pgsqlString(b []byte, sz int) (string, error) {
	if sz == 0 {
		return "", nil
	}

	if b[sz-1] != 0 {
		return "", errInvalidString
	}

	return string(b[:sz-1]), nil
}

func pgsqlValidType(t byte) bool {
	switch t {
	case '1', '2', '3',
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K',
		'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Z',
		'c', 'd', 'f', 'n', 'p', 's', 't':
		return true
	default:
		return false
	}
}

func (pgsql *pgsqlPlugin) parseServersion(s *pgsqlStream, length int, priv pgsqlPrivateData) (bool, bool) {

	// ignore command
	offset := s.parseOffset
	s.parseOffset++ //type
	s.parseOffset += length

	m := s.message
	m.end = s.parseOffset
	m.size = uint64(m.end - m.start)

	//解析键值
	pkgMap := make(map[string]string)
	dataStartUp := s.data[:]

	offset++    //type
	offset += 4 //length field
	index := bytes.IndexByte(dataStartUp[offset:], 0x00)

	key := string(dataStartUp[offset : offset+index])
	offset = offset + index + 1
	index = bytes.IndexByte(dataStartUp[offset:], 0x00)
	val := string(dataStartUp[offset : offset+index])
	pkgMap[key] = val

	if v, ok := pkgMap["server_encoding"]; ok {
		priv.tcpSession.ServerEncoding = v

	}
	if v, ok := pkgMap["server_version"]; ok {
		priv.tcpSession.ServerVersion = v
		m.isRequest = false
		m.toExport = true
		return true, true
	}

	return true, true
}

//func (pgsql *pgsqlPlugin) isAuthSuccess(s *pgsqlStream, length int) (bool, bool) {
// pgsql.debugf("this is isAuth")
//
//
//   if  length ==8{
//	   offset :=s.parseOffset
//	   val := BytesNtohl(s.data[offset+5 :length+1])
//	   if val ==0 {
//		   s.parseOffset++ //type
//		   s.parseOffset += length
//
//		   m := s.message
//		   m.end = s.parseOffset
//		   m.size = uint64(m.end - m.start)
//
//		   m.isRequest =false
//		   m.toExport = true
//		   return true, true
//	   }
//
//	   return pgsql.parseSkipMessage(s, length)
//
//   }
//
//
//
//	return pgsql.parseSkipMessage(s, length)
//}
