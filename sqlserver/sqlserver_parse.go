package sqlserver

import (
	"fmt"
	"strconv"
	"strings"
)

func (sqlserver *sqlserverPlugin) sqlserverMessageParser(priv sqlserverPrivateData, dir uint8) (bool, bool) {
	s := priv.data[dir]
	//m := s.message
	realLength := len(s.data[:])
	// 测试realLength

	if len(s.data) < 2 {
		//直接drop
		return false, true
	}

	//packet type && status(0x01:End of Message,0x00:not End of Message) &&length
	typ, status, length := handleStartMsg(priv, dir)
	if realLength < int(length) {
		//get more packet
		return true, false
	}
	//        预登录              Query           TDS7.0 login         Server Response
	if typ == PRELOGIN || typ == SQL_BATCH || typ == LOGIN7 || typ == TABULAR_RESULT {
		s.message.size = uint64(length)

		s.parseOffset += 2 //channel
		s.parseOffset +=
			1 + // package number
				1 // windows

		if typ == TABULAR_RESULT && status == EOM {
			//Server Response
			//a := priv.data[dir].data[s.parseOffset]
			if priv.sqlserverMsg.firstLogin == 1 {
				//Server Response for PRELOGIN (analyse Server Version)

				return handlePreLoginResponse(priv, dir)
			} else {
				for len(s.data[s.parseOffset:]) > 0 {

					handleResponseMsg(priv, dir)

					if s.parseState == 1 {
						break
					}
				}
				return true, true

			}

		} else if typ == SQL_BATCH && status == EOM {
			// SQL
			return handleQueryMsg(priv, dir)
		} else if typ == PRELOGIN && status == EOM {
			//PreLogin  有多个prelogin 只解析第一个
			//a := priv.data[dir].data[s.parseOffset+1]
			if priv.sqlserverMsg.firstLogin < 1 {
				priv.sqlserverMsg.firstLogin += 1
				fmt.Println("this is 登录")
				return handlePreLoginRequest(priv, dir)
			} else {
				priv.sqlserverMsg.firstLogin += 1
				return true, true
			}

		} else if status == NORMAL {

			// there are a lot of data need to be received
			return true, false
		}
		//else if typ ==0x03 && status ==0x01{
		// TODO: deal with rpc request
		//}else if typ ==0x10 && status ==0x01 {
		// TODO: deal with login request
		//}else if typ ==0x08 && status ==0x01 {
		// TODO: deal with Federated Authentication Token request
		//}

		return true, true
	} else {

		// drop packet which is not belong to PRELOGIN,SQL_BATCH,LOGIN7,TABULAR_RESULT.
		return false, true
	}

}
func handleStartMsg(priv sqlserverPrivateData, dir uint8) (int, int, uint32) {
	s := priv.data[dir]
	s.parseOffset = 0
	// type
	typ := int(s.data[s.parseOffset])
	s.parseOffset += 1
	//status
	status := int(s.data[s.parseOffset])
	//fmt.Printf("this is status %v\n", uint32(status))
	s.parseOffset += 1
	//length
	length := BytesLeft2(s.data[s.parseOffset:])
	//fmt.Printf("this is stream length %v\n", uint32(length))
	s.parseOffset += 2
	return typ, status, length

}
func handleNextPacket(Payload []byte) (int, int, int) {

	// type
	typ := int(Payload[0])

	//status
	status := int(Payload[1])
	//fmt.Printf("this is status %v\n", uint32(status))
	length := len(Payload[:])
	//fmt.Println("this is PayLoadLength", length)
	return typ, status, length

}

func handleResponseMsg(priv sqlserverPrivateData, dir uint8) {
	s := priv.data[dir]
	m := s.message
	typ := s.data[s.parseOffset]

	if typ == 0xaa {
		// Error
		dealErrMsg(s, m)

	} else if typ == 0xfd {
		//Done
		dealDoneMsg(s, m)

	} else if typ == 0xad {
		// LoginAck
		dealLoginAckMsg(s, m, priv)

	} else if typ == 0x81 {
		// 如果有错误不会相应0x81 遇到0x81则发送导出
		if !m.symbol {
			m.isRequest = false
			m.toExport = true
			s.parseState = 1
			m.symbol = true
		}

		return
		//s.parseOffset += 1 //typ
		//rangeTimes := Bytes2(s.data[s.parseOffset:])
		//priv.sqlserverMsg.circleTimes = int(rangeTimes)
		//m.numberOfFields = int(rangeTimes)
		//priv.sqlserverMsg.sizes = priv.sqlserverMsg.sizes[:0]
		//priv.sqlserverMsg.typ = priv.sqlserverMsg.typ[:0]
		//
		//s.parseOffset += 2 //rangeTimes
		//
		//for i := 0; i < int(rangeTimes); i++ {
		//	s.parseOffset += 4 //usertype
		//	s.parseOffset += 2 //flag
		//	typ := s.data[s.parseOffset]
		//
		//	//fmt.Println("this is typppp", typ)
		//
		//	if isCollateAndSize2(typ) {
		//		// contain collate and size =2
		//		s.parseOffset += 1 // typ
		//		s.parseOffset += 2 //size
		//		priv.sqlserverMsg.sizes = append(priv.sqlserverMsg.sizes, 2)
		//		priv.sqlserverMsg.typ = append(priv.sqlserverMsg.typ, typ)
		//		s.parseOffset += 2 + //codepage
		//			2 + //flags
		//			1 //ID
		//		length := int(s.data[s.parseOffset])
		//		//fmt.Println(length)
		//		s.parseOffset += 1 // length
		//		colName := string(s.data[s.parseOffset : s.parseOffset+length*2])
		//		s.parseOffset += length * 2
		//		fmt.Println(colName)
		//
		//	} else if isCollateAndSize4(typ) {
		//
		//		// contain collate and size =4
		//		s.parseOffset += 1 // typ
		//		s.parseOffset += 4 //size
		//		priv.sqlserverMsg.sizes = append(priv.sqlserverMsg.sizes, 4)
		//		priv.sqlserverMsg.typ = append(priv.sqlserverMsg.typ, typ)
		//		s.parseOffset += 2 + //codepage
		//			2 + //flags
		//			1 //ID
		//		length := int(s.data[s.parseOffset])
		//		fmt.Println(length)
		//		s.parseOffset += 1 // length
		//		colName := string(s.data[s.parseOffset : s.parseOffset+length*2])
		//		s.parseOffset += length * 2
		//		fmt.Println(colName)
		//
		//	} else if isNotCollateAndSize1(typ) {
		//		// not contain collate and size =1
		//		s.parseOffset += 1 // typ
		//		s.parseOffset += 1 //size
		//		priv.sqlserverMsg.sizes = append(priv.sqlserverMsg.sizes, 1)
		//		priv.sqlserverMsg.typ = append(priv.sqlserverMsg.typ, typ)
		//		length := int(s.data[s.parseOffset])
		//		fmt.Println(length)
		//		s.parseOffset += 1 // length
		//		colName := string(s.data[s.parseOffset : s.parseOffset+length*2])
		//		s.parseOffset += length * 2
		//		fmt.Println(colName)
		//
		//	} else if typ == 0x6c || typ == 0x6a {
		//		// not contain collate and size =1 and contain precision&&scale
		//		s.parseOffset += 1 // typ
		//		s.parseOffset += 1 //size
		//		priv.sqlserverMsg.sizes = append(priv.sqlserverMsg.sizes, 1)
		//		priv.sqlserverMsg.typ = append(priv.sqlserverMsg.typ, typ)
		//		s.parseOffset += 1 + //precision
		//			1 //scale
		//		length := int(s.data[s.parseOffset])
		//		fmt.Println(length)
		//		s.parseOffset += 1 // length
		//		colName := string(s.data[s.parseOffset : s.parseOffset+length*2])
		//		s.parseOffset += length * 2
		//		fmt.Println(colName)
		//
		//	} else if typ == 0xad || typ == 0xa5 {
		//		// not contain collate and size =2
		//		s.parseOffset += 1 // typ
		//		s.parseOffset += 2 //size
		//		priv.sqlserverMsg.sizes = append(priv.sqlserverMsg.sizes, 2)
		//		priv.sqlserverMsg.typ = append(priv.sqlserverMsg.typ, typ)
		//		length := int(s.data[s.parseOffset])
		//		fmt.Println(length)
		//		s.parseOffset += 1 // length
		//		colName := string(s.data[s.parseOffset : s.parseOffset+length*2])
		//		s.parseOffset += length * 2
		//		fmt.Println(colName)
		//
		//	} else if typ == 0x22 || typ == 0x62 {
		//		//not contain collate and size =4
		//		s.parseOffset += 1 // typ
		//		s.parseOffset += 4 //size
		//		priv.sqlserverMsg.sizes = append(priv.sqlserverMsg.sizes, 4)
		//		priv.sqlserverMsg.typ = append(priv.sqlserverMsg.typ, typ)
		//		length := int(s.data[s.parseOffset])
		//		fmt.Println(length)
		//		s.parseOffset += 1 // length
		//		colName := string(s.data[s.parseOffset : s.parseOffset+length*2])
		//		s.parseOffset += length * 2
		//		fmt.Println(colName)
		//
		//	} else if typ == 0x2a {
		//		s.parseOffset += 1 // typ
		//		s.parseOffset += 1 //scale
		//		length := int(s.data[s.parseOffset])
		//		fmt.Println(length)
		//		s.parseOffset += 1 // length
		//		colName := string(s.data[s.parseOffset : s.parseOffset+length*2])
		//		s.parseOffset += length * 2
		//		fmt.Println("this is colName", colName)
		//
		//	} else if isZeroSize(typ) {
		//		s.parseOffset += 1 //typ
		//		priv.sqlserverMsg.sizes = append(priv.sqlserverMsg.sizes, 0)
		//		priv.sqlserverMsg.typ = append(priv.sqlserverMsg.typ, typ)
		//		length := int(s.data[s.parseOffset])
		//		s.parseOffset += 1 //length
		//		colName := string(s.data[s.parseOffset : s.parseOffset+length*2])
		//		s.parseOffset += length * 2
		//		fmt.Println(colName)
		//
		//	} else {
		//		s.parseState = 1
		//		m.toExport = false
		//		m.isRequest = false
		//		break
		//	}
		//
		//}

	} else if typ == 0xd1 || typ == 0xd3 { //2 0 1 1 1 2
		return
		//circleTime := priv.sqlserverMsg.circleTimes
		//sizes := priv.sqlserverMsg.sizes
		//typ := priv.sqlserverMsg.typ

		//s.parseOffset += 1 // typ
		//
		//for i := 0; i < circleTime; i++ {
		//	val := sizes[i]
		//	if val == 0 {
		//		if typ[i] == 0x34 {
		//			s.parseOffset += 2
		//		} else if typ[i] == 0x38 || typ[i] == 0x3a {
		//			s.parseOffset += 4
		//		} else if typ[i] == 0x30 || typ[i] == 0x32 {
		//			s.parseOffset += 1
		//		} else if typ[i] == 0x3d || typ[i] == 0x3e {
		//			s.parseOffset += 8
		//		} else if typ[i] == 0x28 {
		//			length := int(s.data[s.parseOffset])
		//			fmt.Println(length)
		//			s.parseOffset += 1 // length
		//			dataName := string(s.data[s.parseOffset : s.parseOffset+length])
		//			fmt.Println("this is date data", dataName)
		//			s.parseOffset += int(length)
		//		} else {
		//			// Skip other condition for unknown factors
		//			m.isRequest = false
		//			m.toExport = true
		//			s.parseState = 1
		//			return
		//		}
		//
		//		continue
		//	} else if val == 2 {
		//		length := Bytes2(s.data[s.parseOffset:])
		//		//CHARBIN_Null
		//		if length == 0xffff {
		//			s.parseOffset += 2 //length
		//			continue
		//		}
		//		s.parseOffset += 2 //length
		//		s.parseOffset += int(length)
		//	} else if val == 1 {
		//		length := int(s.data[s.parseOffset])
		//		s.parseOffset += 1 // length
		//		if length == 0xff {
		//			s.parseOffset += 1 //length
		//			continue
		//		}
		//		s.parseOffset += length
		//
		//	} else if val == 4 {
		//		length := int(s.data[s.parseOffset])
		//		s.parseOffset += 1
		//		s.parseOffset += length
		//		m.isRequest = false
		//		m.toExport = true
		//		s.parseState = 1
		//		return
		//
		//	}
		//	fmt.Println("1111111111111111111111", s.parseOffset)
		//	fmt.Println("rangeTimes")

		//}

	} else if typ == 0xa9 {
		s.parseOffset += 1 // typ
		length := Bytes2(s.data[s.parseOffset:])
		s.parseOffset += 2 //length
		s.parseOffset += int(length)
	} else {
		//Skip other message for correct system
		//s.parseOffset += 1 // typ
		//length := Bytes2(s.data[s.parseOffset:])
		//fmt.Println("this is token length", length)
		//fmt.Println("this is token parseOffset", s.parseOffset)
		//s.parseOffset += 2 //length
		//s.parseOffset += int(length)
		m.isRequest = false
		m.toExport = true
		s.parseState = 1
		return

	}

}
func handleQueryMsg(priv sqlserverPrivateData, dir uint8) (bool, bool) {
	s := priv.data[dir]
	m := s.message
	length := BytesNtohl(s.data[s.parseOffset:])
	//a := removeNeedByte(s.data[s.parseOffset+int(length):])

	query := ByteToChn(s.data[s.parseOffset+int(length):])

	m.query = query
	fmt.Println("this is query", query)
	arr := strings.Split(query, " ")
	method := arr[0]
	m.method = method
	m.isRequest = true
	m.toExport = true
	return true, true
}

func Bytes2(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8
}
func ByteToChn(arr []byte) string {
	var str string
	for i := 0; i < len(arr)-1; i += 2 {
		a := Bytes2(arr[i : i+2])
		str += string(rune(a))
	}
	return str
}
func BytesNtohl(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 |
		uint32(b[2])<<16 | uint32(b[3])<<24
}
func BytesNtohl2(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 |
		uint32(b[2])<<8 | uint32(b[3])
}
func handlePreLoginRequest(priv sqlserverPrivateData, dir uint8) (bool, bool) {
	s := priv.data[dir]
	m := priv.data[dir].message
	priOffset := s.parseOffset
	for {
		option := int(s.data[s.parseOffset])

		if option == 255 {

			break
		}
		s.parseOffset += 1
		realOffset := int(BytesLeft2(s.data[s.parseOffset:]))

		s.parseOffset += 2
		realLength := int(BytesLeft2(s.data[s.parseOffset:]))
		if realLength == 4 {
			//a := BytesNtohl2(s.data[priOffset+realOffset : priOffset+realOffset+realLength])
			//fmt.Println("this is thread ID",a)
		} else if realLength == 6 {
			first := uint32(s.data[priOffset+realOffset])
			second := uint32(s.data[priOffset+realOffset+1])
			third := BytesLeft2(s.data[priOffset+realOffset+2:])
			clientVersion := strconv.Itoa(int(first)) + "." + strconv.Itoa(int(second)) + "." + strconv.Itoa(int(third))

			priv.tcpSession.ClientVersion = clientVersion
		} else if realLength == 1 {

		}
		s.parseOffset += 2

	}
	m.toExport = true
	m.isRequest = true
	m.query = "登录"
	return true, true

}
func handlePreLoginResponse(priv sqlserverPrivateData, dir uint8) (bool, bool) {
	s := priv.data[dir]

	priOffset := s.parseOffset
	for {
		option := int(s.data[s.parseOffset])

		if option == 255 {

			break
		}
		s.parseOffset += 1
		realOffset := int(BytesLeft2(s.data[s.parseOffset:]))

		s.parseOffset += 2
		realLength := int(BytesLeft2(s.data[s.parseOffset:]))
		// ThreadID
		if realLength == 4 {
			//a := BytesNtohl2(s.data[priOffset+realOffset : priOffset+realOffset+realLength])
			//fmt.Println("this is thread ID ",a)
			//Server Version
		} else if realLength == 6 {
			first := uint32(s.data[priOffset+realOffset])
			second := uint32(s.data[priOffset+realOffset+1])
			third := BytesLeft2(s.data[priOffset+realOffset+2:])
			serverVersion := strconv.Itoa(int(first)) + "." + strconv.Itoa(int(second)) + "." + strconv.Itoa(int(third))

			priv.tcpSession.ServerVersion = serverVersion
			// other condition
		} else {
			//TODO: analyse other messages
		}
		s.parseOffset += 2

	}
	s.message.isRequest = false
	s.message.toExport = true
	return true, true

}

func BytesLeft2(b []byte) uint32 {
	return uint32(b[0])<<8 | uint32(b[1])
}
func removeNeedByte(arr []byte) []byte {
	serverArr := make([]byte, 0)
	for _, item := range arr {
		if item == 0x00 {
			continue
		}
		serverArr = append(serverArr, item)
	}
	return serverArr
}

func Bytes8(b []byte) int64 {
	return int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16 | int64(b[3])<<24 | int64(b[4])<<32 | int64(b[5])<<40 | int64(b[6])<<48 | int64(b[7])<<56
}
func isCollateAndSize2(typ byte) bool {
	return typ == 0xef || typ == 0xe7 || typ == 0xaf || typ == 0xa7
}

func isCollateAndSize4(typ byte) bool {
	return typ == 0x23 || typ == 0x63
}

func isNotCollateAndSize1(typ byte) bool {
	return typ == 0x24 || typ == 0x25 || typ == 0x26 || typ == 0x27 || typ == 0x2d || typ == 0x2f || typ == 0x67 || typ == 0x68 || typ == 0x6d || typ == 0x6e || typ == 0x6f
}
func isZeroSize(typ byte) bool {
	return typ == 0x30 || typ == 0x32 || typ == 0x34 || typ == 0x38 || typ == 0x3a || typ == 0x3b || typ == 0x3c ||
		typ == 0x3d || typ == 0x3e || typ == 0x40 || typ == 0x41 || typ == 0x42 || typ == 0x43 || typ == 0x7a || typ == 0x7f || typ == 0x28
}
func dealErrMsg(s *sqlserverStream, m *sqlserverMessage) {
	m.isError = true

	//fmt.Println("this is error message")
	s.parseOffset += 1 // typ
	length := Bytes2(s.data[s.parseOffset:])
	//fmt.Println("this is error length", length)
	s.parseOffset += 2 //length
	offset := s.parseOffset
	s.parseOffset += int(length)

	errCode := BytesNtohl(s.data[offset:])
	m.errorCode = strconv.Itoa(int(errCode))
	//fmt.Println("this is errCode", errCode)
	offset += 4 + // errNumber
		1 + // state
		1 // class
	errLength := Bytes2(s.data[offset:])
	//fmt.Println("this is errLength", errLength)
	offset += 2 // errLength
	errMsg := ByteToChn(s.data[offset : offset+int(errLength*2)])
	m.errorInfo = errMsg
	fmt.Println("this is errMsg", errMsg)
	//offset += int(errLength * 2)
	//serverLength := s.data[offset]
	//fmt.Println("this is serverLength", int(serverLength))
	offset++
	m.isRequest = false
	m.toExport = true
	s.parseState = 1
}

func dealDoneMsg(s *sqlserverStream, m *sqlserverMessage) {
	s.parseOffset += 1 //typ
	flag := s.data[s.parseOffset]
	if flag == 0x10 {
		s.parseOffset += 4 //operation and
		rowCount := Bytes8(s.data[s.parseOffset:])
		m.affectedRows = uint64(rowCount)
		m.numberOfRows = rowCount

	}

	m.isRequest = false
	m.toExport = true
	//fmt.Println("I am done ")
	s.parseState = 1
}
func dealLoginAckMsg(s *sqlserverStream, m *sqlserverMessage, priv sqlserverPrivateData) {
	s.parseOffset += 1 //typ
	length := Bytes2(s.data[s.parseOffset:])
	//fmt.Println("this is LoginAck Length", length)
	s.parseOffset += 2 // length
	offset := s.parseOffset
	s.parseOffset += int(length)
	offset += 1 //interface

	//fmt.Printf("this is unknown version %x\n", s.data[offset:offset+4])
	offset += 4 + //version
		1 //16进制
	//serverName := string(s.data[offset:offset+44])
	a := removeNeedByte(s.data[offset : offset+44])
	serverName := string(a)
	priv.tcpSession.ServerHostname = serverName
	//fmt.Println("this is serverName", serverName)
	offset += 44 //serverName

	first := uint32(s.data[offset])
	second := uint32(s.data[offset+1])
	third := BytesLeft2(s.data[offset+2:])
	serverVersion := strconv.Itoa(int(first)) + "." + strconv.Itoa(int(second)) + "." + strconv.Itoa(int(third))
	priv.tcpSession.ServerVersion = serverVersion
	//fmt.Println("this is serverVersion", serverVersion)
	m.isRequest = false
	m.toExport = true
}
