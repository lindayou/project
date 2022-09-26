package oracle

import "fmt"

func (oracle *oraclePlugin) oracleMessageParser(priv oraclePrivateData, dir uint8) (bool, bool) {
	s := priv.data[dir]
	//解析长度  checksum 包类型 reserved header checksum
	length, typ := parseNormalData(priv, dir)
	fmt.Printf("this is length :%v,this is typ %v\n ", length, typ)
	fmt.Println("this is s.parseOffset", s.parseOffset)
	switch typ {
	case TNS_TYPE_CONNECT:
		return parseConnect(priv)
		//response for first connect
	case TNS_TYPE_RESEND:
		return parseResend(priv)
	case TNS_TYPE_ACCEPT:
		return parseAccept(priv)
		//when server refuse the request from client
	case TNS_TYPE_REFUSE:
		return parseRefuse(priv)
	case TNS_TYPE_DATA:
		return parseData(priv, dir)

	}
	return false, false
}
func parseNormalData(priv oraclePrivateData, dir uint8) (uint32, int8) {
	s := priv.data[dir]
	s.parseOffset = 0
	//length
	length := BytesLeft2(s.data)
	fmt.Println("this is packet length", length)
	s.parseOffset += 2 + //length
		2 //checksum
	typ := int8(s.data[s.parseOffset])
	s.parseOffset += 1 + //type
		1 + // reserved
		2 //header checksum
	return length, typ
}

func BytesLeft2(b []byte) uint32 {
	return uint32(b[0])<<8 | uint32(b[1])
}
func parseConnect(priv oraclePrivateData) (bool, bool) {
	return false, false
}
func parseResend(priv oraclePrivateData) (bool, bool) {
	return false, false
}
func parseAccept(priv oraclePrivateData) (bool, bool) {
	return false, false
}
func parseRefuse(priv oraclePrivateData) (bool, bool) {
	return false, false
}
func parseData(priv oraclePrivateData, dir uint8) (bool, bool) {
	s := priv.data[dir]
	s.parseOffset += 2
	typ := parseDataType(s)
	switch typ {
	case SQLNET_SET_PROTOCOL:
		return parseSqlProtocol(priv, dir)
	case SQLNET_SET_DATATYPES:
		return parseSqlDataType(priv, dir)
	case SQLNET_USER_OCI_FUNC:
		return parseSqlUseOci(priv, dir)
	case SQLNET_RETURN_STATUS:
		return parseSqlStatus(priv, dir)
	case SQLNET_ACCESS_USR_ADDR:
		return parseSqlAccess(priv, dir)
	case SQLNET_ROW_TRANSF_HDR:
		return parseSqlRowHdr(priv, dir)
	case SQLNET_ROW_TRANSF_DATA:
		return parseSqlRowData(priv, dir)
	case SQLNET_RETURN_OPI_PARAM:
		return parseSqlOpiParam(priv, dir)
	case SQLNET_FUNCCOMPLETE:
		return parseSqlComplete(priv, dir)
	case SQLNET_NERROR_RET_DEF:
		return parseSqlError(priv, dir)
	case SQLNET_IOVEC_4FAST_UPI:
		return parseSqlIovec(priv, dir)
	case SQLNET_LONG_4FAST_UPI:
		return parseSqlLong(priv, dir)
	case SQLNET_INVOKE_USER_CB:
		return parseSqlInvokeUser(priv, dir)
	case SQLNET_LOB_FILE_DF:
		return parseSqlLobFile(priv, dir)
	case SQLNET_WARNING:
		return parseSqlWarning(priv, dir)
	case SQLNET_DESCRIBE_INFO:
		return parseSqlInfo(priv, dir)
	case SQLNET_PIGGYBACK_FUNC:
		return parseSqlPiggyback(priv, dir)
	case SQLNET_SIG_4UCS:
		return parseSqlSig(priv, dir)
	case SQLNET_FLUSH_BIND_DATA:
		return parseSqlFlushData(priv, dir)
	case SQLNET_SNS:
		return parseSqlSns(priv, dir)
	case SQLNET_XTRN_PROCSERV_R1:
		return parseSqlXtrnR1(priv, dir)
	case SQLNET_XTRN_PROCSERV_R2:
		return parseSqlXtrnR2(priv, dir)

	}
	return false, false
}
func parseDataType(s *oracleStream) uint32 {

	typ := uint32(s.data[s.parseOffset])
	if typ == 0xde {
		typ = 0xdeadbeef
	}
	return typ
}
func parseSqlProtocol(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlDataType(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlUseOci(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlStatus(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlAccess(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlRowHdr(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlRowData(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlOpiParam(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlComplete(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlError(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlIovec(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlLong(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlInvokeUser(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlLobFile(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlWarning(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlInfo(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlPiggyback(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlSig(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlFlushData(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlSns(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlXtrnR1(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
func parseSqlXtrnR2(priv oraclePrivateData, dir uint8) (bool, bool) {
	return false, false
}
