package oracle

import (
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
	"time"
)

const (
	TNS_TYPE_CONNECT   = 1
	TNS_TYPE_ACCEPT    = 2
	TNS_TYPE_ACK       = 3
	TNS_TYPE_REFUSE    = 4
	TNS_TYPE_REDIRECT  = 5
	TNS_TYPE_DATA      = 6
	TNS_TYPE_NULL      = 7
	TNS_TYPE_ABORT     = 9
	TNS_TYPE_RESEND    = 11
	TNS_TYPE_MARKER    = 12
	TNS_TYPE_ATTENTION = 13
	TNS_TYPE_CONTROL   = 14
	TNS_TYPE_MAX       = 19
)
const (
	SQLNET_SET_PROTOCOL     = 1
	SQLNET_SET_DATATYPES    = 2
	SQLNET_USER_OCI_FUNC    = 3
	SQLNET_RETURN_STATUS    = 4
	SQLNET_ACCESS_USR_ADDR  = 5
	SQLNET_ROW_TRANSF_HDR   = 6
	SQLNET_ROW_TRANSF_DATA  = 7
	SQLNET_RETURN_OPI_PARAM = 8
	SQLNET_FUNCCOMPLETE     = 9
	SQLNET_NERROR_RET_DEF   = 10
	SQLNET_IOVEC_4FAST_UPI  = 11
	SQLNET_LONG_4FAST_UPI   = 12
	SQLNET_INVOKE_USER_CB   = 13
	SQLNET_LOB_FILE_DF      = 14
	SQLNET_WARNING          = 15
	SQLNET_DESCRIBE_INFO    = 16
	SQLNET_PIGGYBACK_FUNC   = 17
	SQLNET_SIG_4UCS         = 18
	SQLNET_FLUSH_BIND_DATA  = 19
	SQLNET_SNS              = 0xdeadbeef
	SQLNET_XTRN_PROCSERV_R1 = 32
	SQLNET_XTRN_PROCSERV_R2 = 68
)

type oraclePlugin struct {
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
	handleOracle func(oracle *oraclePlugin, m *oracleMessage, tcp *common.TCPTuple,
		dir uint8, raw_msg []byte, priv oraclePrivateData)
}

type oracleMessage struct {
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
	numberOfRows   int64
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
	method                     string
	length                     int
	totalLen                   int
	symbol                     bool
}
type oracleStream struct {
	data []byte

	parseOffset       int
	parseState        int
	seenSSLRequest    bool
	expectSSLResponse bool

	message *oracleMessage
}

type oraclePrivateData struct {
	data       [2]*oracleStream
	tcpSession *tcp.TCPSession
	oracleMsg  *oracleMsg
}
type oracleMsg struct {
	sizes       []int
	circleTimes int
	typ         []byte
	firstLogin  int
}
type oracleTransaction struct {
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

	oracle common.MapStr

	requestRaw                                                                                                                                        string
	responseRaw                                                                                                                                       string
	transId                                                                                                                                           string // 事务唯一id
	sessionId                                                                                                                                         string // 会话id
	serverVersion, serverOS, serverHostname, serverArch, serverProgram                                                                                string // 数据库程序版本
	dbUser, clientProgram, clientVersion, clientOS, clientArch, clientPID, clientUsername, clientHostname, InitDbName, ClientEncoding, ServerEncoding string
	tables                                                                                                                                            []string
}
