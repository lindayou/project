package sqlserver

import (
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/packetbeat/procs"
	"github.com/elastic/beats/v7/packetbeat/protos"
	"github.com/elastic/beats/v7/packetbeat/protos/tcp"
	"time"
)

// const define for tds operator
const (
	SQL_BATCH           = 0x01 //Query
	RPC_REQUEST         = 0x03
	TABULAR_RESULT      = 0x04 //Response from Server
	ATTENTION           = 0x06 //cancels
	BULK_LOAD           = 0x07 // Only Work for TDS5.0
	TRANSACTION_MANAGER = 0x0E
	LOGIN7              = 0x10 //TDS7.0 Login packet
	NTLMAUTH_PKT        = 0x11 //TDS 7.0 authentication packet
	PRELOGIN            = 0x12 // Client Version for >TDS8.0
	//FEDAUTH_TOKEN       = 0x08
)

// const define for tds status
const (
	NORMAL                  = 0x00
	EOM                     = 0x01
	IGNORE                  = 0x02
	RESETCONNECTION         = 0x08
	RESETCONNECTIONSKIPTRAN = 0x10
)

type sqlserverPlugin struct {
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
	handleSqlserver func(sqlserver *sqlserverPlugin, m *sqlserverMessage, tcp *common.TCPTuple,
		dir uint8, raw_msg []byte, priv sqlserverPrivateData)
}
type sqlserverMessage struct {
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
type sqlserverStream struct {
	data []byte

	parseOffset       int
	parseState        int
	seenSSLRequest    bool
	expectSSLResponse bool

	message *sqlserverMessage
}

type sqlserverPrivateData struct {
	data         [2]*sqlserverStream
	tcpSession   *tcp.TCPSession
	sqlserverMsg *sqlserverMsg
}
type sqlserverMsg struct {
	sizes       []int
	circleTimes int
	typ         []byte
	firstLogin  int
}
type sqlserverTransaction struct {
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

	sqlserver common.MapStr

	requestRaw                                                                                                                                        string
	responseRaw                                                                                                                                       string
	transId                                                                                                                                           string // 事务唯一id
	sessionId                                                                                                                                         string // 会话id
	serverVersion, serverOS, serverHostname, serverArch, serverProgram                                                                                string // 数据库程序版本
	dbUser, clientProgram, clientVersion, clientOS, clientArch, clientPID, clientUsername, clientHostname, InitDbName, ClientEncoding, ServerEncoding string
	tables                                                                                                                                            []string
}
