package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/charlesgreat/gaio"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	// enable SSL mode
	gaio.SSLEnvInit()
	gaio.SetGlobalSSLCtx(gaio.NewSSLCTX("./ca/cacert.pem", "./ca/privkey.pem"))

	HandleFunc("/", IndexHandler)
	err := StartHttpServe("127.0.0.1:50006", 1, false)
	if err != nil {
		fmt.Println("faild to start server")
	}
}

func IndexHandler(conInfo *ConInfo) {
	req := &conInfo.Req
	rsp := &conInfo.Rsp
	if 0 == strings.Compare(req.Header.RequestURI, "/") ||  0 == strings.Compare(req.Header.RequestURI, "/index.html") {
		//content, _ := ioutil.ReadFile("/home/charles/www/index.html")
		rsp.Body = append(rsp.Body, rspBody...)
	} else {
		rsp.StatusCode = StatusBadRequest
	}
}


var rspBody = []byte(
	"<!DOCTYPE html>\n" +
		"<html>\n" +
		"\n" +
		"<head>\n" +
		"  <title>Welcome to us!</title>\n" +
		"  <style>\n" +
		"    body {\n" +
		"      width: 35em;\n" +
		"      margin: 0 auto;\n" +
		"      font-family: Tahoma, Verdana, Arial, sans-serif;\n" +
		"    }\n" +
		"  </style>\n" +
		"</head>\n" +
		"\n" +
		"<body>\n" +
		"  <h1>Welcome to us!</h1>\n" +
		"  <p>If you see this page, the web server is successfully installed and working. Further configuration is required.</p>\n" +
		"\n" +
		"</body>\n" +
		"\n" +
		"</html>\n")

const (
	// gorilla/websocket 发送的单帧最大数据为4096字节（默认数据缓存为4096） 加上包头6个字节 为4102
	// 所以这里的缓存设置为5120 一次能读取一个最大帧 多占了内存 但是避免了多次读取数据
	defaultRecBufSize   = 5120
	defaultInOutBufSize = 5120

	ContentLenLen = 15

	// HTTP 状态码
	StatusOK = 200

	StatusTemporaryRedirect = 307

	StatusBadRequest       = 400
	StatusUnauthorized     = 401
	StatusPaymentRequired  = 402
	StatusForbidden        = 403
	StatusNotFound         = 404
	StatusMethodNotAllowed = 405

	StatusInternalServerError = 500
)

const (
	// Frame header
	finalBit = 1 << 7
	rsv1Bit  = 1 << 6
	rsv2Bit  = 1 << 5
	rsv3Bit  = 1 << 4

	// Frame header byte 1 bits from Section 5.2 of RFC 6455
	maskBit = 1 << 7

	maxFrameHeaderSize         = 2 + 8 + 4 // Fixed header + length + mask
	maxControlFramePayloadSize = 125

	continuationFrame = 0
	noFrame           = -1
)

// The message types are defined in RFC 6455, section 11.8.
const (
	// TextMessage denotes a text data message. The text message payload is
	// interpreted as UTF-8 encoded text data.
	TextMessage = 1

	// BinaryMessage denotes a binary data message.
	BinaryMessage = 2

	// CloseMessage denotes a close control message. The optional message
	// payload contains a numeric code and text. Use the FormatCloseMessage
	// function to format a close message payload.
	CloseMessage = 8

	// PingMessage denotes a ping control message. The optional message payload
	// is UTF-8 encoded text.
	PingMessage = 9

	// PongMessage denotes a pong control message. The optional message payload
	// is UTF-8 encoded text.
	PongMessage = 10
)

// Close codes defined in RFC 6455, section 11.7.
const (
	CloseNormalClosure           = 1000
	CloseGoingAway               = 1001
	CloseProtocolError           = 1002
	CloseUnsupportedData         = 1003
	CloseNoStatusReceived        = 1005
	CloseAbnormalClosure         = 1006
	CloseInvalidFramePayloadData = 1007
	ClosePolicyViolation         = 1008
	CloseMessageTooBig           = 1009
	CloseMandatoryExtension      = 1010
	CloseInternalServerErr       = 1011
	CloseServiceRestart          = 1012
	CloseTryAgainLater           = 1013
	CloseTLSHandshake            = 1015
)

const (
	strConnection         = "Connection:"
	strContentLength      = "Content-Length:"
	strContentLengthLower = "content-length"
	strContentType        = "Content-Type:"
	strHost               = "Host:"

	strKeepAlice = "Keep-Alive"
	strUpgrade   = "Upgrade"
	strPost      = "POST"
	strColon     = ":"
	strQuestion  = "?"
	strSlash     = "/"

	strDefContentType = "text/html"
)

var (
	HeaderColon    = []byte(strColon)
	HeaderCrlf     = []byte("\r\n")
	HeaderCrlfCrlf = []byte("\r\n\r\n")

	HeaderContentLength      = []byte(strContentLength)
	HeaderContentLengthLower = []byte(strContentLengthLower)
	HeaderHost               = []byte(strHost)
	HeaderConnection         = []byte(strConnection)

	HeaderKeepAlive = []byte(strKeepAlice)
	HeaderUpgrade   = []byte(strUpgrade)

	HeaderPost = []byte(strPost)

	statusMessages = map[int]string{
		StatusOK:                  "200 OK",
		StatusTemporaryRedirect:   "307 Temporary Redirect",
		StatusBadRequest:          "400 Bad Request",
		StatusUnauthorized:        "401 Unauthorized",
		StatusNotFound:            "404 Not Found",
		StatusInternalServerError: "500 Internal Server Error",
	}
)


type ConInfo struct {
	rec    []byte //  接收缓存
	in     []byte //  数据处理缓存
	out    []byte //  发送缓存
	tmpBuf []byte // 临时缓存 目前在ws协议协议帧头有使用
	wc     *gaio.Watcher
	Conn   net.Conn
	Req    Request  //  http请求消息
	Rsp    Response // http响应消息

	// websocket 消息信息
	WSMsg     WSMessage
	wsHandler WSHandle
}

type Request struct {
	Header      HttpRequestHeader
	Body        []byte
	RemoteAddr  string
	HostName    string // host名 去掉了端口
	ContentType string
}

type Response struct {
	Body        []byte
	ContentType string
	StatusCode  int
	Action      int //是否关闭连接
}


type HttpRequestHeader struct {
	Method     string
	RequestURI string
	Host       string
	Path       string // 去掉？后的全路径  业务函数调用路由匹配要用

	IfPost        bool
	KeepAlive     bool
	Upgrade       bool
	ContentLength int
	BufKV         map[string][]byte // 请求参数对
}

type WSRequestHeader struct {
	fin  bool
	rsv1 bool
	rsv2 bool
	rsv3 bool

	opCode  int
	masked  bool
	maskKey [4]byte

	payloadLength int64
}


type WSRequest struct {
	header      WSRequestHeader
	msContinue  bool //针对分片消息是否结束的判断
	MessageType int
	Message     []byte //已经完整解析后的请求业务数据
}

type WSMessage struct {
	maskKey     [4]byte
	msContinue  bool //针对分片消息是否结束的判断
	MessageType int
	CloseCode   int
	ReqData     []byte //已经完整解析后的请求业务数据
	RspData     []byte //响应消息
	Action      int    //是否关闭连接
}

func (rsp *Response) Reset() {
	rsp.ContentType = ""
	rsp.StatusCode = 0
	rsp.Body = rsp.Body[0:0]
}

// 只情况必要部分
func (req *Request) Reset() {
	req.Header.Reset()
	req.RemoteAddr = ""
	req.HostName = ""
	req.ContentType = ""
	req.Body = req.Body[0:0]
}

func (header *HttpRequestHeader) Reset() {
	header.Method = ""
	header.RequestURI = ""
	header.Host = ""
	header.Path = ""
	header.IfPost = false
	header.KeepAlive = false
	header.Upgrade = false
	header.ContentLength = 0
	header.BufKV = nil
}

func (wsMsg *WSMessage) Reset() {
	wsMsg.msContinue = false
	wsMsg.MessageType = 0
	wsMsg.ReqData = wsMsg.ReqData[:0]
	wsMsg.RspData = wsMsg.RspData[:0]
}

// 可能有多个字段
func (header HttpRequestHeader) ContainsValue(name string, value []byte) bool {
	v, ok := header.BufKV[name]
	if ok {
		return caseInsensitiveContain(v, value)
	}
	return false
}

func (header HttpRequestHeader) Get(name string) []byte {
	v, ok := header.BufKV[name]
	if ok {
		return bytes.TrimSpace(v)
	}
	return nil
}

var aliveClose = "Connection: close\r\n"
var aliveKeep = "Connection: keep-alive\r\n"

// 缓存接收到的数据
func (conn *ConInfo) Begin(packet []byte) (data []byte) {
	data = packet
	if len(conn.in) > 0 {
		conn.in = append(conn.in, data...)
		data = conn.in
	}
	return data
}

// 保留多余的数据下次处理 如果数据处理完了就清空处理缓存区
func (conn *ConInfo) End(data []byte) {
	if len(data) > 0 {
		if len(data) != len(conn.in) { // 相等的话 数据一样不用再拷贝
			conn.in = append(conn.in[:0], data...)
		}
	} else if len(conn.in) > 0 {
		conn.in = conn.in[:0]
	}
}

var wTest *gaio.Watcher

func httpService(w *gaio.Watcher) {
	wTest = w
	for {
		// loop wait for any IO events
		results, err := w.WaitIO()
		if err != nil {
			log.Println(err)
			return
		}

		for _, res := range results {
			switch res.Operation {
			case gaio.OpRead: // read completion event
				//if res.Error != nil {
				//	log.Println("httpService, OpRead error and len ", res.Error, res.Size)
				//}
				ifClose, conInfo := handleReadBack(&res)
				if len(conInfo.out) > 0 {
					w.Write(res.Context, res.Conn, conInfo.out)
				}

				if ifClose {
					w.Free(res.Conn)
				} else if len(conInfo.out) == 0 {
					// 如果没有发送数据时 主动触发读取  避免在数据不完整时无法触发数据再次读取
					// 数据不完整有2中情况 1.客户端一次发的太少 本身不完整  2. 单次请求数据大 读取缓存满了
					w.Read(res.Context, res.Conn, conInfo.rec[:cap(conInfo.rec)])
				}

			case gaio.OpWrite: // write completion event
				conInfo := res.Context.(*ConInfo)
				if res.Error == nil {
					w.Read(res.Context, res.Conn, conInfo.rec[:cap(conInfo.rec)])
				}
			}
		}
	}
}

func handleReadBack(res *gaio.OpResult) (ifClose bool, conInfo *ConInfo) {
	// 清空out缓存
	ifClose = false
	conInfo = res.Context.(*ConInfo)
	//log.Println("handleReadBack ", conInfo.Conn.RemoteAddr())
	if len(conInfo.out) > 0 {
		conInfo.out = conInfo.out[:0]
	}

	// 连接被关闭
	if res.Error != nil {
		ifClose = true
		return
	}

	// 没有数据
	if len(res.Buffer) == 0 || res.Size == 0 {
		return
	}

	// 读取数据异常
	if res.Size > len(res.Buffer) {
		ifClose = true
		return
	} else {
		res.Buffer = res.Buffer[0:res.Size]
	}

	data := conInfo.Begin(res.Buffer)

	for {
		if conInfo.wsHandler == nil { //HTTP 处理
			req := &conInfo.Req
			rsp := &conInfo.Rsp
			req.Reset()
			rsp.Reset()
			leftover, err := ParseHttpReq(data, req)
			if err != nil {
				// 请求异常
				rsp.StatusCode = StatusBadRequest
				conInfo.appendHttpOutBuf()
				break
			} else if len(leftover) == len(data) {
				// 数据不完整
				break
			}

			// 设置常用参数
			req.RemoteAddr = res.Conn.RemoteAddr().String()

			// 识别是否升级为websocket 并做校验
			if req.Header.Upgrade {
				UpgradeCheck(conInfo)
				if rsp.StatusCode == StatusOK {
					// 升级成功的话 只能有一个消息
					if len(leftover) != 0 {
						rsp.StatusCode = StatusBadRequest
						rsp.Body = conInfo.Rsp.Body[:0]
						rsp.Body = append(rsp.Body, "websocket: too many request"...)
					} else {
						conInfo.out = append(conInfo.out, rsp.Body...)
						data = leftover
						break
					}
				}
			} else {
				// Http 业务处理
				httpServerHandler(conInfo)
			}

			conInfo.appendHttpOutBuf()
			data = leftover

			if !req.Header.KeepAlive || rsp.Action == Close {
				ifClose = true
				break
			}

			if len(data) == 0 {
				break
			}
		} else { // websocket  数据处理
			if conInfo.tmpBuf == nil {
				conInfo.tmpBuf = make([]byte, 0, maxFrameHeaderSize)
			}
			wsMsg := &conInfo.WSMsg
			leftover, err := ParseWSReq(data, wsMsg)
			if err != nil {
				// 请求异常
				wsMsg.RspData = append(wsMsg.RspData, "bad request"...)
				conInfo.appendWSOutBuf()
				wsMsg.Reset()
				break
			} else if len(leftover) == len(data) {
				//fmt.Println("frame incomplete ", len(leftover), len(wsMsg.ReqData), len(wsMsg.RspData))
				// 数据不完整
				break
			} else if wsMsg.msContinue {
				// 数据不全  有多帧
				//fmt.Println("data incomplete ", len(leftover), len(wsMsg.ReqData), len(wsMsg.RspData))
				data = leftover
				if len(data) == 0 {
					break
				}
				continue
			}

			//fmt.Println("rec data  ", len(wsMsg.ReqData), len(leftover), len(wsMsg.RspData))
			if isControl(wsMsg.MessageType) {
				// 处理控制帧
				conInfo.handleWSControlFrame()
			} else {
				// 处理业务数据
				conInfo.wsHandler(conInfo)
			}

			if len(wsMsg.RspData) > 0 {
				conInfo.appendWSOutBuf()
			}

			action := wsMsg.Action
			wsMsg.Reset()

			data = leftover

			if action == Close {
				ifClose = true
				break
			}

			if len(data) == 0 {
				break
			}

		}
	}
	conInfo.End(data)

	return
}

func handWriteBack(res *gaio.OpResult) (ifclose bool, conInfo *ConInfo) {
	ifclose = false
	conInfo = res.Context.(*ConInfo)
	if res.Error != nil {
		if res.Error == io.EOF {
			ifclose = true
		}
		return ifclose, conInfo
	}

	return ifclose, conInfo
}

func GetStatusMessage(statusCode int) string {
	s := statusMessages[statusCode]
	if s == "" {
		s = "400 Bad Request"
	}
	return s
}

func (conn *ConInfo) appendHttpOutBuf() {
	req := &conn.Req
	rsp := &conn.Rsp

	conn.out = append(conn.out, "HTTP/1.1 "...)
	if 0 == rsp.StatusCode {
		rsp.StatusCode = StatusOK
	}

	conn.out = append(conn.out, GetStatusMessage(rsp.StatusCode)...)
	conn.out = append(conn.out, '\r', '\n')

	conn.out = append(conn.out, "Content-Type: "...)
	if len(rsp.ContentType) != 0 {
		conn.out = append(conn.out, rsp.ContentType...)
	} else if len(req.ContentType) != 0 {
		conn.out = append(conn.out, req.ContentType...)
	} else {
		conn.out = append(conn.out, strDefContentType...)
	}
	conn.out = append(conn.out, '\r', '\n')

	if len(rsp.Body) > 0 {
		conn.out = append(conn.out, "Content-Length: "...)
		conn.out = strconv.AppendInt(conn.out, int64(len(rsp.Body)), 10)
		conn.out = append(conn.out, '\r', '\n')
	}

	if req.Header.KeepAlive == true && rsp.Action != Close {
		conn.out = append(conn.out, aliveKeep...)
	} else {
		conn.out = append(conn.out, aliveClose...)
	}

	conn.out = append(conn.out, '\r', '\n')

	if len(rsp.Body) > 0 {
		conn.out = append(conn.out, rsp.Body...)
	}
}

// 先判断消息头、body的完整性 然后再开始解析消息头
func ParseHttpReq(data []byte, req *Request) (leftover []byte, err error) {

	// 完整性判断
	bHeadEnd := false
	bWithBody := false
	bBodyEnd := false
	indexHeadEnd := bytes.Index(data, HeaderCrlfCrlf) // 头部结束标志
	if indexHeadEnd > 0 {
		bHeadEnd = true
		indexCon := bytes.Index(data[:indexHeadEnd], HeaderContentLength) // 内容长度
		if indexCon < 0 {
			indexCon = bytes.Index(data[:indexHeadEnd], HeaderContentLengthLower) // 内容长度 按小写再找一次
		}
		if indexCon > 0 {
			bWithBody = true
			index := bytes.Index(data[indexCon:indexHeadEnd+2], HeaderCrlf) // 内容长度
			if index > 0 {
				iLen, err := strconv.Atoi(string(bytes.TrimSpace(data[indexCon+ContentLenLen : indexCon+index])))
				if nil == err && iLen > 0 && iLen+indexHeadEnd+4 <= len(data) {
					bBodyEnd = true
					req.Header.ContentLength = iLen
					req.Body = data[indexHeadEnd+4 : indexHeadEnd+4+iLen]
				}
			}
		}
	}

	// 头部不完整 或者 有内容但是内容不完整时直接返回
	if !bHeadEnd || (bWithBody && !bBodyEnd) {
		return data, nil
	}

	// 记录剩余数据
	iLeft := indexHeadEnd + 4 + req.Header.ContentLength
	if len(data) > iLeft {
		leftover = data[iLeft:]
	}

	buf := data[:indexHeadEnd+2] // buf是一个完整的http消息头

	// 请求行/首行
	iLenEnd := bytes.Index(buf, HeaderCrlf)
	line := buf[:iLenEnd]
	n := bytes.IndexByte(line, ' ')
	if n <= 0 {
		return nil, errors.New("cannot find http request method")
	}
	req.Header.Method = string(line[:n])
	if strings.Compare(req.Header.Method, strPost) == 0 {
		req.Header.IfPost = true
	}

	line = line[n+1:]
	n = bytes.IndexByte(line, ' ')
	if n <= 0 {
		return nil, errors.New("requestURI cannot be empty")
	}
	req.Header.RequestURI = string(line[:n])

	// 解析头部信息(请求参数对)
	buf = buf[iLenEnd+2:]

	var i, s int
	req.Header.KeepAlive = false
	req.Header.BufKV = make(map[string][]byte)

	for ; i < len(buf); i++ {
		if i > 1 && buf[i] == '\n' && buf[i-1] == '\r' {
			line = buf[s : i-1]
			s = i + 1

			switch line[0] | 0x20 {
			case 'h':
				if caseInsensitiveHasPrefix(line, HeaderHost) {
					req.Header.Host = string(bytes.TrimSpace(line[len(HeaderHost):]))
				}
				fallthrough
			case 'c':
				if caseInsensitiveHasPrefix(line, HeaderConnection) {
					if caseInsensitiveContain(line[len(HeaderConnection):], HeaderKeepAlive) {
						req.Header.KeepAlive = true
					}

					if caseInsensitiveContain(line[len(HeaderConnection):], HeaderUpgrade) {
						req.Header.Upgrade = true
					}
				}
				fallthrough
			default:
				n = bytes.Index(line, HeaderColon)
				if n <= 0 {
					return nil, errors.New("bad http header")
				}
				req.Header.BufKV[string(bytes.ToLower(line[:n]))] = line[n+1:]
			}
		}
	}

	// 设置常用参数
	n = strings.Index(req.Header.Host, strColon)
	if n > 0 {
		req.HostName = string(req.Header.Host[:n])
	}

	// 对Path进行设置
	n = strings.LastIndex(req.Header.RequestURI, strQuestion)
	if n >= 0 {
		req.Header.Path = string(req.Header.RequestURI[:n+1])
	} else {
		req.Header.Path = string(req.Header.RequestURI)
	}

	return leftover, nil
}

// a是否以b为开头 大小写不敏感
func caseInsensitiveHasPrefix(a, b []byte) bool {
	if len(a) < len(b) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if a[i]|0x20 != b[i]|0x20 {
			return false
		}
	}
	return true
}

// 字节串是否相等 大小写不敏感
func caseInsensitiveEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if a[i]|0x20 != b[i]|0x20 {
			return false
		}
	}
	return true
}

// 字符串包含判断 大小写不敏感
func caseInsensitiveContain(a, b []byte) bool {
	lenA := len(a)
	lenB := len(b)
	if lenA < lenB {
		return false
	}

	i := 0
	j := 0
	lenC := lenA - lenB
	for ; i <= lenC; i++ {
		j = 0
		for ; j < lenB; j++ {
			if a[i+j]|0x20 != b[j]|0x20 {
				break
			}
		}

		if j == lenB {
			return true
		}
	}

	return false
}

func Clear(v interface{}) {
	p := reflect.ValueOf(v).Elem()
	p.Set(reflect.Zero(p.Type()))
}

// 启动http服务
// 输入参数为  地址  业务处理协程数 是否端口复用
// 业务处理协程数先用1 设置大了性能不提高 太大反而降低 需要再分析原因
func StartHttpServe(address string, numHandler int, reusePort bool) error {

	var watchlist []*gaio.Watcher
	var err error
	i := 0
	for i = 0; i < numHandler; i++ {
		w, err := gaio.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		go httpService(w)
		watchlist = append(watchlist, w)

	}

	defer func() {
		for i = 0; i < numHandler; i++ {
			watchlist[i].Close()
		}
	}()

	var ln net.Listener
	if reusePort {
		// use github.com/libp2p/go-reuseport later
		ln, err = net.Listen("tcp", address)

	} else {
		ln, err = net.Listen("tcp", address)
	}

	if err != nil {
		log.Fatal(err)
		return err
	}
	log.Println("Http server listening on ", ln.Addr(), ", numHandler ", numHandler, ", reusePort ", reusePort)

	i = 0
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			return err
		}
		//log.Println("new client", conn.RemoteAddr())

		conInfo := &ConInfo{
			wc:   watchlist[i],
			Conn: conn,
			rec:  make([]byte, defaultRecBufSize, defaultRecBufSize),
			in:   make([]byte, 0, defaultInOutBufSize),
			out:  make([]byte, 0, defaultInOutBufSize),
		}

		// submit the first async read IO request
		err = watchlist[i].Read(conInfo, conn, conInfo.rec)
		if err != nil {
			log.Println(err)
			return err
		}

		i++
		if i >= numHandler {
			i = 0
		}
	}
}

// 业务回调函数处理 参考自go http
const (
	None     int = iota
	Close        // Close closes the connection.
	Shutdown     // Shutdown shutdowns the server.
)

type HttpHandle func(conInfo *ConInfo)

type ServeMux struct {
	mu    sync.RWMutex
	m     map[string]HttpHandle
	es    []string // slice of pattern sorted from longest to shortest.
	hosts bool     // whether any patterns contain hostnames
}

var DefaultServeMux = &defaultServeMux
var defaultServeMux ServeMux

func HandleFunc(pattern string, handler HttpHandle) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

func (mux *ServeMux) HandleFunc(pattern string, handler HttpHandle) {
	if pattern == "" || handler == nil {
		return
	}

	mux.mu.Lock()
	defer mux.mu.Unlock()

	if _, exist := mux.m[pattern]; exist {
		return
	}

	if mux.m == nil {
		mux.m = make(map[string]HttpHandle)
	}

	mux.m[pattern] = handler
	if pattern[len(pattern)-1] == '/' {
		n := len(mux.es)
		i := sort.Search(n, func(i int) bool {
			return len(mux.es[i]) < len(pattern)
		})
		if i == n {
			mux.es = append(mux.es, pattern)
		} else {
			mux.es = append(mux.es, "")    //先增加一个空数据
			copy(mux.es[i+1:], mux.es[i:]) // Move shorter entries down
			mux.es[i] = pattern
		}
	}

	if pattern[0] != '/' {
		mux.hosts = true
	}
}

func httpServerHandler(conInfo *ConInfo) {
	DefaultServeMux.HttpServerHandler(conInfo)
}

func (mux *ServeMux) HttpServerHandler(conInfo *ConInfo) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	req := &conInfo.Req
	rsp := &conInfo.Rsp

	var path string
	if mux.hosts {
		path = req.HostName + req.Header.Path
	} else {
		path = req.Header.Path
	}

	var h HttpHandle
	v, ok := mux.m[path]
	if ok {
		h = v
	}

	// 精确匹配失败的话 再模糊匹配一次
	if h == nil {
		for _, e := range mux.es {
			if strings.HasPrefix(path, e) {
				v, ok := mux.m[e] //如果能找到的话 这里必然应该有
				if ok {
					h = v
					break
				}
			}
		}
	}

	if h == nil {
		rsp.StatusCode = StatusNotFound
		return
	}

	h(conInfo)
}

// websocket注册 只能注册一个
type WSHandle func(conInfo *ConInfo)

type WSHandleInfo struct {
	mu      sync.RWMutex
	pattern string
	handler WSHandle
	hosts   bool // whether any patterns contain hostnames
}

var wsHandleInfo WSHandleInfo

func HandleWSFunc(pattern string, handler WSHandle) {
	wsHandleInfo.HandleWSFunc(pattern, handler)
}

func (wsi *WSHandleInfo) HandleWSFunc(pattern string, handler WSHandle) {
	if pattern == "" || handler == nil {
		return
	}

	wsi.mu.Lock()
	defer wsi.mu.Unlock()

	wsi.pattern = pattern
	wsi.handler = handler
	if pattern[0] != '/' {
		wsi.hosts = true
	}

}

func getWSHandler(conInfo *ConInfo) WSHandle {
	return wsHandleInfo.GetWSHandler(conInfo)
}

func (wsi *WSHandleInfo) GetWSHandler(conInfo *ConInfo) WSHandle {
	wsi.mu.RLock()
	defer wsi.mu.RUnlock()

	req := &conInfo.Req
	rsp := &conInfo.Rsp

	var path string
	if wsi.hosts {
		path = req.HostName + req.Header.Path
	} else {
		path = req.Header.Path
	}

	var h WSHandle
	if path == wsi.pattern {
		h = wsi.handler
	}

	if h == nil {
		rsp.StatusCode = StatusNotFound
		return nil
	}

	return h
}

func UpgradeCheck(conInfo *ConInfo) {
	const badHandshake = "websocket: the client is not using the websocket protocol: "

	req := &conInfo.Req
	rsp := &conInfo.Rsp
	rsp.StatusCode = StatusOK

	// 判断URL是否一致
	h := getWSHandler(conInfo)
	if h == nil {
		rsp.StatusCode = StatusBadRequest
		rsp.Body = append(rsp.Body, "websocket: request url error"...)
		return
	}

	if req.Header.Method != "GET" {
		rsp.StatusCode = StatusMethodNotAllowed
		rsp.Body = append(rsp.Body, badHandshake+"request method is not GET"...)
		return
	}

	if !req.Header.ContainsValue("upgrade", []byte("websocket")) {
		rsp.StatusCode = StatusBadRequest
		rsp.Body = append(rsp.Body, badHandshake+"'websocket' token not found in 'Upgrade' header"...)
		return
	}

	challengeKey := req.Header.Get("sec-websocket-key")
	if len(challengeKey) == 0 {
		rsp.StatusCode = StatusBadRequest
		rsp.Body = append(rsp.Body, "websocket: not a websocket handshake: 'Sec-WebSocket-Key' header is missing or blank"...)
	}

	rsp.Body = append(rsp.Body, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "...)
	rsp.Body = append(rsp.Body, computeAcceptKey(challengeKey)...)
	rsp.Body = append(rsp.Body, "\r\n"...)
	rsp.Body = append(rsp.Body, "\r\n"...)

	conInfo.wsHandler = h
	if wsPinghandler == nil {
		SetWSPingHandler(nil)
	}
	if wsCloseHandler == nil {
		SetWSCloseHandler(nil)
	}
}

var keyGUID = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

func computeAcceptKey(challengeKey []byte) []byte {
	h := sha1.New()
	h.Write(challengeKey)
	h.Write(keyGUID)
	src := h.Sum(nil)
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dst, src)
	return dst
}

func ParseWSReq(data []byte, wsMsg *WSMessage) (leftover []byte, err error) {

	// 客户端的请求至少有2个字节的请求头 4个字节的掩码
	// 客户端到服务端的请求必须掩码处理 服务端发送不需要
	if len(data) < 6 {
		return data, nil
	}

	// 第1个字节的前8位分别为 FIN RSV1 RSV2 RSV3 opcode(4)
	// 第2个字节的分别为 MASK PayloadLen(7)
	// 第3、4个字节可选 当PayloadLen=126时占用
	// 第5、6、7、8、9、10个字节可选 当PayloadLen=127时占用
	// 第10-13个字节可选 为maskingkey 设置了mask就有
	// 对于可选字节 没有的时候不占用 比如3-10没用的话 maskingkey会放在第3个字节
	final := data[0]&finalBit != 0
	frameType := int(data[0] & 0xf)
	if wsMsg.MessageType == 0 {
		wsMsg.MessageType = frameType
	}

	// RSV 不协商使用的话 都为0
	if rsv := data[0] & (rsv1Bit | rsv2Bit | rsv3Bit); rsv != 0 {
		return data, fmt.Errorf("unexpected reserved bits 0x" + strconv.FormatInt(int64(rsv), 16))
	}

	mask := data[1]&maskBit != 0
	if !mask {
		return data, errors.New("no mask flag from client")
	}

	payloadLen := int64(data[1] & 0x7f)

	// 请求长度识别
	iPos := 2
	switch payloadLen {
	case 126:
		if len(data) < 4 {
			return data, nil
		}
		p := data[2:4]
		payloadLen = int64(binary.BigEndian.Uint16(p))
		iPos = 4

	case 127:
		if len(data) < 10 {
			return data, nil
		}
		p := data[2:10]
		payloadLen = int64(binary.BigEndian.Uint64(p))
		iPos = 10
	}

	// 单次请求完整性判断
	// 4 frame masking
	if len(data) < (iPos + 4 + (int)(payloadLen)) {
		return data, nil
	}

	// 读取mask
	copy(wsMsg.maskKey[:], data[iPos:iPos+4])
	iPos += 4

	switch frameType {
	case CloseMessage, PingMessage, PongMessage:
		if payloadLen > maxControlFramePayloadSize {
			return data, errors.New("control frame length > 125")
		}
		if !final {
			return data, errors.New("control frame not final")
		}
	case TextMessage, BinaryMessage:
		if wsMsg.msContinue {
			return data, errors.New("message start before final message frame")
		}
		wsMsg.msContinue = !final
	case continuationFrame:
		if !wsMsg.msContinue {
			return data, errors.New("continuation after final message frame")
		}
		wsMsg.msContinue = !final
	default:
		return data, errors.New("unknown opcode " + strconv.Itoa(frameType))
	}

	if payloadLen > 0 {
		oldLen := len(wsMsg.ReqData)
		addLen := (int)(payloadLen)
		wsMsg.ReqData = append(wsMsg.ReqData, data[iPos:iPos+addLen]...)
		iPos += addLen
		maskBytes(wsMsg.maskKey, oldLen, wsMsg.ReqData)
	}

	leftover = data[iPos:]
	return leftover, nil
}

func (conn *ConInfo) handleWSControlFrame() {
	wsMsg := &conn.WSMsg
	switch wsMsg.MessageType {
	case PingMessage:
		wsPinghandler(conn)
		wsMsg.MessageType = PongMessage
	case CloseMessage:
		wsMsg.CloseCode = CloseNoStatusReceived
		if len(wsMsg.ReqData) >= 2 {
			wsMsg.CloseCode = int(binary.BigEndian.Uint16(wsMsg.ReqData))
		}
		wsCloseHandler(conn)
		wsMsg.Action = Close
	}
	return
}

const wordSize = int(unsafe.Sizeof(uintptr(0)))

func maskBytes(key [4]byte, pos int, b []byte) int {
	// Mask one byte at a time for small buffers.
	if len(b) < 2*wordSize {
		for i := range b {
			b[i] ^= key[pos&3]
			pos++
		}
		return pos & 3
	}

	// Mask one byte at a time to word boundary.
	if n := int(uintptr(unsafe.Pointer(&b[0]))) % wordSize; n != 0 {
		n = wordSize - n
		for i := range b[:n] {
			b[i] ^= key[pos&3]
			pos++
		}
		b = b[n:]
	}

	// Create aligned word size key.
	var k [wordSize]byte
	for i := range k {
		k[i] = key[(pos+i)&3]
	}
	kw := *(*uintptr)(unsafe.Pointer(&k))

	// Mask one word at a time.
	n := (len(b) / wordSize) * wordSize
	for i := 0; i < n; i += wordSize {
		*(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(&b[0])) + uintptr(i))) ^= kw
	}

	// Mask one byte at a time for remaining bytes.
	b = b[n:]
	for i := range b {
		b[i] ^= key[pos&3]
		pos++
	}

	return pos & 3
}

var validReceivedCloseCodes = map[int]bool{
	// see http://www.iana.org/assignments/websocket/websocket.xhtml#close-code-number

	CloseNormalClosure:           true,
	CloseGoingAway:               true,
	CloseProtocolError:           true,
	CloseUnsupportedData:         true,
	CloseNoStatusReceived:        false,
	CloseAbnormalClosure:         false,
	CloseInvalidFramePayloadData: true,
	ClosePolicyViolation:         true,
	CloseMessageTooBig:           true,
	CloseMandatoryExtension:      true,
	CloseInternalServerErr:       true,
	CloseServiceRestart:          true,
	CloseTryAgainLater:           true,
	CloseTLSHandshake:            false,
}

func isValidReceivedCloseCode(code int) bool {
	return validReceivedCloseCodes[code] || (code >= 3000 && code <= 4999)
}

func FormatCloseMessage(closeCode int, data []byte) []byte {
	if closeCode == CloseNoStatusReceived {
		// Return empty message because it's illegal to send
		// CloseNoStatusReceived. Return non-nil value in case application
		// checks for nil.
		return []byte{}
	}
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf, uint16(closeCode))
	copy(buf[2:], data)
	return buf
}

var wsPinghandler WSHandle
var wsCloseHandler WSHandle

func SetWSCloseHandler(h func(conInfo *ConInfo)) {
	if h == nil {
		h = func(conInfo *ConInfo) {
			message := FormatCloseMessage(conInfo.WSMsg.CloseCode, nil)
			conInfo.WSMsg.RspData = append(conInfo.WSMsg.RspData, message...)
			return
		}
	}

	wsCloseHandler = h
}

func SetWSPingHandler(h func(conInfo *ConInfo)) {
	if h == nil {
		h = func(conInfo *ConInfo) {
			conInfo.WSMsg.RspData = append(conInfo.WSMsg.RspData, conInfo.WSMsg.ReqData...)
			return
		}
	}

	wsPinghandler = h
}

func isWSControl(frameType int) bool {
	return frameType == CloseMessage || frameType == PingMessage || frameType == PongMessage
}

func isWSData(frameType int) bool {
	return frameType == TextMessage || frameType == BinaryMessage
}

func (conn *ConInfo) appendWSOutBuf() {
	wsMsg := &conn.WSMsg
	if len(wsMsg.RspData) == 0 {
		return
	}

	conn.tmpBuf = conn.tmpBuf[:10]
	framePos := 2
	dataLen := len(wsMsg.RspData)
	conn.tmpBuf[0] = byte(wsMsg.MessageType)
	conn.tmpBuf[0] |= finalBit
	switch {
	case dataLen >= 65536:
		conn.tmpBuf[1] = 127
		binary.BigEndian.PutUint64(conn.tmpBuf[2:], uint64(dataLen))
		framePos += 8
	case dataLen > 125:
		conn.tmpBuf[1] = 126
		binary.BigEndian.PutUint16(conn.tmpBuf[2:], uint16(dataLen))
		framePos += 2
		conn.tmpBuf = conn.tmpBuf[:4]
	default:
		conn.tmpBuf[1] = byte(dataLen)
		conn.tmpBuf = conn.tmpBuf[:2]
	}

	conn.out = append(conn.out, conn.tmpBuf...)
	conn.out = append(conn.out, wsMsg.RspData...)

}

func isControl(frameType int) bool {
	return frameType == CloseMessage || frameType == PingMessage || frameType == PongMessage
}

func isData(frameType int) bool {
	return frameType == TextMessage || frameType == BinaryMessage
}
