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

	// add SSL CA
	gaio.SSLEnvInit()
	if !gaio.SetSSLWithPort("./ca/cacert.pem", "./ca/privkey.pem", "50006") {
		return
	}
	if !gaio.SetSSLWithPort("./ca/ca_ee.pem", "./ca/key_ee.pem", "50007") {
		return
	}

	// SSL server1
	var err error
	HandleFunc("/", IndexHandler)
	go func() {
		err = StartHttpServe("127.0.0.1:50006", 1, false)
		if err != nil {
			fmt.Println("faild to start server")
		}
	}()

	//SSL server2
	HandleFunc("/", IndexHandler1)
	go func() {
		err = StartHttpServe("127.0.0.1:50007", 1, false)
		if err != nil {
			fmt.Println("faild to start server")
		}
	}()

	// Common server
	HandleFunc("/", IndexHandler2)
	err = StartHttpServe("127.0.0.1:50008", 1, false)
	if err != nil {
		fmt.Println("faild to start server")
	}
}

func IndexHandler(conInfo *ConInfo) {
	req := &conInfo.Req
	rsp := &conInfo.Rsp
	if 0 == strings.Compare(req.Header.RequestURI, "/") || 0 == strings.Compare(req.Header.RequestURI, "/index.html") {
		//content, _ := ioutil.ReadFile("/home/charles/www/index.html")
		rsp.Body = append(rsp.Body, rspBody...)
	} else {
		rsp.StatusCode = StatusBadRequest
	}
}

func IndexHandler1(conInfo *ConInfo) {
	IndexHandler(conInfo)
}

func IndexHandler2(conInfo *ConInfo) {
	IndexHandler(conInfo)
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
	// gorilla/websocket ??????????????????????????????4096??????????????????????????????4096??? ????????????6????????? ???4102
	// ??????????????????????????????5120 ?????????????????????????????? ??????????????? ?????????????????????????????????
	defaultRecBufSize   = 5120
	defaultInOutBufSize = 5120

	ContentLenLen = 15

	// HTTP ?????????
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
	rec    []byte //  ????????????
	in     []byte //  ??????????????????
	out    []byte //  ????????????
	tmpBuf []byte // ???????????? ?????????ws???????????????????????????
	wc     *gaio.Watcher
	Conn   net.Conn
	Req    Request  //  http????????????
	Rsp    Response // http????????????

	// websocket ????????????
	WSMsg     WSMessage
	wsHandler WSHandle
}

type Request struct {
	Header      HttpRequestHeader
	Body        []byte
	RemoteAddr  string
	HostName    string // host??? ???????????????
	ContentType string
}

type Response struct {
	Body        []byte
	ContentType string
	StatusCode  int
	Action      int //??????????????????
}

type HttpRequestHeader struct {
	Method     string
	RequestURI string
	Host       string
	Path       string // ????????????????????????  ????????????????????????????????????

	IfPost        bool
	KeepAlive     bool
	Upgrade       bool
	ContentLength int
	BufKV         map[string][]byte // ???????????????
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
	msContinue  bool //???????????????????????????????????????
	MessageType int
	Message     []byte //??????????????????????????????????????????
}

type WSMessage struct {
	maskKey     [4]byte
	msContinue  bool //???????????????????????????????????????
	MessageType int
	CloseCode   int
	ReqData     []byte //??????????????????????????????????????????
	RspData     []byte //????????????
	Action      int    //??????????????????
}

func (rsp *Response) Reset() {
	rsp.ContentType = ""
	rsp.StatusCode = 0
	rsp.Body = rsp.Body[0:0]
}

// ?????????????????????
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

// ?????????????????????
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

// ????????????????????????
func (conn *ConInfo) Begin(packet []byte) (data []byte) {
	data = packet
	if len(conn.in) > 0 {
		conn.in = append(conn.in, data...)
		data = conn.in
	}
	return data
}

// ????????????????????????????????? ????????????????????????????????????????????????
func (conn *ConInfo) End(data []byte) {
	if len(data) > 0 {
		if len(data) != len(conn.in) { // ???????????? ???????????????????????????
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
					// ??????????????????????????? ??????????????????  ?????????????????????????????????????????????????????????
					// ??????????????????2????????? 1.??????????????????????????? ???????????????  2. ????????????????????? ??????????????????
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
	// ??????out??????
	ifClose = false
	conInfo = res.Context.(*ConInfo)
	//log.Println("handleReadBack ", conInfo.Conn.RemoteAddr())
	if len(conInfo.out) > 0 {
		conInfo.out = conInfo.out[:0]
	}

	// ???????????????
	if res.Error != nil {
		ifClose = true
		return
	}

	// ????????????
	if len(res.Buffer) == 0 || res.Size == 0 {
		return
	}

	// ??????????????????
	if res.Size > len(res.Buffer) {
		ifClose = true
		return
	} else {
		res.Buffer = res.Buffer[0:res.Size]
	}

	data := conInfo.Begin(res.Buffer)

	for {
		if conInfo.wsHandler == nil { //HTTP ??????
			req := &conInfo.Req
			rsp := &conInfo.Rsp
			req.Reset()
			rsp.Reset()
			leftover, err := ParseHttpReq(data, req)
			if err != nil {
				// ????????????
				rsp.StatusCode = StatusBadRequest
				conInfo.appendHttpOutBuf()
				break
			} else if len(leftover) == len(data) {
				// ???????????????
				break
			}

			// ??????????????????
			req.RemoteAddr = res.Conn.RemoteAddr().String()

			// ?????????????????????websocket ????????????
			if req.Header.Upgrade {
				UpgradeCheck(conInfo)
				if rsp.StatusCode == StatusOK {
					// ?????????????????? ?????????????????????
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
				// Http ????????????
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
		} else { // websocket  ????????????
			if conInfo.tmpBuf == nil {
				conInfo.tmpBuf = make([]byte, 0, maxFrameHeaderSize)
			}
			wsMsg := &conInfo.WSMsg
			leftover, err := ParseWSReq(data, wsMsg)
			if err != nil {
				// ????????????
				wsMsg.RspData = append(wsMsg.RspData, "bad request"...)
				conInfo.appendWSOutBuf()
				wsMsg.Reset()
				break
			} else if len(leftover) == len(data) {
				//fmt.Println("frame incomplete ", len(leftover), len(wsMsg.ReqData), len(wsMsg.RspData))
				// ???????????????
				break
			} else if wsMsg.msContinue {
				// ????????????  ?????????
				//fmt.Println("data incomplete ", len(leftover), len(wsMsg.ReqData), len(wsMsg.RspData))
				data = leftover
				if len(data) == 0 {
					break
				}
				continue
			}

			//fmt.Println("rec data  ", len(wsMsg.ReqData), len(leftover), len(wsMsg.RspData))
			if isControl(wsMsg.MessageType) {
				// ???????????????
				conInfo.handleWSControlFrame()
			} else {
				// ??????????????????
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

// ?????????????????????body???????????? ??????????????????????????????
func ParseHttpReq(data []byte, req *Request) (leftover []byte, err error) {

	// ???????????????
	bHeadEnd := false
	bWithBody := false
	bBodyEnd := false
	indexHeadEnd := bytes.Index(data, HeaderCrlfCrlf) // ??????????????????
	if indexHeadEnd > 0 {
		bHeadEnd = true
		indexCon := bytes.Index(data[:indexHeadEnd], HeaderContentLength) // ????????????
		if indexCon < 0 {
			indexCon = bytes.Index(data[:indexHeadEnd], HeaderContentLengthLower) // ???????????? ?????????????????????
		}
		if indexCon > 0 {
			bWithBody = true
			index := bytes.Index(data[indexCon:indexHeadEnd+2], HeaderCrlf) // ????????????
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

	// ??????????????? ?????? ?????????????????????????????????????????????
	if !bHeadEnd || (bWithBody && !bBodyEnd) {
		return data, nil
	}

	// ??????????????????
	iLeft := indexHeadEnd + 4 + req.Header.ContentLength
	if len(data) > iLeft {
		leftover = data[iLeft:]
	}

	buf := data[:indexHeadEnd+2] // buf??????????????????http?????????

	// ?????????/??????
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

	// ??????????????????(???????????????)
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

	// ??????????????????
	n = strings.Index(req.Header.Host, strColon)
	if n > 0 {
		req.HostName = string(req.Header.Host[:n])
	}

	// ???Path????????????
	n = strings.LastIndex(req.Header.RequestURI, strQuestion)
	if n >= 0 {
		req.Header.Path = string(req.Header.RequestURI[:n+1])
	} else {
		req.Header.Path = string(req.Header.RequestURI)
	}

	return leftover, nil
}

// a?????????b????????? ??????????????????
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

// ????????????????????? ??????????????????
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

// ????????????????????? ??????????????????
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

// ??????http??????
// ???????????????  ??????  ????????????????????? ??????????????????
// ???????????????????????????1 ??????????????????????????? ?????????????????? ?????????????????????
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

// ???????????????????????? ?????????go http
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
			mux.es = append(mux.es, "")    //????????????????????????
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

	// ???????????????????????? ?????????????????????
	if h == nil {
		for _, e := range mux.es {
			if strings.HasPrefix(path, e) {
				v, ok := mux.m[e] //????????????????????? ?????????????????????
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

// websocket?????? ??????????????????
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

	// ??????URL????????????
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

	// ???????????????????????????2????????????????????? 4??????????????????
	// ???????????????????????????????????????????????? ????????????????????????
	if len(data) < 6 {
		return data, nil
	}

	// ???1???????????????8???????????? FIN RSV1 RSV2 RSV3 opcode(4)
	// ???2????????????????????? MASK PayloadLen(7)
	// ???3???4??????????????? ???PayloadLen=126?????????
	// ???5???6???7???8???9???10??????????????? ???PayloadLen=127?????????
	// ???10-13??????????????? ???maskingkey ?????????mask??????
	// ?????????????????? ???????????????????????? ??????3-10???????????? maskingkey????????????3?????????
	final := data[0]&finalBit != 0
	frameType := int(data[0] & 0xf)
	if wsMsg.MessageType == 0 {
		wsMsg.MessageType = frameType
	}

	// RSV ????????????????????? ??????0
	if rsv := data[0] & (rsv1Bit | rsv2Bit | rsv3Bit); rsv != 0 {
		return data, fmt.Errorf("unexpected reserved bits 0x" + strconv.FormatInt(int64(rsv), 16))
	}

	mask := data[1]&maskBit != 0
	if !mask {
		return data, errors.New("no mask flag from client")
	}

	payloadLen := int64(data[1] & 0x7f)

	// ??????????????????
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

	// ???????????????????????????
	// 4 frame masking
	if len(data) < (iPos + 4 + (int)(payloadLen)) {
		return data, nil
	}

	// ??????mask
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
