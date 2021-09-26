// +build linux darwin netbsd freebsd openbsd dragonfly

// Package gaio is an Async-IO library for Golang.
//
// gaio acts in proactor mode, https://en.wikipedia.org/wiki/Proactor_pattern.
// User submit async IO operations and waits for IO-completion signal.
package gaio

import "C"
import (
	"container/heap"
	"container/list"
	"errors"
	"io"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

/*
//#cgo darwin CFLAGS: -DCGO_OS_DARWIN=1
//#cgo linux CFLAGS: -DCGO_OS_LINUX=1
#cgo CFLAGS: -I ./cfile/include/
#cgo LDFLAGS: -l ssl -l crypto -ldl
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include "openssl/ssl.h"
typedef enum {
    SSL_CONN_INIT,
    SSL_SHAKE_HAND_BEGIN,
    SSL_SHAKE_HAND_END,
    SSL_PLAIN_TEXT,
} SSLConnStatus;

void C_SSLEnvInit() {
	SSL_load_error_strings(); /// 注册SSL错误信息
	SSL_library_init(); /// SSL库初始化
	OpenSSL_add_all_algorithms(); /// SSL算法加载
}

SSL_CTX* C_NewSSLCTX(char* caPath, char* keyPath) {
	SSL_CTX* sslCTX = SSL_CTX_new(SSLv23_server_method());
	if (sslCTX == NULL) {
		return NULL;
	}

	// 加载服务端数字证书
    int iRst = 0;
	iRst = SSL_CTX_use_certificate_file(sslCTX, caPath, SSL_FILETYPE_PEM);
	if (iRst <= 0) {
		printf("SSL_CTX_use_certificate failed %d\n", errno);
		SSL_CTX_free(sslCTX);
		return NULL;
	}

	// 加载私钥 (PEM格式 )
	iRst = SSL_CTX_use_PrivateKey_file(sslCTX, keyPath, SSL_FILETYPE_PEM);
	if (iRst <= 0) {
		printf("SSL_CTX_use_PrivateKey failed %d\n", errno);
		SSL_CTX_free(sslCTX);
		return NULL;
	}

	// 私钥验证
	iRst = SSL_CTX_check_private_key(sslCTX);
	if (iRst <= 0) {
		printf("SSL_CTX_check_private_key failed %d\n", errno);
		SSL_CTX_free(sslCTX);
		return NULL;
	}

	/// 对于非阻塞模式， SSL_write 默认直到发送完才会返回成功，未全部发送完时返回errno 11， SSL error 3
	/// 设置SSL_CTX_set_mode（3）后，每次调用SSL_write都会返回发送了多少
	SSL_CTX_set_mode(sslCTX, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    printf("SSL_CTX_new addr %p\n", sslCTX);
    return sslCTX;
}

void C_CheckSSLCTXAddr(SSL_CTX *sslCTX)
{
    printf("C_CheckSSLCTXAddr  %p\n", sslCTX);
}

int C_SSLHandShake(int fd, int* ssl_conn_status, SSL_CTX *ssl_ctx, SSL** ssl_)
{
    if (NULL == ssl_ctx) {
        printf("SSLHandleShake ssl_ctx == NULL\n");
        return -1;
    }

    /// 初始化状态
    int iRst = 0;
    if (SSL_CONN_INIT == *ssl_conn_status){
        /// 取第一个字节判断是否是SSL连接
        char buf[1];
        iRst = recv(fd, buf, 1, MSG_PEEK); ///MSG_PEEK标志只是从缓冲区拷贝数据但是不会减少缓冲区数据
        if (0 == iRst) { /// 关闭连接了
            //printf("SSLHandleShake fd %d, iRst %d, err : %d\n", fd, iRst, errno);
            return -1;
        } else if (-1 == iRst){
            if (errno != EAGAIN) {
                printf("SSLHandleShake fd %d, iRst %d, err : %d\n", fd, iRst, errno);
                return -1;
            } else
                //printf("SSLHandleShake fd %d, iRst %d, err : %d, no data now retur 0\n", fd, iRst, errno);
                return 0; /// 暂时没数据
        }

        /// 服务端为SSL模式，但是客户端发送非SSL数据的话返回SSL_PLAIN_TEXT状态 在具体应用协议层处理
        if (!(buf[0] & 0x80)   && (buf[0] != 0x16) ) { //SSLv2  SSLv3/TLSv1
            *ssl_conn_status = SSL_PLAIN_TEXT;
            //printf("SSLHandleShake SSL server but common client fd %d\n", fd);
            return 0;
        }

        if (NULL != *ssl_) {
            printf("SSLHandleShake before SSL_new but not NULL %d\n", fd);
        }
        *ssl_ = SSL_new(ssl_ctx);
        if (NULL == *ssl_) {
            printf("SSLHandleShake SSL_new failed\n");
            return -1;
        }
        //printf("SSL_new succeed addr %d %p\n", fd, *ssl_);

        if (!SSL_set_fd(*ssl_, fd)) {
            printf("SSLHandleShake SSL_set_fd failed");
            return -1;
        }

        SSL_set_accept_state(*ssl_);
        *ssl_conn_status = SSL_SHAKE_HAND_BEGIN;
    }


    if (NULL == *ssl_){
        printf("SSLHandleShake NULL == ssl_");
        return -1;
    }

    iRst = SSL_do_handshake(*ssl_);
    if (1 == iRst){
        *ssl_conn_status = SSL_SHAKE_HAND_END;

    } else {
        int err = SSL_get_error(*ssl_, iRst);
        if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ) {
            return -1;
        }
    }
    return 0;
}

int C_SSL_READ(int fd, void * buf, int bytes, SSL * ssl, int* errNo)
{
    if (NULL == ssl)
    {
        return -1;
    }

    int iRst = SSL_read(ssl, buf, bytes);
    *errNo = errno;
//    int ssl_err = SSL_get_error(ssl, fd);
//    if (iRst < 0 && ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE && ssl_err != SSL_ERROR_NONE) {
//        printf("fd %d, SSL_read return %d, ssl_err %d,  errno %d", fd, iRst, ssl_err, *errNo);
//    }
    return iRst;
}

int C_SSL_WRITE(int fd, void * buf, int bytes, SSL * ssl, int* errNo)
{
    if (NULL == ssl)
    {
        return -1;
    }

    int iRst =  SSL_write(ssl, buf, bytes);
    *errNo = errno;
//    int ssl_err = SSL_get_error(ssl, fd);
//    if (iRst < 0 && ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE && ssl_err != SSL_ERROR_NONE) {
//        printf("fd %d, SSL_read return %d, ssl_err %d,  errno %d", fd, iRst, ssl_err, *errNo);
//    }
    return iRst;
}


*/
import "C"

var (
	aiocbPool sync.Pool
)

func init() {
	aiocbPool.New = func() interface{} {
		return new(aiocb)
	}
}

// fdDesc contains all data structures associated to fd
type fdDesc struct {
	readers       list.List // all read/write requests
	writers       list.List
	ptr           uintptr // pointer to net.Conn
	r_armed       bool
	w_armed       bool
	ssl_          *C.SSL
	sslConnStatus C.int
}

// watcher will monitor events and process async-io request(s),
type watcher struct {
	// poll fd
	pfd *poller

	// netpoll events
	chEventNotify chan pollerEvents

	// events from user
	chPendingNotify   chan struct{}
	pendingCreate     []*aiocb
	pendingProcessing []*aiocb // swaped pending
	pendingMutex      sync.Mutex
	recycles          []*aiocb

	// IO-completion events to user
	chResults chan *aiocb

	// internal buffer for reading
	swapSize         int // swap buffer capacity, triple buffer
	swapBufferFront  []byte
	swapBufferMiddle []byte
	swapBufferBack   []byte
	bufferOffset     int   // bufferOffset for current using one
	shouldSwap       int32 // atomic mark for swap

	// loop cpu affinity
	chCPUID chan int32

	// loop related data structure
	descs      map[int]*fdDesc // all descriptors
	connIdents map[uintptr]int // we must not hold net.Conn as key, for GC purpose
	// for timeout operations which
	// aiocb has non-zero deadline, either exists
	// in timeouts & queue at any time
	// or in neither of them.
	timeouts timedHeap
	timer    *time.Timer
	// for garbage collector
	gc       []net.Conn
	gcMutex  sync.Mutex
	gcNotify chan struct{}

	die     chan struct{}
	dieOnce sync.Once
}

// NewWatcher creates a management object for monitoring file descriptors
// with default internal buffer size - 64KB
func NewWatcher() (*Watcher, error) {
	return NewWatcherSize(defaultInternalBufferSize)
}

// NewWatcherSize creates a management object for monitoring file descriptors.
// 'bufsize' sets the internal swap buffer size for Read() with nil, 2 slices with'bufsize'
// will be allocated for performance.
func NewWatcherSize(bufsize int) (*Watcher, error) {
	w := new(watcher)
	pfd, err := openPoll()
	if err != nil {
		return nil, err
	}
	w.pfd = pfd

	// loop related chan
	w.chCPUID = make(chan int32)
	w.chEventNotify = make(chan pollerEvents)
	w.chPendingNotify = make(chan struct{}, 1)
	w.chResults = make(chan *aiocb, maxEvents*4)
	w.die = make(chan struct{})

	// swapBuffer for shared reading
	w.swapSize = bufsize
	w.swapBufferFront = make([]byte, bufsize)
	w.swapBufferMiddle = make([]byte, bufsize)
	w.swapBufferBack = make([]byte, bufsize)

	// init loop related data structures
	w.descs = make(map[int]*fdDesc)
	w.connIdents = make(map[uintptr]int)
	w.gcNotify = make(chan struct{}, 1)
	w.timer = time.NewTimer(0)

	go w.pfd.Wait(w.chEventNotify)
	go w.loop()

	// watcher finalizer for system resources
	wrapper := &Watcher{watcher: w}
	runtime.SetFinalizer(wrapper, func(wrapper *Watcher) {
		wrapper.Close()
	})

	return wrapper, nil
}

// Set Poller Affinity for Epoll/Kqueue
func (w *watcher) SetPollerAffinity(cpuid int) (err error) {
	if cpuid >= runtime.NumCPU() {
		return ErrCPUID
	}

	// store and wakeup
	atomic.StoreInt32(&w.pfd.cpuid, int32(cpuid))
	w.pfd.wakeup()
	return nil
}

// Set Loop Affinity for syscall.Read/syscall.Write
func (w *watcher) SetLoopAffinity(cpuid int) (err error) {
	if cpuid >= runtime.NumCPU() {
		return ErrCPUID
	}

	// sendchan
	select {
	case w.chCPUID <- int32(cpuid):
	case <-w.die:
		return ErrConnClosed
	}
	return nil
}

// Close stops monitoring on events for all connections
func (w *watcher) Close() (err error) {
	w.dieOnce.Do(func() {
		close(w.die)
		err = w.pfd.Close()
	})
	return err
}

// notify new operations pending
func (w *watcher) notifyPending() {
	select {
	case w.chPendingNotify <- struct{}{}:
	default:
	}
}

// WaitIO blocks until any read/write completion, or error.
// An internal 'buf' returned or 'r []OpResult' are safe to use BEFORE next call to WaitIO().
func (w *watcher) WaitIO() (r []OpResult, err error) {
	// recycle previous aiocb
	for k := range w.recycles {
		aiocbPool.Put(w.recycles[k])
	}
	w.recycles = w.recycles[:0]

	for {
		select {
		case pcb := <-w.chResults:
			r = append(r, OpResult{Operation: pcb.op, Conn: pcb.conn, IsSwapBuffer: pcb.useSwap, Buffer: pcb.buffer, Size: pcb.size, Error: pcb.err, Context: pcb.ctx})
			w.recycles = append(w.recycles, pcb)
			for len(w.chResults) > 0 {
				pcb := <-w.chResults
				r = append(r, OpResult{Operation: pcb.op, Conn: pcb.conn, IsSwapBuffer: pcb.useSwap, Buffer: pcb.buffer, Size: pcb.size, Error: pcb.err, Context: pcb.ctx})
				w.recycles = append(w.recycles, pcb)
			}

			atomic.CompareAndSwapInt32(&w.shouldSwap, 0, 1)

			return r, nil
		case <-w.die:
			return nil, ErrWatcherClosed
		}
	}
}

// Read submits an async read request on 'fd' with context 'ctx', using buffer 'buf'.
// 'buf' can be set to nil to use internal buffer.
// 'ctx' is the user-defined value passed through the gaio watcher unchanged.
func (w *watcher) Read(ctx interface{}, conn net.Conn, buf []byte) error {
	return w.aioCreate(ctx, OpRead, conn, buf, zeroTime, false)
}

// ReadTimeout submits an async read request on 'fd' with context 'ctx', using buffer 'buf', and
// expects to read some bytes into the buffer before 'deadline'.
// 'ctx' is the user-defined value passed through the gaio watcher unchanged.
func (w *watcher) ReadTimeout(ctx interface{}, conn net.Conn, buf []byte, deadline time.Time) error {
	return w.aioCreate(ctx, OpRead, conn, buf, deadline, false)
}

// ReadFull submits an async read request on 'fd' with context 'ctx', using buffer 'buf', and
// expects to fill the buffer before 'deadline'.
// 'ctx' is the user-defined value passed through the gaio watcher unchanged.
// 'buf' can't be nil in ReadFull.
func (w *watcher) ReadFull(ctx interface{}, conn net.Conn, buf []byte, deadline time.Time) error {
	if len(buf) == 0 {
		return ErrEmptyBuffer
	}
	return w.aioCreate(ctx, OpRead, conn, buf, deadline, true)
}

// Write submits an async write request on 'fd' with context 'ctx', using buffer 'buf'.
// 'ctx' is the user-defined value passed through the gaio watcher unchanged.
func (w *watcher) Write(ctx interface{}, conn net.Conn, buf []byte) error {
	if len(buf) == 0 {
		return ErrEmptyBuffer
	}
	return w.aioCreate(ctx, OpWrite, conn, buf, zeroTime, false)
}

// WriteTimeout submits an async write request on 'fd' with context 'ctx', using buffer 'buf', and
// expects to complete writing the buffer before 'deadline', 'buf' can be set to nil to use internal buffer.
// 'ctx' is the user-defined value passed through the gaio watcher unchanged.
func (w *watcher) WriteTimeout(ctx interface{}, conn net.Conn, buf []byte, deadline time.Time) error {
	if len(buf) == 0 {
		return ErrEmptyBuffer
	}
	return w.aioCreate(ctx, OpWrite, conn, buf, deadline, false)
}

// Free let the watcher to release resources related to this conn immediately,
// like socket file descriptors.
func (w *watcher) Free(conn net.Conn) error {
	return w.aioCreate(nil, opDelete, conn, nil, zeroTime, false)
}

// core async-io creation
func (w *watcher) aioCreate(ctx interface{}, op OpType, conn net.Conn, buf []byte, deadline time.Time, readfull bool) error {
	select {
	case <-w.die:
		return ErrWatcherClosed
	default:
		var ptr uintptr
		if conn != nil && reflect.TypeOf(conn).Kind() == reflect.Ptr {
			ptr = reflect.ValueOf(conn).Pointer()
		} else {
			return ErrUnsupported
		}

		cb := aiocbPool.Get().(*aiocb)
		*cb = aiocb{op: op, ptr: ptr, size: 0, ctx: ctx, conn: conn, buffer: buf, deadline: deadline, readFull: readfull, idx: -1}

		w.pendingMutex.Lock()
		w.pendingCreate = append(w.pendingCreate, cb)
		w.pendingMutex.Unlock()

		w.notifyPending()
		return nil
	}
}

// tryRead will try to read data on aiocb and notify
func (w *watcher) tryRead(fd int, pcb *aiocb) bool {
	desc, ok := w.descs[fd]
	if !ok {
		return false
	}

	buf := pcb.buffer

	useSwap := false
	backBuffer := false

	if buf == nil { // internal or backBuffer
		if atomic.CompareAndSwapInt32(&w.shouldSwap, 1, 0) {
			w.swapBufferFront, w.swapBufferMiddle, w.swapBufferBack = w.swapBufferMiddle, w.swapBufferBack, w.swapBufferFront
			w.bufferOffset = 0
		}

		buf = w.swapBufferFront[w.bufferOffset:]
		if len(buf) > 0 {
			useSwap = true
		} else {
			backBuffer = true
			buf = pcb.backBuffer[:]
		}
	}

	nr := 0
	var er error
	for {
		// 先进行SSL处理
		bSSL := ifSSLConn(desc)
		if bSSL && desc.sslConnStatus != SSL_SHAKE_HAND_END {
			iRst := SSLHandShake(fd, desc)
			if iRst == -1 {
				pcb.err = errors.New("SSLHandShake failed")
				break
			}

			if desc.sslConnStatus < SSL_SHAKE_HAND_END {
				return false
			}

			if desc.sslConnStatus == SSL_PLAIN_TEXT { //先按错误处理 后面考虑重定向
				pcb.err = errors.New("SSL server but common client")
				break
			}

			//log.Println("tryRead handshake finish ", fd)
		}

		// return values are stored in pcb
		if bSSL {
			iSize := len(buf[pcb.size:])
			cBuf := unsafe.Pointer(&buf[pcb.size])
			var cErr C.int
			nr = (int)(C.C_SSL_READ(C.int(fd), cBuf, C.int(iSize), desc.ssl_, &cErr))
			//log.Println("tryRead SSL_READ finish ", fd, nr, cErr, desc.ssl_)
			if nr == 0 {
				pcb.err = io.EOF
				break
			}
			if nr == -1 {
				if cErr == ErrIntr {
					continue
				}
				if cErr != ErrAgain {
					pcb.err = io.EOF
					break
				} else {
					return false
				}
			}
			pcb.size += nr
			break

		} else {
			nr, er = rawRead(fd, buf[pcb.size:])
			if er == syscall.EAGAIN {
				return false
			}

			// On MacOS we can see EINTR here if the user
			// pressed ^Z.
			if er == syscall.EINTR {
				continue
			}

			// if er is nil, accumulate bytes read
			if er == nil {
				pcb.size += nr
			}

			pcb.err = er
			// proper setting of EOF
			if nr == 0 && er == nil {
				pcb.err = io.EOF
			}

			break
		}

	}

	if pcb.readFull { // read full operation
		if pcb.err != nil {
			return true
		}
		if pcb.size == len(pcb.buffer) {
			return true
		}
		return false
	}

	if useSwap { // IO completed with internal buffer
		pcb.useSwap = true
		pcb.buffer = buf[:pcb.size] // set len to pcb.size
		w.bufferOffset += pcb.size
	} else if backBuffer { // internal buffer exhausted
		pcb.buffer = buf
	}
	return true
}

func (w *watcher) tryWrite(fd int, pcb *aiocb) bool {
	var nw int
	var ew error

	if pcb.buffer != nil {
		desc, ok := w.descs[fd]
		if !ok {
			return false
		}
		for {
			if ifSSLConn(desc) {
				iSize := len(pcb.buffer[pcb.size:])
				cBuf := unsafe.Pointer(&pcb.buffer[pcb.size])
				var cErr C.int
				nw = (int)(C.C_SSL_WRITE(C.int(fd), cBuf, C.int(iSize), desc.ssl_, &cErr))
				if nw < 0 {
					if cErr == ErrIntr {
						continue
					}

					if cErr != ErrAgain {
						pcb.err = io.EOF
						break
					} else {
						return false
					}
				}

				pcb.size += nw
				break

			} else {
				nw, ew = rawWrite(fd, pcb.buffer[pcb.size:])
				pcb.err = ew
				if ew == syscall.EAGAIN {
					return false
				}

				if ew == syscall.EINTR {
					continue
				}

				// if ew is nil, accumulate bytes written
				if ew == nil {
					pcb.size += nw
				}
				break
			}
		}
	}

	// all bytes written or has error
	// nil buffer still returns
	if pcb.size == len(pcb.buffer) || ew != nil {
		return true
	}
	return false
}

// release connection related resources
func (w *watcher) releaseConn(ident int) {
	if desc, ok := w.descs[ident]; ok {
		// delete from heap
		for e := desc.readers.Front(); e != nil; e = e.Next() {
			tcb := e.Value.(*aiocb)
			// notify caller
			tcb.err = io.ErrClosedPipe
			w.deliver(tcb)
		}

		for e := desc.writers.Front(); e != nil; e = e.Next() {
			tcb := e.Value.(*aiocb)
			tcb.err = io.ErrClosedPipe
			w.deliver(tcb)
		}

		if desc.ssl_ != nil {
			C.SSL_free(desc.ssl_)
		}
		delete(w.descs, ident)
		delete(w.connIdents, desc.ptr)
		// close socket file descriptor duplicated from net.Conn
		syscall.Close(ident)
	}
}

// deliver function will try best to aggregate results for batch delivery
func (w *watcher) deliver(pcb *aiocb) {
	if pcb.idx != -1 {
		heap.Remove(&w.timeouts, pcb.idx)
	}

	select {
	case w.chResults <- pcb:
	case <-w.die:
	}
}

// the core event loop of this watcher
func (w *watcher) loop() {
	// defer function to release all resources
	defer func() {
		for ident := range w.descs {
			w.releaseConn(ident)
		}
	}()

	for {
		select {
		case <-w.chPendingNotify:
			// swap w.pending with w.pending2
			w.pendingMutex.Lock()
			w.pendingCreate, w.pendingProcessing = w.pendingProcessing, w.pendingCreate
			w.pendingCreate = w.pendingCreate[:0]
			w.pendingMutex.Unlock()
			w.handlePending(w.pendingProcessing)

		case pe := <-w.chEventNotify: // poller events
			w.handleEvents(pe)

		case <-w.timer.C: // timeout heap
			for w.timeouts.Len() > 0 {
				now := time.Now()
				pcb := w.timeouts[0]
				if now.After(pcb.deadline) {
					// ErrDeadline
					pcb.err = ErrDeadline
					// remove from list
					pcb.l.Remove(pcb.elem)
					w.deliver(pcb)
				} else {
					w.timer.Reset(pcb.deadline.Sub(now))
					break
				}
			}

		case <-w.gcNotify: // gc recycled net.Conn
			w.gcMutex.Lock()
			for i, c := range w.gc {
				ptr := reflect.ValueOf(c).Pointer()
				if ident, ok := w.connIdents[ptr]; ok {
					// since it's gc-ed, queue is impossible to hold net.Conn
					// we don't have to send to chIOCompletion,just release here
					w.releaseConn(ident)
				}
				w.gc[i] = nil
			}
			w.gc = w.gc[:0]
			w.gcMutex.Unlock()

		case cpuid := <-w.chCPUID:
			setAffinity(cpuid)

		case <-w.die:
			return
		}
	}
}

// for loop handling pending requests
func (w *watcher) handlePending(pending []*aiocb) {
	for _, pcb := range pending {
		ident, ok := w.connIdents[pcb.ptr]
		// resource releasing operation
		if pcb.op == opDelete && ok {
			w.releaseConn(ident)
			continue
		}

		// handling new connection
		var desc *fdDesc
		if ok {
			desc = w.descs[ident]
		} else {
			if dupfd, err := dupconn(pcb.conn); err != nil {
				// unexpected situation, should notify caller if we cannot dup(2)
				pcb.err = err
				w.deliver(pcb)
				continue
			} else {
				// as we duplicated successfully, we're safe to
				// close the original connection
				//log.Println("handlePending, get new fd ", pcb.conn.RemoteAddr(), dupfd)
				pcb.conn.Close()
				// assign idents
				ident = dupfd

				werr := w.pfd.Watch(ident)
				if werr != nil {
					pcb.err = werr
					w.deliver(pcb)
					continue
				}

				// file description bindings
				desc = &fdDesc{ptr: pcb.ptr}
				w.descs[ident] = desc
				w.connIdents[pcb.ptr] = ident

				// the conn is still useful for GC finalizer.
				// note finalizer function cannot hold reference to net.Conn,
				// if not it will never be GC-ed.
				runtime.SetFinalizer(pcb.conn, func(c net.Conn) {
					w.gcMutex.Lock()
					w.gc = append(w.gc, c)
					w.gcMutex.Unlock()

					// notify gc processor
					select {
					case w.gcNotify <- struct{}{}:
					default:
					}
				})
			}
		}

		// operations splitted into different buckets
		switch pcb.op {
		case OpRead:
			// try immediately queue is empty
			if desc.readers.Len() == 0 {
				if w.tryRead(ident, pcb) {
					w.deliver(pcb)
					continue
				}
			}
			// enqueue for poller events
			pcb.l = &desc.readers
			pcb.elem = pcb.l.PushBack(pcb)

			if !desc.r_armed {
				desc.r_armed = true
			}
		case OpWrite:
			if desc.writers.Len() == 0 {
				if w.tryWrite(ident, pcb) {
					w.deliver(pcb)
					continue
				}
			}

			pcb.l = &desc.writers
			pcb.elem = pcb.l.PushBack(pcb)

			if !desc.w_armed {
				desc.w_armed = true
			}
		}

		// try rearm descriptor
		w.pfd.Rearm(ident, desc.r_armed, desc.w_armed)

		// push to heap for timeout operation
		if !pcb.deadline.IsZero() {
			heap.Push(&w.timeouts, pcb)
			if w.timeouts.Len() == 1 {
				w.timer.Reset(time.Until(pcb.deadline))
			}
		}
	}
}

// handle poller events
func (w *watcher) handleEvents(pe pollerEvents) {
	// suppose fd(s) being polled is closed by conn.Close() from outside after chanrecv,
	// and a new conn has re-opened with the same handler number(fd). The read and write
	// on this fd is fatal.
	//
	// Note poller will remove closed fd automatically epoll(7), kqueue(2) and silently.
	// To solve this problem watcher will dup() a new fd from net.Conn, which uniquely
	// identified by 'e.ident', all library operation will be based on 'e.ident',
	// then IO operation is impossible to misread or miswrite on re-created fd.
	//log.Println(e)
	for _, e := range pe {
		if desc, ok := w.descs[e.ident]; ok {
			if e.ev&EV_READ != 0 {
				desc.r_armed = false
				var next *list.Element
				for elem := desc.readers.Front(); elem != nil; elem = next {
					next = elem.Next()
					pcb := elem.Value.(*aiocb)
					if w.tryRead(e.ident, pcb) {
						w.deliver(pcb)
						desc.readers.Remove(elem)
					} else {
						break
					}
				}

				if desc.readers.Len() > 0 {
					desc.r_armed = true
				}
			}

			if e.ev&EV_WRITE != 0 {
				desc.w_armed = false
				var next *list.Element
				for elem := desc.writers.Front(); elem != nil; elem = next {
					next = elem.Next()
					pcb := elem.Value.(*aiocb)
					if w.tryWrite(e.ident, pcb) {
						w.deliver(pcb)
						desc.writers.Remove(elem)
					} else {
						break
					}
				}

				if desc.writers.Len() > 0 {
					desc.w_armed = true
				}
			}

			if desc.r_armed || desc.w_armed {
				w.pfd.Rearm(e.ident, desc.r_armed, desc.w_armed)
			}
		}
	}
}

var gSSLCtx *C.SSL_CTX

func SetGlobalSSLCtx(ctx *C.SSL_CTX) {
	gSSLCtx = ctx
}

func SSLEnvInit() {
	C.C_SSLEnvInit()
}

func NewSSLCTX(caPath string, keyPath string) *C.SSL_CTX {
	// 加载服务端数字证书
	cCAPath := C.CString(caPath)
	defer C.free(unsafe.Pointer(cCAPath))

	// 加载私钥 (PEM格式 )
	cKeyPath := C.CString(keyPath)
	defer C.free(unsafe.Pointer(cKeyPath))

	return C.C_NewSSLCTX(cCAPath, cKeyPath)
}

const (
	SSL_CONN_INIT = iota
	SSL_SHAKE_HAND_BEGIN
	SSL_SHAKE_HAND_END
	SSL_PLAIN_TEXT
)

// 0 成功 但是不一定完全握手结束，-1 失败 需要关闭连接
func SSLHandShake(fd int, desc *fdDesc) C.int {
	iRst := C.C_SSLHandShake(C.int(fd), &desc.sslConnStatus, gSSLCtx, &desc.ssl_)
	return iRst
}

func ifSSLConn(desc *fdDesc) bool {
	if gSSLCtx != nil {
		return true
	}

	return false
}

func CheckSSLCTXADDR(gSSLCtx *C.SSL_CTX) {
	C.C_CheckSSLCTXAddr(gSSLCtx)
}
