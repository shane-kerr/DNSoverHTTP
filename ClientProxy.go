package main

import (
	"bytes"
	"dns-master"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// flag whether we want to emit debug output
var DEBUG bool = false

// called for debug output
func _D(fmt string, v ...interface{}) {
	if DEBUG {
		log.Printf(fmt, v...)
	}
}

// I am not sure if we can know the request is from UDP or TCP.
// May be we need two proxy to listen TCP and UDP differently since the parameter is different

// Unfortunately neither the dns.ResponseWriter interface nor the dns.Msg structure
// tell us whether a message came in with TCP or UDP. (It is in the dns.response
// structure, but we don't have access to that.)

// There are at least two ways to do this:
//
// 1. We can have two separate ClientProxy structures, and include an "ip_protocol"
//    field in each structure, one with "tcp" and one with "udp".
// 2. We can define a ClientProxyUDP and a ClientProxyTCP structure.
//
// Probably the first is the easiest.

func (this ClientProxy) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	request_bytes, err := request.Pack() //I am not sure it is better to pack directly or using a pointer
	if err != nil {
		SRVFAIL(w, request)
		_D("error in packing request, error message: %s", err)
		return
	}
	postBytesReader := bytes.NewReader(request_bytes)
	req, err := http.NewRequest("POST", this.SERVERS[0], postBytesReader)
	if err != nil {
		SRVFAIL(w, request)
		_D("error in creating HTTP request, error message: %s", err)
		return
	}
	if this.TransPro == UDPcode {
		req.Header.Add("X-Proxy-DNS-Transport", "udp")
	}
	if this.TransPro == TCPcode {
		req.Header.Add("X-Proxy-DNS-Transport", "tcp")
	}
	req.Header.Add("Content-Type", "application/X-DNSoverHTTP")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		SRVFAIL(w, request)
		_D("error in HTTP post request, error message: %s", err)
		return
	}
	var requestBody []byte
	nRead, err := resp.Body.Read(requestBody)
	if err != nil {
		// these need to be separate checks, otherwise you will get a nil-reference
		// when you print the error message below!
		SRVFAIL(w, request)
		_D("error in reading HTTP response, error message: %s", err)
		return
	}
	//I not sure whether I should return server fail directly
	if nRead < (int)(resp.ContentLength) {
		SRVFAIL(w, request)
		_D("fail to read all HTTP content")
		return
	}
	var DNSreponse dns.Msg
	err = DNSreponse.Unpack(requestBody)
	if err != nil {
		SRVFAIL(w, request)
		_D("error in packing HTTP response to DNS, error message: %s", err)
		return
	}
	err = w.WriteMsg(&DNSreponse)
	if err != nil {
		//I don't think we need to call SRVFALL here since we already fail to send response back
		_D("error in sending DNS response back, error message: %s", err)
		return
	}
	// possibly we want to check the return of WriteMsg() and log it if an error happens?
}

func SRVFAIL(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(m)
}

type ClientProxy struct {
	ACCESS      []*net.IPNet
	SERVERS     []string
	s_len       int
	entries     int64
	max_entries int64
	NOW         int64
	giant       *sync.RWMutex
	timeout     time.Duration
	TransPro    int //specify for transmit protocol
}

const UDPcode = 1
const TCPcode = 2

func main() {
	var (
		S_SERVERS       string
		S_LISTEN        string
		S_ACCESS        string
		timeout         int
		max_entries     int64
		expire_interval int64
	)
	flag.StringVar(&S_SERVERS, "proxy", "", "we proxy requests to those servers") //Not sure use IP or URL, default server undefined
	flag.StringVar(&S_LISTEN, "listen", "[::]:53", "listen on (both tcp and udp)")
	flag.StringVar(&S_ACCESS, "access", "127.0.0.0/8,10.0.0.0/8", "allow those networks, use 0.0.0.0/0 to allow everything")
	flag.IntVar(&timeout, "timeout", 5, "timeout")
	flag.Int64Var(&expire_interval, "expire_interval", 300, "delete expired entries every N seconds")
	flag.BoolVar(&DEBUG, "debug", false, "enable/disable debug")
	flag.Int64Var(&max_entries, "max_cache_entries", 2000000, "max cache entries")

	flag.Parse()
	servers := strings.Split(S_SERVERS, ",")
	UDPproxyer := ClientProxy{
		giant:       new(sync.RWMutex),
		ACCESS:      make([]*net.IPNet, 0),
		SERVERS:     servers,
		s_len:       len(servers),
		NOW:         time.Now().UTC().Unix(),
		entries:     0,
		timeout:     time.Duration(timeout) * time.Second,
		max_entries: max_entries,
		TransPro:    UDPcode}
	TCPproxyer := ClientProxy{
		giant:       new(sync.RWMutex),
		ACCESS:      make([]*net.IPNet, 0),
		SERVERS:     servers,
		s_len:       len(servers),
		NOW:         time.Now().UTC().Unix(),
		entries:     0,
		timeout:     time.Duration(timeout) * time.Second,
		max_entries: max_entries,
		TransPro:    TCPcode}
	for _, mask := range strings.Split(S_ACCESS, ",") {
		_, cidr, err := net.ParseCIDR(mask)
		if err != nil {
			panic(err)
		}
		_D("added access for %s\n", mask)
		UDPproxyer.ACCESS = append(UDPproxyer.ACCESS, cidr)
		TCPproxyer.ACCESS = append(TCPproxyer.ACCESS, cidr)
	}
	for _, addr := range strings.Split(S_LISTEN, ",") {
		_D("listening @ %s\n", addr)
		go func() {
			if err := dns.ListenAndServe(addr, "udp", UDPproxyer); err != nil {
				log.Fatal(err)
			}
		}()

		go func() {
			if err := dns.ListenAndServe(addr, "tcp", TCPproxyer); err != nil {
				log.Fatal(err)
			}
		}()
	}
}
