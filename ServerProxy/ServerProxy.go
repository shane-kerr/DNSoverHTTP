package main

import (
	//	"bytes"
	"dns-master"
	"flag"
	"io/ioutil"
	"log"
	"math/rand"
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

type Server struct {
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

//not sure how to make a server fail, error 501?
func SRVFAIL(w http.ResponseWriter, r *http.Request) {

}
func (this Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	TransProString := r.Header.Get("X-Proxy-DNS-Transport")
	if TransProString == "tcp" {
		this.TransPro = TCPcode
	} else if TransProString == "udp" {
		this.TransPro = UDPcode
	} else {
		_D("Transport protol not udp or tcp")
		SRVFAIL(w, r)
		return
	}
	contentTypeStr := r.Header.Get("Content-Type")
	if contentTypeStr != "Content-Type" {
		_D("Content-Type illegal")
		SRVFAIL(w, r)
		return
	}
	var requestBody []byte
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		SRVFAIL(w, r)
		_D("error in reading HTTP response, error message: %s", err)
		return
	}
	if len(requestBody) < (int)(r.ContentLength) {
		SRVFAIL(w, r)
		_D("fail to read all HTTP content")
		return
	}
	var dnsRequest dns.Msg
	err = dnsRequest.Unpack(requestBody)
	if err != nil {
		SRVFAIL(w, r)
		_D("error in packing HTTP response to DNS, error message: %s", err)
		return
	}
	dnsClient := new(dns.Client)
	if dnsClient == nil {
		SRVFAIL(w, r)
		_D("cannot create DNS client")
		return
	}
	dnsClient.ReadTimeout = this.timeout
	dnsClient.WriteTimeout = this.timeout
	dnsClient.Net = TransProString
	//will use a parameter to let user address resolver in future
	dnsResponse, RTT, err := dnsClient.Exchange(&dnsRequest, this.SERVERS[rand.Intn(this.s_len)])
	if err != nil {
		_D("error in communicate with resolver, error message: %s", err)
	} else {
		_D("request took %s", RTT)
	}
	//don't know how to creat a response here
}

func main() {
	var (
		S_SERVERS   string
		timeout     int
		max_entries int64
		ACCESS      string
	)
	flag.StringVar(&S_SERVERS, "proxy", "", "we proxy requests to those servers") //Not sure use IP or URL, default server undefined
	flag.IntVar(&timeout, "timeout", 5, "timeout")
	flag.BoolVar(&DEBUG, "debug", false, "enable/disable debug")
	flag.Int64Var(&max_entries, "max_cache_entries", 2000000, "max cache entries")
	flag.StringVar(&ACCESS, "access", "127.0.0.0/8,10.0.0.0/8", "allow those networks, use 0.0.0.0/0 to allow everything")
	flag.Parse()
	servers := strings.Split(S_SERVERS, ",")
	proxyServer := Server{
		SERVERS:     servers,
		timeout:     time.Duration(timeout) * time.Second,
		max_entries: max_entries,
		ACCESS:      make([]*net.IPNet, 0)}
	for _, mask := range strings.Split(ACCESS, ",") {
		_, cidr, err := net.ParseCIDR(mask)
		if err != nil {
			panic(err)
		}
		_D("added access for %s\n", mask)
		proxyServer.ACCESS = append(proxyServer.ACCESS, cidr)
	}
	_D("start server HTTP")
	err := http.ListenAndServe(":80", proxyServer)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
	for {
		proxyServer.NOW = time.Now().UTC().Unix()
		time.Sleep(time.Duration(1) * time.Second)
	}
}
