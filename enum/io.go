// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/miekg/dns"
)

// 向以知库中查询       用户第一次查询完毕 会写到图数据库中
func (e *Enumeration) submitKnownNames(wg *sync.WaitGroup) {
	defer wg.Done()
	for _, g := range e.Sys.GraphDatabases() {
		for _, enum := range g.EventList() {
			var found bool
			for _, domain := range g.EventDomains(enum) {

				if e.Config.IsDomainInScope(domain) {
					found = true
					break
				}
			}
			if !found {
				continue
			}

			for _, o := range g.GetOutput(enum) {
				//fmt.Printf("o参数为   %v\n",o)

				if e.Config.IsDomainInScope(o.Name) {
					// 推送到总线上去
					e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
						Name:   o.Name,
						Domain: o.Domain,
						Tag:    requests.EXTERNAL,
						Source: "Previous Enum",
					})
					//fmt.Printf("o参数为   %v\n",o.Name)
				}
			}
		}
	}
}

func (e *Enumeration) submitProvidedNames(wg *sync.WaitGroup) {
	defer wg.Done()

	for _, name := range e.Config.ProvidedNames {
		if domain := e.Config.WhichDomain(name); domain != "" {
			e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    requests.EXTERNAL,
				Source: "User Input",
			})
		}

	}

}

func (e *Enumeration) namesFromCertificates(addr string) {
	for _, name := range http.PullCertificateNames(addr, e.Config.Ports) {
		if n := strings.TrimSpace(name); n != "" {
			if domain := e.Config.WhichDomain(n); domain != "" {
				e.Bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   n,
					Domain: domain,
					Tag:    requests.CERT,
					Source: "Active Cert",
				})
				fmt.Printf("name:%v   ccc", name)
			}
		}
	}
}

// 寫入日誌通道
func (e *Enumeration) processOutput(wg *sync.WaitGroup) {
	fmt.Println("进行了写日志   。。。。。。。。。。。。")
	defer fmt.Println("进行了写日志   。。。。。。。。。。。。 End")
	defer wg.Done()
	// 如果寫入完畢就關閉通道防止死鎖
	defer close(e.Output)

	curIdx := 0
	maxIdx := 6
	delays := []int{25, 50, 75, 100, 150, 250, 500}

	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
			e.outputResolvedNames()
		default:
			// 如果消息队列中为空 就continue
			element, ok := e.outputQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}

			output := element.(*requests.Output)
			if !e.filters.Output.Duplicate(output.Name) {
				e.Output <- output
			}
		}
	}
}

func (e *Enumeration) outputResolvedNames() {
	var failed []*requests.DNSRequest

	// Prepare discovered names for output processing
	for {
		element, ok := e.resolvedQueue.Next()
		if !ok {
			break
		}

		name := element.(*requests.DNSRequest)

		output := e.buildOutput(name)
		if output == nil {
			failed = append(failed, name)
			continue
		}

		e.outputQueue.Append(output)
	}

	// Put failed attempts back on the resolved names queue
	for _, f := range failed {
		e.resolvedQueue.Append(f)
	}
}

func (e *Enumeration) buildOutput(req *requests.DNSRequest) *requests.Output {
	output := &requests.Output{
		Name:   req.Name,
		Domain: req.Domain,
		Tag:    req.Tag,
		Source: req.Source,
	}

	for _, r := range req.Records {
		if t := uint16(r.Type); t != dns.TypeA && t != dns.TypeAAAA {
			continue
		}

		addrInfo := e.buildAddrInfo(strings.TrimSpace(r.Data))
		if addrInfo == nil {
			return nil
		}

		output.Addresses = append(output.Addresses, *addrInfo)
	}

	return output
}

func (e *Enumeration) buildAddrInfo(addr string) *requests.AddressInfo {
	ainfo := &requests.AddressInfo{Address: net.ParseIP(addr)}

	asn := e.ipSearch(addr)
	if asn == nil {
		return nil
	}

	var err error
	ainfo.CIDRStr = asn.Prefix
	_, ainfo.Netblock, err = net.ParseCIDR(asn.Prefix)
	if err != nil || !ainfo.Netblock.Contains(ainfo.Address) {
		return nil
	}

	ainfo.ASN = asn.ASN
	ainfo.Description = asn.Description

	return ainfo
}

func (e *Enumeration) sendOutput(o *requests.Output) {
	select {
	case <-e.done:
		return
	default:
		if e.Config.IsDomainInScope(o.Name) {
			e.outputQueue.Append(o)
		}
	}
}

// 调用此处写日志到打印队列中
func (e *Enumeration) queueLog(msg string) {
	e.logQueue.Append(msg)
}

var ov sync.Once
var file *os.File

// 这里注意  没有查询到打印日志
func (e *Enumeration) writeLogs() {
	ov.Do(func() {
		var i error
		file, i = os.Create("op.log")
		if i != nil {
			panic(i)
		}
	})

	for {
		// 数据
		msg, ok := e.logQueue.Next()
		if !ok {
			break
		}

		fmt.Fprintf(file, "FOC:    %v  >>> \n", msg)

		if e.Config.Log != nil {
			e.Config.Log.Print(msg.(string))
		}
	}

}
