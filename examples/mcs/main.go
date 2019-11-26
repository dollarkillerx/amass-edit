/**
 * @Author: DollarKillerX
 * @Description: main.go
 * @Github: https://github.com/dollarkillerx
 * @Date: Create in 上午10:05 2019/11/26
 */
package main

import "sync"

// 域名爆破

type DomainP struct {
	host string

	max chan bool
	mu sync.Mutex

	dir []string
}

//func New(host string,max int) *DomainP {
//	return &DomainP{
//		host:host,
//		max:make(chan bool,max),
//		dir: []string{
//			"www",
//			"",
//			"admin",
//			"mx",
//			""
//		},
//	}
//}

func main() {

}
