/**
 * @Author: DollarKillerX
 * @Description: alienvault.go
 * @Github: https://github.com/dollarkillerx
 * @Date: Create in 下午5:37 2019/11/25
 */
package main

import (
	"context"
	"github.com/OWASP/Amass/v3/requests"
	"log"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/services"
)

func main() {
	sys, err := services.NewLocalSystem(config.NewConfig())
	if err != nil {
		log.Fatalln(err)
	}

	//for _, src := range services.GetAllSources(sys) {
	//	names = append(names, src.String())
	//}
	vault := services.NewAlienVault(sys)
	err = vault.Start()
	if err != nil {
		log.Fatalln(err)
	}

	err = vault.OnStart()
	if err != nil {
		log.Fatalln(err)
	}
	domain := &requests.DNSRequest{Name:"dollarkiller.com",Domain:"dollarkiller.com"}
	vault.OnDNSRequest(context.TODO(),domain)
}
