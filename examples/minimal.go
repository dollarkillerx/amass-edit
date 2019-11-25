package main

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/services"
)

func main() {
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	// 进行了网络请求  本查询耗时3s    初始化dns解析pool等基础服务
	sys, err := services.NewLocalSystem(config.NewConfig())
	if err != nil {
		return
	}

	e := enum.NewEnumeration(sys)
	if e == nil {
		return
	}

	go func() {
		// e.Output 日志text
		for result := range e.Output {
			fmt.Println(result.Name)
		}
	}()


	// Setup the most basic amass configuration
	e.Config.AddDomain("dollarkiller.com")
	/**
	 * AddDomain 做了两件事 配置来e.config 的 c.regexps  c.domains
	 */

	fmt.Println("start app")
	e.Start()
}
