package testcase

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"sync"
	"testing"
)

func queueLog(msg string) {
	log.Println(msg)
}

func tc(fn interface{}) {
	if reflect.TypeOf(fn).Kind() != reflect.Func {
		log.Println("is not func")
	}

	of := reflect.ValueOf(fn)
	log.Println(of)
}

func TestTC(t *testing.T) {
	tc(queueLog)
}

func TestLogF(t *testing.T) {
	file, e := os.OpenFile("test.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 00666)
	if e != nil {
		panic(e)
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			// 打印到文件
			fmt.Fprintf(file, "file log: %d\n", i)
		}
	}()

	wg.Wait()
}

func fib(n int64) int64 {
	if n <= 2 {
		return 1
	}
	return fib(n-1) + fib(n-2)
}

func TestBc(t *testing.T) {
	fmt.Println(fib(45))
}
