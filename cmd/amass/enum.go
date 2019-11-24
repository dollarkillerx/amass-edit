// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/format"
	"github.com/OWASP/Amass/v3/services"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/fatih/color"
)

const (
	enumUsageMsg = "enum [options] -d DOMAIN"
)

var (
	finished chan struct{}
)

type enumArgs struct {
	Addresses         format.ParseIPs
	ASNs              format.ParseInts
	CIDRs             format.ParseCIDRs
	AltWordList       stringset.Set
	AltWordListMask   stringset.Set
	BruteWordList     stringset.Set
	BruteWordListMask stringset.Set
	Blacklist         stringset.Set
	Domains           stringset.Set
	Excluded          stringset.Set
	Included          stringset.Set
	MaxDNSQueries     int
	MinForRecursive   int
	Names             stringset.Set
	Ports             format.ParseInts
	Resolvers         stringset.Set
	Timeout           int
	Options           struct {
		Active              bool
		BruteForcing        bool
		DemoMode            bool
		IPs                 bool
		IPv4                bool
		IPv6                bool
		ListSources         bool
		MonitorResolverRate bool
		NoAlts              bool
		NoRecursive         bool
		Passive             bool
		PublicDNS           bool
		ScoreResolvers      bool
		Sources             bool
		Unresolved          bool
		Verbose             bool
	}
	Filepaths struct {
		AllFilePrefix string
		AltWordlist   format.ParseStrings
		Blacklist     string
		BruteWordlist format.ParseStrings
		ConfigFile    string
		DataOpts      string
		Directory     string
		Domains       format.ParseStrings
		ExcludedSrcs  string
		IncludedSrcs  string
		JSONOutput    string
		LogFile       string
		Names         format.ParseStrings
		Resolvers     format.ParseStrings
		TermOut       string
	}
}

func defineEnumArgumentFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.Var(&args.Addresses, "addr", "IPs and ranges (192.168.1.1-254) separated by commas")
	enumFlags.Var(&args.AltWordListMask, "awm", "\"hashcat-style\" wordlist masks for name alterations")
	enumFlags.Var(&args.ASNs, "asn", "ASNs separated by commas (can be used multiple times)")
	enumFlags.Var(&args.CIDRs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	enumFlags.Var(&args.Blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	enumFlags.Var(&args.BruteWordListMask, "wm", "\"hashcat-style\" wordlist masks for DNS brute forcing")
	enumFlags.Var(&args.Domains, "d", "Domain names separated by commas (can be used multiple times)")
	enumFlags.Var(&args.Excluded, "exclude", "Data source names separated by commas to be excluded")
	enumFlags.Var(&args.Included, "include", "Data source names separated by commas to be included")
	enumFlags.IntVar(&args.MaxDNSQueries, "max-dns-queries", 0, "Maximum number of concurrent DNS queries")
	enumFlags.IntVar(&args.MinForRecursive, "min-for-recursive", 0, "Number of subdomain discoveries before recursive brute forcing")
	enumFlags.Var(&args.Ports, "p", "Ports separated by commas (default: 443)")
	enumFlags.Var(&args.Resolvers, "r", "IP addresses of preferred DNS resolvers (can be used multiple times)")
	enumFlags.IntVar(&args.Timeout, "timeout", 0, "Number of minutes to let enumeration run before quitting")
}

func defineEnumOptionFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.BoolVar(&args.Options.Active, "active", false, "Attempt zone transfers and certificate name grabs")
	enumFlags.BoolVar(&args.Options.BruteForcing, "brute", false, "Execute brute forcing after searches")
	enumFlags.BoolVar(&args.Options.DemoMode, "demo", false, "Censor output to make it suitable for demonstrations")
	enumFlags.BoolVar(&args.Options.IPs, "ip", false, "Show the IP addresses for discovered names")
	enumFlags.BoolVar(&args.Options.IPv4, "ipv4", false, "Show the IPv4 addresses for discovered names")
	enumFlags.BoolVar(&args.Options.IPv6, "ipv6", false, "Show the IPv6 addresses for discovered names")
	enumFlags.BoolVar(&args.Options.ListSources, "list", false, "Print the names of all available data sources")
	enumFlags.BoolVar(&args.Options.MonitorResolverRate, "noresolvrate", true, "Disable resolver rate monitoring")
	enumFlags.BoolVar(&args.Options.NoAlts, "noalts", false, "Disable generation of altered names")
	enumFlags.BoolVar(&args.Options.NoRecursive, "norecursive", false, "Turn off recursive brute forcing")
	enumFlags.BoolVar(&args.Options.Passive, "passive", false, "Disable DNS resolution of names and dependent features")
	enumFlags.BoolVar(&args.Options.PublicDNS, "public-dns", false, "Use public-dns.info resolver list")
	enumFlags.BoolVar(&args.Options.ScoreResolvers, "noresolvscore", true, "Disable resolver reliability scoring")
	enumFlags.BoolVar(&args.Options.Sources, "src", false, "Print data sources for the discovered names")
	enumFlags.BoolVar(&args.Options.Unresolved, "include-unresolvable", false, "Output DNS names that did not resolve")
	enumFlags.BoolVar(&args.Options.Verbose, "v", false, "Output status / debug / troubleshooting info")
}

func defineEnumFilepathFlags(enumFlags *flag.FlagSet, args *enumArgs) {
	enumFlags.StringVar(&args.Filepaths.AllFilePrefix, "oA", "", "Path prefix used for naming all output files")
	enumFlags.Var(&args.Filepaths.AltWordlist, "aw", "Path to a different wordlist file for alterations")
	enumFlags.StringVar(&args.Filepaths.Blacklist, "blf", "", "Path to a file providing blacklisted subdomains")
	enumFlags.Var(&args.Filepaths.BruteWordlist, "w", "Path to a different wordlist file")
	enumFlags.StringVar(&args.Filepaths.ConfigFile, "config", "", "Path to the INI configuration file. Additional details below")
	enumFlags.StringVar(&args.Filepaths.DataOpts, "do", "", "Path to data operations JSON output file")
	enumFlags.StringVar(&args.Filepaths.Directory, "dir", "", "Path to the directory containing the output files")
	enumFlags.Var(&args.Filepaths.Domains, "df", "Path to a file providing root domain names")
	enumFlags.StringVar(&args.Filepaths.ExcludedSrcs, "ef", "", "Path to a file providing data sources to exclude")
	enumFlags.StringVar(&args.Filepaths.IncludedSrcs, "if", "", "Path to a file providing data sources to include")
	enumFlags.StringVar(&args.Filepaths.JSONOutput, "json", "", "Path to the JSON output file")
	enumFlags.StringVar(&args.Filepaths.LogFile, "log", "", "Path to the log file where errors will be written")
	enumFlags.Var(&args.Filepaths.Names, "nf", "Path to a file providing already known subdomain names (from other tools/sources)")
	enumFlags.Var(&args.Filepaths.Resolvers, "rf", "Path to a file providing preferred DNS resolvers")
	enumFlags.StringVar(&args.Filepaths.TermOut, "o", "", "Path to the text file containing terminal stdout/stderr")
}

func runEnumCommand(clArgs []string) {
	// 定义本模块需要的参数信息   初始化
	args := enumArgs{
		AltWordList:       stringset.New(),
		AltWordListMask:   stringset.New(),
		BruteWordList:     stringset.New(),
		BruteWordListMask: stringset.New(),
		Blacklist:         stringset.New(),
		Domains:           stringset.New(),
		Excluded:          stringset.New(),
		Included:          stringset.New(),
		Names:             stringset.New(),
		Resolvers:         stringset.New(),
	}
	var help1, help2 bool
	enumCommand := flag.NewFlagSet("enum", flag.ContinueOnError)

	enumBuf := new(bytes.Buffer)
	// 输出错误消息到enumBuf
	enumCommand.SetOutput(enumBuf)
	// 再次作了一层的获取
	enumCommand.BoolVar(&help1, "h", false, "Show the program usage message")
	enumCommand.BoolVar(&help2, "help", false, "Show the program usage message")
	// 初始化解析传递不同的区块
	defineEnumArgumentFlags(enumCommand, &args)
	defineEnumOptionFlags(enumCommand, &args)
	defineEnumFilepathFlags(enumCommand, &args)

	if len(clArgs) < 1 {
		commandUsage(enumUsageMsg, enumCommand, enumBuf)
		return
	}

	// 解析用户传递参数
	if err := enumCommand.Parse(clArgs); err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if help1 || help2 {
		commandUsage(enumUsageMsg, enumCommand, enumBuf)
		return
	}

	// Check if the user has requested the data source names
	// 如果你的参数列表存在list 就 打印当前系统所的数据源名称 然后退出服务
	if args.Options.ListSources {
		for _, name := range GetAllSourceNames() {
			g.Println(name)
		}
		return
	}

	// 一些设置 当 mask存在 就 放到与之对应的list中去  为什么要这样作呢?  mask这里什么都没有作啊
	if len(args.AltWordListMask) > 0 {
		args.AltWordList.Union(args.AltWordListMask)
	}
	if len(args.BruteWordListMask) > 0 {
		args.BruteWordList.Union(args.BruteWordListMask)
	}
	// Some input validation
	if args.Options.Passive && (args.Options.IPs || args.Options.IPv4 || args.Options.IPv6) {
		r.Fprintln(color.Error, "IP addresses cannot be provided without DNS resolution")
		os.Exit(1)
	}
	if args.Options.Passive && args.Options.BruteForcing {
		r.Fprintln(color.Error, "Brute forcing cannot be performed without DNS resolution")
		os.Exit(1)
	}
	if (len(args.Excluded) > 0 || args.Filepaths.ExcludedSrcs != "") &&
		(len(args.Included) > 0 || args.Filepaths.IncludedSrcs != "") {
		commandUsage(enumUsageMsg, enumCommand, enumBuf)
		os.Exit(1)
	}

	if err := processEnumInputFiles(&args); err != nil {
		fmt.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}

	// 配置文件读取和一些验证
	cfg := config.NewConfig()
	// Check if a configuration file was provided, and if so, load the settings
	if err := config.AcquireConfig(args.Filepaths.Directory, args.Filepaths.ConfigFile, cfg); err == nil {
		// Check if a config file was provided that has DNS resolvers specified
		if len(cfg.Resolvers) > 0 && len(args.Resolvers) == 0 {
			args.Resolvers = stringset.New(cfg.Resolvers...)
		}
	} else if args.Filepaths.ConfigFile != "" {
		r.Fprintf(color.Error, "Failed to load the configuration file: %v\n", err)
		os.Exit(1)
	}

	// Override configuration file settings with command-line arguments
	if err := cfg.UpdateConfig(args); err != nil {
		r.Fprintf(color.Error, "Configuration error: %v\n", err)
		os.Exit(1)
	}

	rLog, wLog := io.Pipe()
	cfg.Log = log.New(wLog, "", log.Lmicroseconds)
	logfile := filepath.Join(config.OutputDirectory(cfg.Dir), "amass.log")
	if args.Filepaths.LogFile != "" {
		logfile = args.Filepaths.LogFile
	}

	// 创建日志输出文件夹
	createOutputDirectory(cfg)
	go writeLogsAndMessages(rLog, logfile, args.Options.Verbose)

	sys, err := services.NewLocalSystem(cfg)
	if err != nil {
		r.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano()) // 這個扎沒有用呢？
	e := enum.NewEnumeration(sys)
	if e == nil {
		r.Fprintf(color.Error, "%s\n", "No DNS resolvers passed the sanity check")
		os.Exit(1)
	}
	e.Config = cfg

	// 二級
	processEnumOutput(e, &args)
	//graph := sys.GraphDatabases()[0]
	//fmt.Println(graph.DumpGraph())
}

func processEnumOutput(e *enum.Enumeration, args *enumArgs) {
	// 設置文件存放目錄  如果 用戶傳入了就按照用戶傳入的為準
	var err error
	dir := config.OutputDirectory(e.Config.Dir)

	txtfile := filepath.Join(dir, "amass.txt")
	if args.Filepaths.TermOut != "" {
		txtfile = args.Filepaths.TermOut
	}
	jsonfile := filepath.Join(dir, "amass.json")
	if args.Filepaths.JSONOutput != "" {
		jsonfile = args.Filepaths.JSONOutput
	}
	datafile := filepath.Join(dir, "amass_data.json")
	if args.Filepaths.DataOpts != "" {
		datafile = args.Filepaths.DataOpts
	}
	if args.Filepaths.AllFilePrefix != "" {
		txtfile = args.Filepaths.AllFilePrefix + ".txt"
		jsonfile = args.Filepaths.AllFilePrefix + ".json"
		datafile = args.Filepaths.AllFilePrefix + "_data.json"
	}

	if !e.Config.Passive && datafile != "" {
		fileptr, err := os.OpenFile(datafile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the data operations output file: %v\n", err)
			os.Exit(1)
		}
		// 注意這點  這個函數的生命周期是貫穿整個查詢的  當查詢完畢後才會關閉
		defer func() {
			fileptr.Sync()
			fileptr.Close()
		}()
		fileptr.Truncate(0)
		fileptr.Seek(0, 0)
		// 文件句柄放入其中
		e.Config.DataOptsWriter = fileptr
	}

	// 這裡獲得了日誌文件的句柄在下載進行寫入用
	// 在374 進行了輸入操作
	var outptr, jsonptr *os.File
	if txtfile != "" {
		outptr, err = os.OpenFile(txtfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the text output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			outptr.Sync()
			outptr.Close()
		}()
		outptr.Truncate(0)
		outptr.Seek(0, 0)
	}

	// 在378 進行了輸入操作
	var enc *json.Encoder
	if jsonfile != "" {
		jsonptr, err = os.OpenFile(jsonfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the JSON output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			jsonptr.Sync()
			jsonptr.Close()
		}()
		jsonptr.Truncate(0)
		jsonptr.Seek(0, 0)
		enc = json.NewEncoder(jsonptr)
	}

	// Kick off the output management goroutine
	// 程序結束的標識符   程序結束寫入日誌
	finished = make(chan struct{})
	go func() {
		var total int
		tags := make(map[string]int)
		// 網關相關信息
		asns := make(map[int]*format.ASNSummaryData)
		// Collect all the names returned by the enumeration
		// 獲取chan中的消息   這裡注意 這個獲取的是處理好的信息 寫入到文件日誌中  (異步的)
		for out := range e.Output {
			out.Addresses = format.DesiredAddrTypes(out.Addresses, args.Options.IPv4, args.Options.IPv6)
			if !e.Config.Passive && len(out.Addresses) <= 0 {
				continue
			}

			total++
			format.UpdateSummaryData(out, tags, asns)
			source, name, ips := format.OutputLineParts(out, args.Options.Sources,
				args.Options.IPs || args.Options.IPv4 || args.Options.IPv6, args.Options.DemoMode)

			if ips != "" {
				ips = " " + ips
			}

			fmt.Fprintf(color.Output, "%s%s%s\n", blue(source), green(name), yellow(ips))
			// Handle writing the line to a specified output file
			// 這裡發生了txt文件的輸入
			if outptr != nil {
				fmt.Fprintf(outptr, "%s%s%s\n", source, name, ips)
			}
			// Handle encoding the result as JSON
			// 這裡發生json文件的輸入
			if jsonptr != nil {
				enc.Encode(out)
			}
		}
		if total == 0 {
			r.Println("No names were discovered")
		} else {
			// 输出最终信息
			format.PrintEnumerationSummary(total, tags, asns, args.Options.DemoMode)
		}
		// 完成關閉這個
		close(finished)
	}()
	// Start the enumeration process
	// 監聽程序是否被用戶手動中斷  如果中斷 打印相關信息
	go signalHandler(e)
	// 开始枚举查询
	if err := e.Start(); err != nil {
		r.Println(err)
		os.Exit(1)
	}
	// 阻塞
	<-finished
}

// If the user interrupts the program, print the summary information
func signalHandler(e *enum.Enumeration) {
	quit := make(chan os.Signal, 1)

	// 監聽信號  interrupt手動停止中斷   SIGTERM 結束程序
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	// Start final output operations
	e.Done()
	// 接受到終止命令 結束程序
	<-finished
	os.Exit(1)
}

func writeLogsAndMessages(logs *io.PipeReader, logfile string, verbose bool) {
	wildcard := regexp.MustCompile("DNS wildcard")
	avg := regexp.MustCompile("Average DNS queries")
	rScore := regexp.MustCompile("Resolver .* has a low score")
	alterations := regexp.MustCompile("queries for altered names")
	brute := regexp.MustCompile("queries for brute forcing")
	sanity := regexp.MustCompile("SanityChecks")
	queries := regexp.MustCompile("Querying")

	var filePtr *os.File
	if logfile != "" {
		var err error

		filePtr, err = os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the log file: %v\n", err)
		} else {
			defer func() {
				filePtr.Sync()
				filePtr.Close()
			}()
			filePtr.Truncate(0)
			filePtr.Seek(0, 0)
		}
	}

	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(color.Error, "Error reading the Amass logs: %v\n", err)
			break
		}

		if filePtr != nil {
			fmt.Fprintln(filePtr, line)
		}
		// Remove the timestamp
		parts := strings.Split(line, " ")
		line = strings.Join(parts[1:], " ")
		// Check for the Amass average DNS names messages
		if avg.FindString(line) != "" {
			fgY.Fprintln(color.Error, line)
		}
		// Check if a DNS resolver was lost due to its score
		if rScore.FindString(line) != "" {
			fgR.Fprintln(color.Error, line)
		}
		// Let the user know when brute forcing has started
		if brute.FindString(line) != "" {
			fgY.Fprintln(color.Error, line)
		}
		// Let the user know when name alterations have started
		if alterations.FindString(line) != "" {
			fgY.Fprintln(color.Error, line)
		}
		// Check if DNS resolvers have failed the sanity checks
		if verbose && sanity.FindString(line) != "" {
			fgR.Fprintln(color.Error, line)
		}
		// Check for Amass DNS wildcard messages
		if verbose && wildcard.FindString(line) != "" {
			fgR.Fprintln(color.Error, line)
		}
		// Let the user know when data sources are being queried
		if queries.FindString(line) != "" {
			fgY.Fprintln(color.Error, line)
		}
	}
}

// Obtain parameters from provided input files
func processEnumInputFiles(args *enumArgs) error {
	if args.Options.BruteForcing && len(args.Filepaths.BruteWordlist) > 0 {
		for _, f := range args.Filepaths.BruteWordlist {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the brute force wordlist file: %v", err)
			}

			args.BruteWordList.InsertMany(list...)
		}
	}
	if !args.Options.NoAlts && len(args.Filepaths.AltWordlist) > 0 {
		for _, f := range args.Filepaths.AltWordlist {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the alterations wordlist file: %v", err)
			}

			args.AltWordList.InsertMany(list...)
		}
	}
	if args.Filepaths.Blacklist != "" {
		list, err := config.GetListFromFile(args.Filepaths.Blacklist)
		if err != nil {
			return fmt.Errorf("Failed to parse the blacklist file: %v", err)
		}
		args.Blacklist.InsertMany(list...)
	}
	if args.Filepaths.ExcludedSrcs != "" {
		list, err := config.GetListFromFile(args.Filepaths.ExcludedSrcs)
		if err != nil {
			return fmt.Errorf("Failed to parse the exclude file: %v", err)
		}
		args.Excluded.InsertMany(list...)
	}
	if args.Filepaths.IncludedSrcs != "" {
		list, err := config.GetListFromFile(args.Filepaths.IncludedSrcs)
		if err != nil {
			return fmt.Errorf("Failed to parse the include file: %v", err)
		}
		args.Included.InsertMany(list...)
	}
	if len(args.Filepaths.Names) > 0 {
		for _, f := range args.Filepaths.Names {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the subdomain names file: %v", err)
			}

			args.Names.InsertMany(list...)
		}
	}
	if len(args.Filepaths.Domains) > 0 {
		for _, f := range args.Filepaths.Domains {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the domain names file: %v", err)
			}

			args.Domains.InsertMany(list...)
		}
	}
	if len(args.Filepaths.Resolvers) > 0 {
		for _, f := range args.Filepaths.Resolvers {
			list, err := config.GetListFromFile(f)
			if err != nil {
				return fmt.Errorf("Failed to parse the esolver file: %v", err)
			}

			args.Resolvers.InsertMany(list...)
		}
	}
	return nil
}

// Setup the amass enumeration settings
func (e enumArgs) OverrideConfig(conf *config.Config) error {
	if len(e.Addresses) > 0 {
		conf.Addresses = e.Addresses
	}
	if len(e.ASNs) > 0 {
		conf.ASNs = e.ASNs
	}
	if len(e.CIDRs) > 0 {
		conf.CIDRs = e.CIDRs
	}
	if len(e.Ports) > 0 {
		conf.Ports = e.Ports
	}
	if e.Filepaths.Directory != "" {
		conf.Dir = e.Filepaths.Directory
	}
	if e.MaxDNSQueries > 0 {
		conf.MaxDNSQueries = e.MaxDNSQueries
	}
	if len(e.Names) > 0 {
		conf.ProvidedNames = e.Names.Slice()
	}
	if len(e.BruteWordList) > 0 {
		conf.Wordlist = e.BruteWordList.Slice()
	}
	if len(e.AltWordList) > 0 {
		conf.AltWordlist = e.AltWordList.Slice()
	}
	if e.Options.BruteForcing {
		conf.BruteForcing = true
	}
	if e.Options.NoAlts {
		conf.Alterations = false
	}
	if e.Options.NoRecursive {
		conf.Recursive = false
	}
	if e.MinForRecursive > 0 {
		conf.MinForRecursive = e.MinForRecursive
	}
	if e.Options.Active {
		conf.Active = true
	}
	if e.Options.Unresolved {
		conf.IncludeUnresolvable = true
	}
	if e.Options.Passive {
		conf.Passive = true
	}
	if len(e.Blacklist) > 0 {
		conf.Blacklist = e.Blacklist.Slice()
	}
	if e.Timeout > 0 {
		conf.Timeout = e.Timeout
	}

	if e.Options.PublicDNS {
		conf.PublicDNS = true
	}
	if !e.Options.MonitorResolverRate {
		conf.MonitorResolverRate = false
	}
	if !e.Options.ScoreResolvers {
		conf.ScoreResolvers = false
	}

	if len(e.Included) > 0 {
		conf.SourceFilter.Include = true
		conf.SourceFilter.Sources = e.Included.Slice()
	} else if len(e.Excluded) > 0 {
		conf.SourceFilter.Include = false
		conf.SourceFilter.Sources = e.Excluded.Slice()
	}

	// Attempt to add the provided domains to the configuration
	conf.AddDomains(e.Domains.Slice())
	if len(conf.Domains()) == 0 {
		return errors.New("No root domain names were provided")
	}
	return nil
}
