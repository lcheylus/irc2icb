package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	logger "irc2icb/utils"
	optparse "irc2icb/utils"

	icb "irc2icb/network/icb"
	irc "irc2icb/network/irc"
	"irc2icb/version"

	"github.com/BurntSushi/toml"
)

// Struct for configuration (set via opt flags or TOML file)
type Config struct {
	Debug      bool
	LogFile    string
	ConfigFile string
	ListenAddr string `toml:"listen-address"`
	ListenPort int    `toml:"listen-port"`
	Server     string `toml:"server"`
	ServerPort int    `toml:"server-port"`
}

// Print usage / help message
func printUsage() {
	fmt.Printf("Usage: %s [-h] [-v] [-d] [-f logfile] -c conffile | [-l address] [-p port] -s server [-P port]\n", version.Name)
	fmt.Println("\nOptions:")
	fmt.Println("  -h, --help\t\t\tShow this help message")
	fmt.Println("  -v, --version\t\t\tShow version")
	fmt.Println("  -d, --debug\t\t\tDo not daemonize (detach from controlling terminal) and produce debugging output on stdout/stderr")
	fmt.Println("  -f, --logfile logfile\t\tFile to write logs")
	fmt.Println("  -c, --conf conffile\t\tConfiguration file (TOML format)")
	fmt.Println("  -l, --listen listen-address\tBind to the specified address when listening for client connections. If not specified, connections to any address are accepted")
	fmt.Println("  -p, --listen-port listen-port\tBind to the specified port when listening for client connections. Defaults to 6667 when not specified")
	fmt.Println("  -s, --server server-name\tHostname or numerical address of the ICB server to connect to")
	fmt.Println("  -P, --server-port server-port\tPort of the ICB server to connect to. Defaults to 7326 when not specified")
}

// Parse command line arguments with optparse package
// Returns configuration
func parseOptions() Config {
	var config Config

	options := []optparse.Option{
		{"help", 'h', optparse.KindNone},
		{"version", 'v', optparse.KindNone},
		{"debug", 'd', optparse.KindNone},
		{"logfile", 'f', optparse.KindRequired},
		{"conf", 'c', optparse.KindRequired},
		{"listen", 'l', optparse.KindRequired},
		{"listen-port", 'p', optparse.KindRequired},
		{"server", 's', optparse.KindRequired},
		{"server-port", 'P', optparse.KindRequired},
	}

	results, _, err := optparse.Parse(options, os.Args)
	if err != nil {
		logger.LogError(err.Error())
		os.Exit(1)
	}

	for _, result := range results {
		switch result.Long {
		case "help":
			printUsage()
			os.Exit(0)
		case "version":
			fmt.Println(version.Version)
			os.Exit(0)
		case "debug":
			config.Debug = true
		case "logfile":
			config.LogFile = result.Optarg
		case "conf":
			config.ConfigFile = result.Optarg
		case "listen":
			config.ListenAddr = result.Optarg
			ip := net.ParseIP(config.ListenAddr)
			if ip == nil {
				logger.LogErrorf("listen-addr is not a valid IP address (value = %s)", config.ListenAddr)
				os.Exit(1)
			}
		case "listen-port":
			config.ListenPort, err = strconv.Atoi(result.Optarg)
			if err != nil {
				logger.LogError("listen-port must be an integer")
				os.Exit(1)
			}
			if config.ListenPort < 0 || config.ListenPort > 65535 {
				logger.LogErrorf("invalid value for listen-port (value = %d)", config.ListenPort)
				os.Exit(1)
			}
		case "server":
			config.Server = result.Optarg
		case "server-port":
			config.ServerPort, err = strconv.Atoi(result.Optarg)
			if err != nil {
				logger.LogError("server-port must be an integer")
				os.Exit(1)
			}
			if config.ServerPort < 0 || config.ServerPort > 65535 {
				logger.LogErrorf("invalid value for server-port (value = %d)", config.ServerPort)
				os.Exit(1)
			}
		}
	}

	if config.ConfigFile == "" && config.Server == "" {
		logger.LogError("config file or server name must be set")
		os.Exit(1)
	}

	if config.ConfigFile != "" && config.Server != "" {
		logger.LogError("use only configuration file or server address, not both")
		os.Exit(1)
	}

	return config
}

// Returns configuration read from TOML file
func loadConfig(pathname string) Config {
	var config Config

	if _, err := os.Stat(pathname); err == nil {
		_, err_config := toml.DecodeFile(pathname, &config)
		if err_config != nil {
			logger.LogFatalf("unable to load config from file '%s' (err = %s)", pathname, err_config.Error())
		}
	} else if errors.Is(err, os.ErrNotExist) {
		logger.LogFatalf("unknown '%s' config file", pathname)
	} else {
		logger.LogFatalf("unable to open config file '%s' (err = %s) ", pathname, err.Error())
	}

	return config
}

// forkProcess process as daemon, returns new process PID
func forkProcess() (int, error) {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	// Add env to run process as daemon
	cmd.Env = append(os.Environ(), "IS_DAEMON=1")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Setsid is used to detach the process from the parent (normally a shell)
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	return cmd.Process.Pid, nil
}

// Handle SIGINT/SIGTERM signals
func handleSignals() {
	sigChannel := make(chan os.Signal, 1)
	signal.Notify(sigChannel, os.Interrupt, syscall.SIGTERM)
	signalReceived := <-sigChannel

	logger.LogInfof("Received Signal: %s", signalReceived.String())

	// TODO send notification to IRC client

	logger.LogInfof("Process exited - PID = %d", os.Getpid())
	os.Exit(0)
}

// Keep this function in main, instead of irc package
// => prevents issue with "Cycle not allowed" between irc and icb packages
//
// Handle datas from TCP connection for IRC client
// Inputs:
// - irc_conn (net.Conn): handle for IRC client connection
// - server_addr (string): address for ICB server
// - server_port (int): port for ICB server
func handleIRCConnection(irc_conn net.Conn, server_addr string, server_port int) {
	var icb_conn net.Conn
	var icb_ch chan struct{}

	defer irc_conn.Close()

	// Get client address
	clientAddr := irc_conn.RemoteAddr().String()
	logger.LogDebugf("IRC - Client connected from %s", clientAddr)

	// Send IRC notification to client
	err := irc.IrcSendNotice(irc_conn, "*** IRC client connected to %s proxy - client addr=%s", version.Name, clientAddr)
	if err != nil {
		logger.LogErrorf("IRC - Error writing to client: %s", err.Error())
		return
	} else {
		logger.LogDebug("IRC - Send notification to client")
	}

	// Read from connection with IRC client
	scanner := bufio.NewScanner(irc_conn)
	for scanner.Scan() {
		data := scanner.Text()
		logger.LogDebugf("IRC - Received from client [%s]: %s", clientAddr, data)

		// Handle IRC client commands
		// ret, params := irc.IrcCommand(conn, data)
		ret, _ := irc.IrcCommand(irc_conn, data)
		switch ret {
		case irc.IrcCommandPass:
			logger.LogDebugf("IRC - password = '%s'", irc.IrcPassword)
		case irc.IrcCommandNick:
			// TODO Handle case if already connected to ICB server
			// Connection to ICB server
			icb_conn = icb.IcbConnect(server_addr, server_port)
			defer icb_conn.Close()

			ip := strings.Split(icb_conn.RemoteAddr().String(), ":")[0]
			logger.LogInfof("ICB - Connected to server %s (%s) port %d", server_addr, ip, server_port)

			// Channel with no type, to close connection to ICB server
			icb_ch = make(chan struct{})

			// Loop to read ICB packets from server
			logger.LogInfo("ICB - Start loop to read packets from server")
			go icb.GetIcbPackets(icb_conn, irc_conn, icb_ch)
		case irc.IrcCommandUser:
			logger.LogDebugf("IRC - user = %s - realname = '%s'", irc.IrcUser, irc.IrcRealname)
		case irc.IrcCommandList:
			// Channel to receive ICB groups list
			icb.IcbGroupsChannel = make(chan []icb.IcbGroup)

			// Send ICB command to list groups
			logger.LogDebugf("IRC - LIST command => send ICB command to list groups")
			icb.IcbSendCommand(icb_conn, "-g")

			// Receive ICB groups list via channel
			icb_groups := <-icb.IcbGroupsChannel
			for _, group := range icb_groups {
				logger.LogDebugf("ICB Group: Name = %s - Topic = '%s'", group.Name, group.Topic)
				// TODO Add count in reply => how many clients are joined to that channel.
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_LIST"], "#%s 42 :%s", group.Name, group.Topic)
			}
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_LISTEND"], ":End of /LIST")
			logger.LogDebugf("IRC - Send reply to LIST command - nick = %s", irc.IrcNick)
		case irc.IrcCommandQuit:
			logger.LogInfof("IRC - Client disconnected: %s\n", clientAddr)
			close(icb_ch)

		case irc.IrcCommandUnknown:
		default:
			/* if err != nil {
				logger.LogErrorf("Error writing to client: %s", err.Error())
				return
			} else {
				logger.LogDebug("Send notification to IRC client")
			} */
		}
	}

}

// Process run as daemon
// Inputs:
// - pathname: path for logs file
// - listen_addr (string): local address for client connection
// - listen_port (int): local port for client connection
// - server_addr (string): address for ICB server
// - server_port (int): port for ICB server
func runIRCDaemon(pathname string, listen_addr string, listen_port int, server_addr string, server_port int) {
	if pathname != "" {
		file, _ := os.OpenFile(pathname, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		defer file.Close()

		log.SetOutput(file)
		log.SetFlags(log.LstdFlags)
		logger.WithoutColors()

		// logger.SetLogLevel(logger.LevelInfo)
	}

	logger.LogInfof("Process running - PID = %d", os.Getpid())

	// Resolve address for TCP listener
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", listen_addr, listen_port))
	if err != nil {
		logger.LogFatalf("unable to resolve TCP address - err = %s", err.Error())
	}

	// Server listen on TCP
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		logger.LogFatalf("unable to start TCP server - err = %s", err.Error())
	}
	defer listener.Close()

	logger.LogInfof("TCP server listening on addr %s", fmt.Sprintf("%s:%d", listen_addr, listen_port))

	for {
		// Accept new connections
		conn, err := listener.Accept()
		if err != nil {
			logger.LogFatalf("Error accepting connection - %s", err.Error())
			continue
		}
		go handleIRCConnection(conn, server_addr, server_port)
	}
}

func main() {
	// No prefix for logs
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	config := parseOptions()

	if config.ConfigFile != "" {
		config_from_file := loadConfig(config.ConfigFile)
		config.Server = config_from_file.Server
		config.ServerPort = config_from_file.ServerPort
		config.ListenAddr = config_from_file.ListenAddr
		config.ListenPort = config_from_file.ListenPort
	}

	if !config.Debug {
		if config.LogFile == "" {
			logger.LogError("log file must be defined")
			os.Exit(1)
		}
		// Check write permissions for log file
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			logger.LogFatalf("unable to write in log file '%s' (%s)", config.LogFile, err.Error())
		}
		f.Close()
	} else {
		if config.LogFile != "" {
			// Print logs to Stdout in debug mode
			config.LogFile = ""
			logger.LogInfo("log file not used in debug mode")
		}
	}

	// Default value listen address
	if config.ListenAddr == "" {
		config.ListenAddr = "localhost"
	}

	// Default value for server port if not defined
	if config.Server != "" && config.ServerPort == 0 {
		config.ServerPort = 7326
	}

	// Default value for listen port if not defined
	if config.ListenPort == 0 {
		config.ListenPort = 6667
	}

	logger.LogInfof("debug %t", config.Debug)
	logger.LogInfof("logfile %s", config.LogFile)
	logger.LogInfof("conf-file %s", config.ConfigFile)
	logger.LogInfof("listen-addr %s", config.ListenAddr)
	logger.LogInfof("listen-port %d", config.ListenPort)
	logger.LogInfof("server %s", config.Server)
	logger.LogInfof("server-port %d", config.ServerPort)

	logger.SetLogLevel(logger.LevelDebug)

	// Fork process to run as daemon
	if !config.Debug && os.Getenv("IS_DAEMON") != "1" {
		pid, err := forkProcess()
		if err != nil {
			logger.LogFatalf("unable to fork process - err = %s", err.Error())
		} else {
			logger.LogInfof("Process started with PID %d\n", pid)
		}
		os.Exit(0) // Parent exit
	}

	log.SetFlags(log.LstdFlags)

	// Handle SIGINT/SIGTERM signals
	go handleSignals()

	// Run TCP daemon to handle IRC connection
	runIRCDaemon(config.LogFile, config.ListenAddr, config.ListenPort, config.Server, config.ServerPort)

	os.Exit(0)
}
