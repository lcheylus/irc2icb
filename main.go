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
	"syscall"

	optparse "irc2icb/utils"

	"github.com/BurntSushi/toml"
)

const Version = "devel"

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

// Print logs for level = DEBUG
func logDebug(msg string) {
	log.Printf("[DEBUG] %s", msg)
}

// Print logs for level = INFO
func logInfo(msg string) {
	log.Printf("[INFO] %s", msg)
}

// Print logs for level = ERROR and exit
func logError(msg string) {
	log.Fatalf("[ERROR] %s", msg)
}

// Print usage / help message
func printUsage() {
	fmt.Println("Usage: irc2icb [-h] [-v] [-d] [-f logfile] -c conffile | [-l address] [-p port] -s server [-P port]")
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
		logError(fmt.Sprintf("unable to parse config file - (err = %s)", err.Error()))
	}

	for _, result := range results {
		switch result.Long {
		case "help":
			printUsage()
			os.Exit(0)
		case "version":
			fmt.Println(Version)
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
				logError(fmt.Sprintf("listen-addr is not a valid IP address (value = %s)", config.ListenAddr))
			}
		case "listen-port":
			config.ListenPort, err = strconv.Atoi(result.Optarg)
			if err != nil {
				logError("listen-port must be an integer")
			}
			if config.ListenPort < 0 || config.ListenPort > 65535 {
				logError(fmt.Sprintf("invalid value for listen-port (value = %d)", config.ListenPort))
			}
		case "server":
			config.Server = result.Optarg
		case "server-port":
			config.ServerPort, err = strconv.Atoi(result.Optarg)
			if err != nil {
				logError("server-port must be an integer")
			}
			if config.ServerPort < 0 || config.ServerPort > 65535 {
				logError(fmt.Sprintf("invalid value for server-port (value = %d)", config.ServerPort))
			}
		}
	}

	if config.ConfigFile == "" && config.Server == "" {
		logError("config file or server name must be set")
	}

	if config.ConfigFile != "" && config.Server != "" {
		logError("use only configuration file or server address, not both")
	}

	return config
}

// Returns configuration read from TOML file
func loadConfig(pathname string) Config {
	var config Config

	if _, err := os.Stat(pathname); err == nil {
		_, err_config := toml.DecodeFile(pathname, &config)
		if err_config != nil {
			logError(fmt.Sprintf("unable to load config from file '%s' (err = %s)", pathname, err_config.Error()))
		}
	} else if errors.Is(err, os.ErrNotExist) {
		logError(fmt.Sprintf("unknown '%s' config file", pathname))
	} else {
		logError(fmt.Sprintf("unable to open config file '%s' (err = %s) ", pathname, err.Error()))
	}

	return config
}

// Fork process as daemon, returns new process PID
func Fork() (int, error) {
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

	logInfo(fmt.Sprintf("Received Signal: %s\n", signalReceived.String()))
	logInfo(fmt.Sprintf("Process exited - PID = %d\n", os.Getpid()))
	os.Exit(0)
}

// Handle datas from TCP connection
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Get client address
	clientAddr := conn.RemoteAddr().String()
	logDebug(fmt.Sprintf("Client connected from %s\n", clientAddr))

	// Read from connection
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		msg := scanner.Text()
		logDebug(fmt.Sprintf("Received from %s: %s\n", clientAddr, msg))

		// Echo message back to client
		_, err := conn.Write([]byte("Echo: " + msg + "\n"))
		if err != nil {
			logError(fmt.Sprintf("Error writing to client: %s", err.Error()))
			return
		} else {
			logDebug("Send message back to client")
		}
	}

	logDebug(fmt.Sprintf("Client disconnected: %s\n", clientAddr))
}

// Process run as daemon
func runTCPDaemon(pathname string, addr string, port int) {
	if pathname != "" {
		file, _ := os.OpenFile(pathname, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		defer file.Close()

		log.SetOutput(file)
		log.SetFlags(log.LstdFlags)
	}

	logInfo(fmt.Sprintf("Process running... - PID = %d\n", os.Getpid()))

	// Server listen on TCP
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		logError(fmt.Sprintf("unable to start TCP server - err = %s", err.Error()))
	}
	defer listener.Close()

	logInfo(fmt.Sprintf("TCP server listening on addr %s...\n", fmt.Sprintf("%s:%d", addr, port)))

	for {
		// Accept new connections
		conn, err := listener.Accept()
		if err != nil {
			logError(fmt.Sprintf("Error accepting connection:", err))
			continue
		}
		go handleConnection(conn)
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
			logError("log file must be defined")
		}
		// Check write permissions for log file
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			logError(fmt.Sprintf("unable to write in log file '%s' (%s)", config.LogFile, err.Error()))
		}
		f.Close()
	} else {
		if config.LogFile != "" {
			// Print logs to Stdout in debug mode
			config.LogFile = ""
			logInfo("log file not used in debug mode")
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

	logInfo(fmt.Sprintf("debug %t", config.Debug))
	logInfo(fmt.Sprintf("logfile %s", config.LogFile))
	logInfo(fmt.Sprintf("conf-file %s", config.ConfigFile))
	logInfo(fmt.Sprintf("listen-addr %s", config.ListenAddr))
	logInfo(fmt.Sprintf("listen-port %d", config.ListenPort))
	logInfo(fmt.Sprintf("server %s", config.Server))
	logInfo(fmt.Sprintf("server-port %d", config.ServerPort))

	if !config.Debug && os.Getenv("IS_DAEMON") != "1" {
		pid, err := Fork()
		if err != nil {
			logError(fmt.Sprintf("unable to fork process - err = %s", err.Error()))
		} else {
			logInfo(fmt.Sprintf("Process started with PID %d\n", pid))
		}
		os.Exit(0) // Parent exit
	}

	// Handle SIGINT/SIGTERM signals
	go handleSignals()

	// Run TCP daemon to handle IRC connection
	runTCPDaemon(config.LogFile, config.ListenAddr, config.ListenPort)

	os.Exit(0)
}
