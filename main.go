package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

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

func printError(err string) {
	fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
	os.Exit(1)
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
		printError(err.Error())
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
				printError(fmt.Sprintf("listen-addr is not a valid IP address (value = %s)", config.ListenAddr))
			}
		case "listen-port":
			config.ListenPort, err = strconv.Atoi(result.Optarg)
			if err != nil {
				printError("listen-port must be an integer")
			}
			if config.ListenPort < 0 || config.ListenPort > 65535 {
				printError(fmt.Sprintf("invalid value for listen-port (value = %d)", config.ListenPort))
			}
		case "server":
			config.Server = result.Optarg
		case "server-port":
			config.ServerPort, err = strconv.Atoi(result.Optarg)
			if err != nil {
				printError("server-port must be an integer")
			}
			if config.ServerPort < 0 || config.ServerPort > 65535 {
				printError(fmt.Sprintf("invalid value for server-port (value = %d)", config.ServerPort))
			}
		}
	}

	if config.ConfigFile == "" && config.Server == "" {
		printError("config file or server name must be set")
	}

	if config.ConfigFile != "" && config.Server != "" {
		printError("use only configuration file or server address, not both")
	}

	return config
}

// Returns configuration read from TOML file
func loadConfig(pathname string) Config {
	var config Config

	if _, err := os.Stat(pathname); err == nil {
		_, err_config := toml.DecodeFile(pathname, &config)
		if err_config != nil {
			printError(fmt.Sprintf("unable to load config from file '%s' (err = %s)", pathname, err_config.Error()))
		}
	} else if errors.Is(err, os.ErrNotExist) {
		printError(fmt.Sprintf("unknown '%s' file", pathname))
	} else {
		printError(fmt.Sprintf("unable to open file '%s' (err = %s) ", pathname, err.Error()))
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

	fmt.Printf("Received Signal: %s\n", signalReceived.String())
	fmt.Printf("Process exited - PID = %d\n", os.Getpid())
	os.Exit(0)
}

// Process run as daemon
func processDaemon(pathname string, n int) {
	var file *os.File

	if pathname != "" {
		file, _ = os.OpenFile(pathname, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		defer file.Close()
		// Redirect stdout and stderr
		os.Stdout = file
		os.Stderr = file
	} else {
		file = os.Stdout
	}

	file.WriteString(fmt.Sprintf("Process running... - PID = %d\n", os.Getpid()))

	for count := 0; count < n; count++ {
		file.WriteString(fmt.Sprintf("count = %d\n", count))
		time.Sleep(1 * time.Second)
	}

	file.WriteString(fmt.Sprintf("Process exited - PID = %d\n", os.Getpid()))
}

func main() {
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
			printError("log file must be defined")
		}
		// Check write permissions for log file
		f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			printError(fmt.Sprintf("unable to write in log file '%s' (%s)", config.LogFile, err.Error()))
		}
		f.Close()
	} else {
		if config.LogFile != "" {
			// Print logs to Stdout in debug mode
			config.LogFile = ""
			fmt.Println("[INFO] log file not used in debug mode")
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

	fmt.Println("debug", config.Debug)
	fmt.Println("logfile", config.LogFile)
	fmt.Println("conf-file", config.ConfigFile)
	fmt.Println("listen-addr", config.ListenAddr)
	fmt.Println("listen-port", config.ListenPort)
	fmt.Println("server", config.Server)
	fmt.Println("server-port", config.ServerPort)

	if !config.Debug && os.Getenv("IS_DAEMON") != "1" {
		pid, err := Fork()
		if err != nil {
			printError(fmt.Sprintf("unable to fork process - err = %s", err.Error()))
		} else {
			fmt.Printf("Process started with PID %d\n", pid)
		}
		os.Exit(0) // Parent exits
	}

	// Handle SIGINT and SIGTERM signals
	go handleSignals()

	// We're now in the daemonized child process
	processDaemon(config.LogFile, 20)

	os.Exit(0)
}
