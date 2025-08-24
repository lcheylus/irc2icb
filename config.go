// Parse options from command line and load configuration from TOML file

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	logger "irc2icb/utils"
	optparse "irc2icb/utils"
	"irc2icb/version"

	"github.com/BurntSushi/toml"
)

// Struct for configuration (set via opt flags or TOML file)
type Config struct {
	Verbose    int
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
	fmt.Println("  -V, --version\t\t\tShow version")
	fmt.Println("  -v\t\t\t\tDo not daemonize (detach from controlling terminal) and produce debugging output on stdout/stderr. Repeat to increase logs level (Info, Debug, Trace)")
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
		{"version", 'V', optparse.KindNone},
		{"", 'v', optparse.KindNone},
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
		switch result.Short {
		case 'h':
			printUsage()
			os.Exit(0)
		case 'V':
			fmt.Println(version.Version)
			os.Exit(0)
		case 'v':
			config.Verbose++
		case 'f':
			config.LogFile = result.Optarg
		case 'c':
			config.ConfigFile = result.Optarg
		case 'l':
			config.ListenAddr = result.Optarg
			ip := net.ParseIP(config.ListenAddr)
			if ip == nil {
				logger.LogErrorf("listen-addr is not a valid IP address (value = %s)", config.ListenAddr)
				os.Exit(1)
			}
		case 'p':
			config.ListenPort, err = strconv.Atoi(result.Optarg)
			if err != nil {
				logger.LogError("listen-port must be an integer")
				os.Exit(1)
			}
			if config.ListenPort < 0 || config.ListenPort > 65535 {
				logger.LogErrorf("invalid value for listen-port (value = %d)", config.ListenPort)
				os.Exit(1)
			}
		case 's':
			config.Server = result.Optarg
		case 'P':
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

// Get configuration from command-line or from TOML file
func getConfig() Config {
	config := parseOptions()

	if config.ConfigFile != "" {
		config_from_file := loadConfig(config.ConfigFile)
		config.Server = config_from_file.Server
		config.ServerPort = config_from_file.ServerPort
		config.ListenAddr = config_from_file.ListenAddr
		config.ListenPort = config_from_file.ListenPort
	}

	if config.Verbose == 0 {
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
		if config.Verbose > 3 {
			config.Verbose = 3
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

	logger.LogInfof("logfile = %s", config.LogFile)
	logger.LogInfof("conf-file = %s", config.ConfigFile)
	logger.LogInfof("listen-addr = %s", config.ListenAddr)
	logger.LogInfof("listen-port = %d", config.ListenPort)
	logger.LogInfof("server = %s", config.Server)
	logger.LogInfof("server-port = %d", config.ServerPort)

	switch config.Verbose {
	case 1:
		logger.SetLogLevel(logger.LevelInfo)
		logger.LogInfo("logs level = INFO")
	case 2:
		logger.SetLogLevel(logger.LevelDebug)
		logger.LogInfo("logs level = DEBUG")
	case 3:
		logger.SetLogLevel(logger.LevelTrace)
		logger.LogInfo("logs level = TRACE")
	default:
		logger.SetLogLevel(logger.LevelInfo)
		logger.LogInfo("logs level = INFO")
	}

	return config
}
