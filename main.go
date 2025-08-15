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
	"unicode"

	logger "irc2icb/utils"
	optparse "irc2icb/utils"
	"irc2icb/version"

	icb "irc2icb/network/icb"
	irc "irc2icb/network/irc"

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

// Check if a string contains only alphanumeric chars
func isAlphanumeric(s string) bool {
	for _, c := range s {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			return false
		}
	}
	return true
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
	var password_invalid bool = false

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
		logger.LogTracef("IRC - Received from client [%s]: %s", clientAddr, data)

		// Handle IRC client commands
		ret, params := irc.IrcCommand(irc_conn, data)
		switch ret {
		case irc.IrcCommandPass:
			logger.LogDebugf("IRC - password = '%s'", irc.IrcPassword)

			// ICB password max length = 12 and contains only alphanumeric chars
			if len(irc.IrcPassword) < 1 || len(irc.IrcPassword) > 12 {
				password_invalid = true
				logger.LogErrorf("IRC - Password '%s' invalid: must be between 1 and 12 chars", irc.IrcPassword)
				irc.IrcSendCode(irc_conn, "Error", irc.IrcReplyCodes["ERR_PASSWDMISMATCH"], ":ICB password must be between 1 and 12 characters.")
			} else if !isAlphanumeric(irc.IrcPassword) {
				password_invalid = true
				logger.LogErrorf("IRC - Password '%s' invalid: must contain only alphanumeric chars", irc.IrcPassword)
				irc.IrcSendCode(irc_conn, "Error", irc.IrcReplyCodes["ERR_PASSWDMISMATCH"], ":ICB password must contain only alphanumeric characters.")
			}
		case irc.IrcCommandNick:
			// Check if password is defined and valid (parsed from IRC PASS command)
			if len(irc.IrcPassword) == 0 {
				irc.IrcSendMsg(irc_conn, "ERROR :ICB password must be defined for nick "+irc.IrcNick)
				logger.LogError("ICB password must be defined for nick " + irc.IrcNick)
				break
			}
			if password_invalid {
				break
			}
			// TODO Handle case if already connected to ICB server => change NICK
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

		case irc.IrcCommandJoin:
			// TODO Handle special case with params == '0' => client leave all channels

			// With ICB protocol, only one current group
			// Format for JOIN paramaters: "<channel>{,<channel>} [<key>{,<key>}]"
			if len(strings.Split(params[0], ",")) > 1 {
				logger.LogErrorf("IRC - Only one unique ICB group for JOIN command - Received '%s'", params[0])
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NEEDMOREPARAMS"], "JOIN :Only one unique ICB group for join")
				break
			}

			var group string
			if !strings.HasPrefix(params[0], "#") {
				logger.LogErrorf("IRC - invalid group '%s' (don't start with #)", params[0])
				break
			} else {
				group = params[0][1:]
			}
			if icb.IcbGroupCurrent == group {
				logger.LogInfof("IRC - JOIN command => already in ICB group '%s'", group)
				irc.IrcSendNotice(irc_conn, "*** :You are already in ICB group %s", group)
				break
			} else {
				logger.LogDebugf("IRC - JOIN command => send ICB command to join group '%s'", group)
				icb.IcbSendGroup(icb_conn, group)
				icb.IcbGroupCurrent = group
			}

			// Get users for current group
			icb_group := icb.IcbGetGroup(group)
			if icb_group == nil {
				logger.LogWarnf("IRC - JOIN command => unable to find current group '%s' in ICB groups list", group)
				logger.LogInfo("IRC - JOIN command => send ICB command to list groups with users")
				icb.IcbQueryGroups(icb_conn)
				icb_group = icb.IcbGetGroup(group)
			}
			logger.LogWarnf("IRC - JOIN command => current ICB group '%s' - users = %q", group, icb_group.Users)

			logger.LogDebugf("IRC - Send replies to JOIN command for group '%s'", group)

			icb_user := icb.IcbGetUser(irc.IrcNick)
			channel := fmt.Sprintf("#%s", group)

			// Send IRC JOIN message with private hostname
			irc.IrcSendJoin(irc_conn, irc.IrcNick, icb_user.Username, icb_user.Hostname, true, channel)

			if icb_group.Topic != "(None)" {
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_TOPIC"], fmt.Sprintf("%s :%s", channel, icb_group.Topic))
			} else {
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NOTOPIC"], fmt.Sprintf("%s :No topic is set", channel))
			}

			// A list of users currently joined to the channel (with one or more RPL_NAMREPLY (353) numerics
			// followed by a single RPL_ENDOFNAMES (366) numeric).
			// These RPL_NAMREPLY messages sent by the server MUST include the requesting client that has just joined the channel.
			// Format for RPL_NAMREPLY message: "<client> <symbol> <channel> :[prefix]<nick>{ [prefix]<nick>}"
			users := icb_group.Users
			if !icb_group.IcbUserInGroup(irc.IrcNick) {
				users = append(users, irc.IrcNick)
			}

			// Get user's operator status from IcbUser object
			var users_with_prefix []string
			var icb_tmp_user *icb.IcbUser
			for _, user := range users {
				icb_tmp_user = icb.IcbGetUser(user)
				users_with_prefix = append(users_with_prefix, irc.IrcGetNickWithPrefix(user, icb_tmp_user.Moderator))
			}

			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NAMREPLY"], fmt.Sprintf("= %s :%s", channel, strings.Join(users_with_prefix, " ")))
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFNAMES"], fmt.Sprintf("%s :End of /NAMES list", channel))

		case irc.IrcCommandList:
			logger.LogInfo("IRC - LIST command => send ICB command to list groups with users")
			icb.IcbQueryGroups(icb_conn)

			// TODO Filter groups with IRC command "LIST" paramaters
			for _, group := range icb.IcbGroups {
				logger.LogDebugf("ICB - [Group] Name = %s - Topic = '%s' - %d users %q", group.Name, group.Topic, len(group.Users), group.Users)
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_LIST"], "#%s %d :%s", group.Name, len(group.Users), group.Topic)
			}
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_LISTEND"], ":End of /LIST")
			logger.LogDebugf("IRC - Send reply to LIST command - nick = %s", irc.IrcNick)

		case irc.IrcCommandQuit:
			logger.LogInfof("IRC - Client disconnected: %s\n", clientAddr)
			close(icb_ch)
		case irc.IrcCommandPing:
			logger.LogDebugf("IRC - Send PONG message")
			irc.IrcSendMsg(irc_conn, "PONG %s", params[0])
			icb.IcbSendNoop(icb_conn)

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

		logger.SetLogLevel(logger.LevelTrace)
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

	// Fork process to run as daemon
	if (config.Verbose == 0) && (os.Getenv("IS_DAEMON") != "1") {
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
