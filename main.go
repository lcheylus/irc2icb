package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	logger "irc2icb/utils"
	utils "irc2icb/utils"
	"irc2icb/version"

	icb "irc2icb/network/icb"
	irc "irc2icb/network/irc"
)

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

	defer irc_conn.Close()

	// Get client address
	clientAddr := irc_conn.RemoteAddr().String()
	logger.LogDebugf("Client connected from %s", clientAddr)

	// Send IRC notification to client
	err := irc.IrcSendNotice(irc_conn, "*** IRC client connected to %s proxy - client addr=%s", version.Name, clientAddr)
	if err != nil {
		logger.LogErrorf("Error writing to client: %s", err.Error())
		return
	} else {
		logger.LogDebug("Send notification to client")
	}

	irc.IrcInit()
	icb.IcbLoggedIn = false
	icb.IcbConnected = true
	icb.IcbInfosForceRefresh = false
	// Create context to close connection with ICB server
	ctx, close_icb_connection := context.WithCancel(context.Background())

	// Read from connection with IRC client
	scanner := bufio.NewScanner(irc_conn)
	for scanner.Scan() && icb.IcbConnected {
		data := scanner.Text()
		logger.LogTracef("Received from client [%s]: %s", clientAddr, data)

		// Handle IRC client commands
		ret, params := irc.IrcCommand(irc_conn, data)
		switch ret {
		case irc.IrcCommandMsg:
			src := params[0]
			content := params[1]
			logger.LogTracef("Received message source = '%s' - content = '%s'", src, content)

			// Message sent to group
			if utils.IsValidIrcChannel(src) {
				group := utils.GroupFromChannel(src)
				logger.LogInfof("Send message in group '%s'", group)

				if icb.IcbGroupCurrent != group {
					irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOSUCHCHANNEL"], "%s :No such channel", src)
				}

				icb.IcbSendOpenmsg(icb_conn, content)
			} else {
				// Case for private message
				logger.LogInfof("Send private message for nick '%s'", src)
				icb.IcbSendPrivatemsg(icb_conn, src, content)
			}

		case irc.IrcCommandPass:
			logger.LogDebugf("password (used for ICB group during login) = '%s'", irc.IrcPassword)

		case irc.IrcCommandNick:
			if !icb.IcbLoggedIn {
				// Connection to ICB server and first login

				// Check if password is defined and valid (parsed from IRC PASS command)
				if len(irc.IrcPassword) == 0 {
					irc.IrcSendRaw(irc_conn, "ERROR :IRC password must be defined for nick "+irc.IrcNick+" (used as group for first ICB login)")
					logger.LogError("IRC password must be defined for nick " + irc.IrcNick)
					break
				}
				irc.IrcNick = params[0]

				icb.IcbGroupCurrent = ""
				icb_conn = icb.IcbConnect(server_addr, server_port)
				defer icb_conn.Close()

				ip := strings.Split(icb_conn.RemoteAddr().String(), ":")[0]
				logger.LogInfof("Connected to server %s (%s) port %d", server_addr, ip, server_port)

				// Start routine to check if initial group is restricted or not
				logger.LogInfo("Start routine to check access for initial group after login")
				icb.IcbChGroupRestricted = make(chan struct{})
				go icb.IcbWaitGroupRestricted(icb_conn, irc_conn, irc.IrcPassword)

				// Start routine to join group after first login
				logger.LogInfo("Start routine to join group after login")
				icb.IcbChFirstJoin = make(chan struct{})
				go icb.IcbJoinAfterLogin(icb_conn, irc_conn)

				// Loop to read ICB packets from server
				logger.LogInfo("Start loop to read packets from server")
				go icb.GetIcbPackets(icb_conn, irc_conn, ctx)

			} else {
				ircCommandChangeNick(irc_conn, icb_conn, params[0])
			}

		case irc.IrcCommandUser:
			logger.LogDebugf("user = %s - realname = '%s'", irc.IrcUser, irc.IrcRealname)

		case irc.IrcCommandJoin:
			ircCommandJoin(irc_conn, icb_conn, params)

		case irc.IrcCommandList:
			ircCommandList(irc_conn, icb_conn, params)

		case irc.IrcCommandNames:
			ircCommandNames(irc_conn, icb_conn, params[0])

		case irc.IrcCommandMode:
			ircCommandMode(irc_conn, icb_conn, params)

		case irc.IrcCommandWho:
			ircCommandWho(irc_conn, icb_conn, params)

		case irc.IrcCommandWhois:
			ircCommandWhois(irc_conn, icb_conn, params[0])

		case irc.IrcCommandTopic:
			ircCommandTopic(irc_conn, icb_conn, params)

		case irc.IrcCommandKick:
			ircCommandKick(irc_conn, icb_conn, params)

		case irc.IrcCommandQuit:
			logger.LogInfof("Client disconnected: %s\n", clientAddr)
			close_icb_connection()

		case irc.IrcCommandPing:
			logger.LogDebugf("Send PONG message")
			irc.IrcSendRaw(irc_conn, "PONG %s", params[0])
			icb.IcbSendNoop(icb_conn)

		case irc.IrcCommandRawIcb:
			logger.LogDebugf("Raw ICB command = '%s'", strings.Join(params, " "))
			icb.IcbSendRaw(icb_conn, strings.Join(params, " "))

		case irc.IrcCommandNop:
		case irc.IrcCommandUnknown:
		default:
		}
	}

	icb.IcbLoggedIn = false
	logger.LogInfof("Disconnected from ICB server => stop to handle IRC commands from client")
	irc.IrcSendNotice(irc_conn, "*** Disconnected from ICB server => proxy stops to reply to IRC commands")
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

		// TODO Send logs via syslog, remove logs file
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

	config := getConfig()

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
