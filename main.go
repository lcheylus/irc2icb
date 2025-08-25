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
	"time"

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
				// Change nick
				nick := params[0]
				if nick == irc.IrcNick {
					irc.IrcSendNotice(irc_conn, "*** :No change, your nick is already %s", nick)
					break
				}
				// Check if param to change nick is valid
				switch icb.IcbValidNickname(nick) {
				case icb.ICB_NICK_TOOLONG:
					irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_ERRONEUSNICKNAME"], "%s :Nickname too long (length = %d)", nick, len(nick))
				case icb.ICB_NICK_INVALID:
					irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_ERRONEUSNICKNAME"], "%s :Erroneus nickname", nick)
				default:
					icb.IcbSendNick(icb_conn, params[0])
				}
			}

		case irc.IrcCommandUser:
			logger.LogDebugf("user = %s - realname = '%s'", irc.IrcUser, irc.IrcRealname)

		case irc.IrcCommandJoin:
			// TODO Handle special case with params == '0' => client leave all channels

			// With ICB protocol, only one current group
			// Format for JOIN paramaters: "<channel>{,<channel>} [<key>{,<key>}]"
			if len(strings.Split(params[0], ",")) > 1 {
				logger.LogErrorf("Only one unique ICB group for JOIN command - Received '%s'", params[0])
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NEEDMOREPARAMS"], "JOIN :Only one unique ICB group for join")
				break
			}

			var group string

			if !utils.IsValidIrcChannel(params[0]) {
				logger.LogErrorf("invalid group '%s' (don't start with #)", params[0])
				irc.IrcSendRaw(irc_conn, "ERROR :Invalid syntax for group '%s' in join (must start with #)", params[0])
				break
			} else {
				group = params[0][1:]
			}

			if icb.IcbGroupCurrent == group {
				logger.LogWarnf("JOIN command => already in ICB group '%s'", group)
				irc.IrcSendNotice(irc_conn, "*** :You are already in ICB group %s", group)
				break
			} else {
				var icb_group *icb.IcbGroup

				// Get users for group
				icb_group = icb.IcbGetGroup(group)
				if icb_group == nil {
					logger.LogWarnf("JOIN command => unable to find current group '%s' in ICB groups list", group)
					logger.LogInfo("JOIN command => send ICB command to list groups and users")

					icb.IcbQueryGroupsUsers(icb_conn, true)

					icb_group = icb.IcbGetGroup(group)
					// Error for unknown group
					if icb_group == nil {
						irc.IrcSendNotice(irc_conn, "*** :Unknown ICB group %s", group)
						break
					}
				}

				// Leave previous group
				if icb.IcbGroupCurrent != "" {
					logger.LogInfof("JOIN command => leave previous channel '%s'", utils.GroupToChannel(icb.IcbGroupCurrent))
					icb_user := icb.IcbGetUser(irc.IrcNick)
					irc.IrcSendPart(irc_conn, irc.IrcNick, icb_user.Username, icb_user.Hostname, utils.GroupToChannel(icb.IcbGroupCurrent))
				}

				logger.LogDebugf("JOIN command => send ICB command to join group '%s'", group)

				// Case when it's not the first login
				if icb.IcbGroupCurrent != "" {
					previous_group := icb.IcbGroupCurrent
					icb.IcbJoinGroup(icb_conn, group)

					// Wait Error packet if group is restricted, with timeout
					select {
					case <-icb.IcbChGroupRestricted:
						logger.LogWarnf("Unable to join group '%s' => restricted", group)
						irc.IrcSendRaw(irc_conn, "ERROR :Access to ICB group %s is restricted", group)
						icb.IcbJoinGroup(icb_conn, previous_group)
						group = previous_group
						irc.IrcSendNotice(irc_conn, "*** :Rejoin previous ICB group %s", group)
					case <-time.After(1 * time.Second):
						logger.LogDebugf("No restriction to join group '%s'", group)
					}

					icb.IcbGroupCurrent = group
					icb.IcbSendIrcJoinReply(irc_conn, group)
				}
			}

		case irc.IrcCommandList:
			ircCommandList(irc_conn, icb_conn, params)

		case irc.IrcCommandNames:
			ircCommandNames(irc_conn, icb_conn, params[0])

		case irc.IrcCommandMode:
			logger.LogInfof("MODE command => parameters = %q", params)
			if !utils.IsValidIrcChannel(params[0]) || utils.GroupFromChannel(params[0]) != icb.IcbGroupCurrent {
				logger.LogDebugf("MODE command not for current ICB group => nothing to do - params = %q", params)
				// TODO Return message for error
				break
			}

			if len(params) == 1 {
				// No need to send IRC reply RPL_CHANNELMODEIS (324)
				// TODO Send ICB command to get users ?
				// see https://github.com/lcheylus/icbirc-portable/blob/5117d377af58aedc94caf89208df477c2aa8a722/src/irc.c#L159
				logger.LogDebugf("MODE command for group '%s' => TODO: get ICB users", params[0])
				break
			}

			// Case for <modestring> defined
			if len(params) > 1 {
				if params[1] != "+o" {
					logger.LogErrorf("MODE command: invalid args '%s'", params[1])
					break
				} else if len(params) < 3 {
					logger.LogError("MODE command: no nick to pass moderation (+o)")
					break
				} else {
					logger.LogDebugf("MODE command to pass moderation to '%s' (TODO)", params[2])
					// TODO Command MODE +o <nick> => pass moderation to nick, send ICB command
					// Check if user exists in ICBUsers
					// icb_send_pass(server_fd, argv[3])
				}
			}

		case irc.IrcCommandWho:
			// In the absence of the <mask> parameter, all visible (users who aren't invisible (user mode +i)
			// and who don't have a common channel with the requesting client) are listed.
			// The same result can be achieved by using a <mask> of "0" or any wildcard which will end up
			// matching every visible user.
			logger.LogInfof("WHO command => params = %q", params)

			if len(params) == 0 || params[0] == "0" {
				logger.LogInfo("WHO command => (TODO) case not handled to list all visible users")
				break
			}

			// mask = channel
			if utils.IsValidIrcChannel(params[0]) {
				logger.LogDebug("WHO command => query groups and users")

				icb.IcbQueryGroupsUsers(icb_conn, false)

				// Check if group exists in ICB groups
				group := utils.GroupFromChannel(params[0])
				icb_group := icb.IcbGetGroup(group)
				if icb_group == nil {
					logger.LogErrorf("WHO command => unknown group '%s'", group)
					irc.IrcSendRaw(irc_conn, "ERROR :Unknown ICB group '%s' for WHO command", group)
					break
				}

				var icb_tmp_user *icb.IcbUser

				for _, user := range icb_group.Users {
					icb_tmp_user = icb.IcbGetUser(user)
					// RPL_WHOREPLY message format = "<client> <channel> <username> <host> <server> <nick> <flags> :<hopcount> <realname>"
					irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_WHOREPLY"], "%s %s %s %s %s H :5 %s",
						utils.GroupToChannel(group), icb_tmp_user.Username, utils.TrimHostname(icb_tmp_user.Hostname), icb.GetIcbHostId(),
						icb_tmp_user.Nick, icb_tmp_user.Username)
				}
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFWHO"], "%s :End of /WHO list", utils.GroupToChannel(group))
				break
			}
			// TODO Case if mask != channel
			logger.LogInfof("WHO command => (TODO) case not handled for mask '%s'", params[0])

		case irc.IrcCommandWhois:
			// This command is used to query information about a particular user.
			// The server SHOULD answer this command with numeric messages with information about the nick.
			logger.LogInfof("WHOIS command => params = %q", params)

			icb.IcbQueryGroupsUsers(icb_conn, false)

			nick := params[0]
			icb_user := icb.IcbGetUser(nick)
			if icb_user == nil {
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOSUCHNICK"], "%s :No such nick", nick)
				break
			}

			// Send replies for WHOIS nick
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_WHOISUSER"], "%s %s %s * :no realname for ICB",
				nick, icb_user.Username, utils.TrimHostname(icb_user.Hostname))
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_WHOISSERVER"], "%s :%s",
				icb.GetIcbHostId(), icb.GetIcbServerId())
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_WHOISIDLE"], "%s %d %d :seconds idle, signon time",
				nick, icb_user.Idle, icb_user.LoginTime.Unix())

			// Get current ICB group for nick
			var current_group string = ""
			for _, group := range icb.IcbGroups {
				if group.IcbUserInGroup(nick) {
					current_group = group.Name
				}
			}

			if current_group != "" {
				var prefix string
				if icb_user.Moderator {
					prefix = "@"
				} else {
					prefix = ""
				}
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_WHOISCHANNELS"], "%s :%s#%s", nick, prefix, current_group)
			}
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFWHOIS"], "%s :End of /WHOIS list", nick)

		case irc.IrcCommandTopic:
			logger.LogInfof("TOPIC command params = %q", params)

			// Get topic for current group => get topic from ICB with topic = ""
			// Reply from parsing Generic command output
			if len(params) == 1 && params[0] == utils.GroupToChannel(icb.IcbGroupCurrent) {
				icb.IcbSendTopic(icb_conn, "")
				break
			}
			// Get topic for another group
			if len(params) == 1 && params[0] != utils.GroupToChannel(icb.IcbGroupCurrent) {
				group := icb.IcbGetGroup(utils.GroupFromChannel(params[0]))
				if group == nil {
					irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOSUCHCHANNEL"], "%s :No such channel", params[0])
					break
				}
				if group.Topic == icb.ICB_TOPICNONE {
					irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NOTOPIC"], "%s :No topic is set", utils.GroupToChannel(group.Name))
					break
				} else {
					irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_TOPIC"], "%s :%s", utils.GroupToChannel(group.Name), group.Topic)
					break
				}
			}

			// Set/delete topic
			if params[0] != utils.GroupToChannel(icb.IcbGroupCurrent) {
				logger.LogWarnf("invalid channel '%s' for TOPIC command", params[0])
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOTONCHANNEL"], "%s :You're not on that channel", params[0])
				break
			}
			if params[1] == "" {
				// Case to "delete" topic for current group
				icb.IcbSendTopic(icb_conn, icb.ICB_TOPICNONE)
			} else {
				icb.IcbSendTopic(icb_conn, params[1])
			}

		case irc.IrcCommandKick:
			// params[0] = channel
			// params[1] = "user *( "," user)"
			logger.LogInfof("KICK command to kick nicks '%s' from channel '%s'", params[1], params[0])
			if len(params) != 2 {
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NEEDMOREPARAMS"], "%s :Invalid KICK command, needs more parameters", params[0])
				break
			}
			if params[0] != utils.GroupToChannel(icb.IcbGroupCurrent) {
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOTONCHANNEL"], "%s :You're not on that channel", params[0])
				break
			}
			users := strings.Split(params[1], ",")
			for _, user := range users {
				group := icb.IcbGetGroup(utils.GroupFromChannel(params[0]))
				if !group.IcbUserInGroup(user) {
					logger.LogDebugf("KICK command nick '%s' => not in channel '%s'", user, params[0])
					irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOTONCHANNEL"], "%s :%s isn't on that channel", params[0], user)
				} else {
					logger.LogDebugf("KICK command to kick nick '%s' from channel '%s'", user, params[0])
					// If not moderator, error ERR_CHANOPRIVSNEEDED sent via ICB Error parsing
					icb.IcbSendBoot(icb_conn, user)
				}
			}

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
