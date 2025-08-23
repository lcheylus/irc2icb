// Package for ICB protocol

package icb

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	irc "irc2icb/network/irc"
	logger "irc2icb/utils"
	utils "irc2icb/utils"
	"irc2icb/version"
)

// Type for ICB message
// Defined as map to get names programmatically
var icbPacketType = map[string]byte{
	"PKT_LOGIN":     'a', // login packet
	"PKT_LOGINOK":   'a', // login OK packet from server
	"PKT_OPEN":      'b', // open msg to group
	"PKT_PERSONAL":  'c', // personal msg
	"PKT_STATUS":    'd', // status update message
	"PKT_ERROR":     'e', // error message
	"PKT_IMPORTANT": 'f', // special important announcement
	"PKT_EXIT":      'g', // tell other side to exit
	"PKT_COMMAND":   'h', // send a command from user
	"PKT_CMDOUT":    'i', // output from a command
	"PKT_PROTO":     'j', // protocol version information
	"PKT_BEEP":      'k', // beep packet
	"PKT_PING":      'l', // ping packet
	"PKT_PONG":      'm', // return for ping packet
	"PKT_NOOP":      'n', // no-op packet
}

// Enum with ICB mode to reply to IRC commands
const (
	IcbModeNone = iota
	IcbModeList
	IcbModeNames
	IcbModeWhois
	IcbModeWho
)

const (
	ICB_JOIN      string = "You are now in group " // ICB Status message when joining a group
	ICB_TOPIC     string = "The topic is: "        // ICB Command generic output to get group's topic
	ICB_NOTOPIC   string = "The topic is not set." // ICB Command generic output when group's topic not set
	ICB_TOPICNONE string = "(None)"                // ICB topic when undefined

	ICB_NOTMODERATOR  string = "You aren't the moderator"      // ICB Error when user isn't moderator for the current group
	ICB_GROUPRESTRICT string = "is restricted."                // ICB Error when group is restricted '<group> is restricted.'
	ICB_SAMEGROUP     string = "You are already in that group" // ICB Error when joining same group

	MAX_PKT_LENGTH   int = 256                                 // Max length for ICB packet (including first by for length)
	MAX_NICKLEN      int = 12                                  // Max length for ICB nick
	MAX_INPUT_LENGTH int = 250 - MAX_NICKLEN - MAX_NICKLEN - 6 // Max length for a line in Open/Personal message
)

// Type to handle variable parsed from ICB Protocol packet
type icbProtocolInfos struct {
	ProtocolLevel int
	HostId        string
	ServerId      string
}

// Variables for ICB connection
var (
	IcbLoggedIn  bool = false       // ICB logged in status
	IcbConnected bool = false       // Status for connection to ICB server
	IcbMode      int  = IcbModeNone // ICB mode to reply to IRC commands

	icbProtocolInfo icbProtocolInfos // Infos for ICB server

	IcbChFirstJoin       chan struct{} // Signal to join first ICB group
	IcbChGroupRestricted chan struct{} // Signal when joined group is restricted
)

// Return HostId from Protocol infos for ICB server
func GetIcbHostId() string {
	return icbProtocolInfo.HostId
}

// Return ServerId from Protocol infos for ICB server
func GetIcbServerId() string {
	return icbProtocolInfo.ServerId
}

// icbPacket represents a parsed ICB packet
type icbPacket struct {
	Type byte
	Data string
}

// Get ICB packet type (PKT_xxx)
// Input: value (byte) for type
// Output: type (PKT_xxx)
func getIcbPacketType(val byte) string {
	for name := range icbPacketType {
		if icbPacketType[name] == val {
			return name
		}
	}

	logger.LogErrorf("ICB - getIcbPacketType: unable to get type for value '%s'", val)
	return ""
}

// Loop to read packets from ICB server, called as goroutine
// Inputs:
// - icb_conn (net.Conn): handle for connection to ICB server
// - irc_conn (net.Conn): handle for connection to IRC client
// - ctx (content.Context): context to check if connection to ICB server is closed
// TODO return code for errors
// TODO Add SetReadDeadline for conn and check time-out
func GetIcbPackets(icb_conn net.Conn, irc_conn net.Conn, ctx context.Context) {
	reader := bufio.NewReader(icb_conn)

	for {
		select {
		case <-ctx.Done():
			// conn.Close called from main via defer
			logger.LogInfof("ICB - Close connection to server %s", icb_conn.RemoteAddr().String())
			goto End
		default:
			logger.LogTracef("ICB - [GetIcbPackets] packet received from ICB server")
			packet, err := parseIcbPacket(reader)
			if err != nil {
				if err == io.EOF {
					// TODO Handle reconnection to ICB server
					logger.LogInfo("ICB - connection closed by ICB server")
					IcbConnected = false
					goto End
				} else {
					// TODO Handle read error from ICB server
					logger.LogErrorf("ICB - Read error from ICB server - %s", err.Error())
					break
				}
			}

			if len(packet.Data) > 1 {
				fields := getIcbPacketFields(packet.Data)
				logger.LogTracef("ICB - ICB message fields = %q", fields)
			}

			// TODO check errors
			icbHandleType(icb_conn, *packet, irc_conn)
		}
	}

End:
	logger.LogInfo("ICB - Stop to read ICB packets from server")
	return
}

// parseIcbPacket parses raw ICB datas received from server
// and converts into an icbPacket struct
//
// The basic unit ICB clients and server communicate with is a packet with the following layout: LTd
// - "L" is the length of the packet in bytes. "L" is a single byte, thus the packet length is limited to 0 to 255 bytes.
// It does not include the L byte, but does include the Packet Type byte.
// The protocol (and the chime server) does not require the data in the packet to be null-terminated,
// but some older (poorly implemented) clients and servers do. If you *do* send the null, you must include it in your length byte.
// Proposed extension: if L is 0, the packet is part of an extended packet. The packet should be treated as if L was 255 and the next packet received from the sender should be appended to this packet.
// - "T" is the ICB type that the packet is to classified as. It is a single byte.
// - "d" is the data contained in the packet. It can contain any valid ASCII data, and can be up to 253 bytes in length if you null-terminate (as recommended above), or 254 bytes in length if not.
func parseIcbPacket(reader *bufio.Reader) (*icbPacket, error) {
	// Read the length byte
	lengthByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	// Length must be at least 1 (to contain the type byte)
	length := int(lengthByte)
	if length < 1 || length > MAX_PKT_LENGTH {
		return nil, fmt.Errorf("invalid packet length: %d", length)
	}

	// Read the type byte
	typeByte, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	// Read the remaining data
	data := make([]byte, length-1)
	_, err = io.ReadFull(reader, data)
	if err != nil {
		return nil, err
	}

	logger.LogTracef("ICB - Received ICB packet: Type=%s, Data=%q (len = %d)", getIcbPacketType(typeByte), data, int(lengthByte)-1)

	// Return data as string, without null char
	// data_trim := strings.Trim(string(data), "\x00")
	return &icbPacket{
		Type: typeByte,
		Data: strings.Trim(string(data), "\x00"),
	}, nil
}

// Get fields from ICB packet datas
// The fields are data separated by ASCII ^A (\001)
//
// Input: raw (string): datas read from ICB server
// Return []string with fields splitted by separator
func getIcbPacketFields(raw string) []string {
	return strings.Split(raw, "\x01")
}

// Parse ICB Generic Command Output (type = 'co')
// Inputs:
// - data (string): data parsed from ICB Generic Command Output
// - irc_conn (net.Conn): connection to IRC client
func parseIcbGenericCommandOutput(data string, irc_conn net.Conn) {
	if strings.HasPrefix(data, "Group:") {
		// Sample of data for 'Group' output
		// Group: zenomt   (rvl) Mod: zenomt        Topic: (None)
		fields := strings.Fields(data)
		if len(fields) < 2 {
			logger.LogWarn("ICB - invalid number of fields for 'Group'")
		}
		logger.LogDebugf("ICB - [Group] fields = %s", fields)

		group := &IcbGroup{}
		group.Name = fields[1]
		for i, v := range fields {
			if v == "Topic:" {
				// TODO check if not null-terminated string in Join
				group.Topic = strings.Join(fields[i+1:], " ")
			}
		}
		if group.Topic == "" {
			logger.LogWarnf("ICB - unable to find topic for group '%s'", group.Name)
		}
		logger.LogDebugf("ICB - [Group] Name = %s", group.Name)
		logger.LogDebugf("ICB - [Group] Topic = '%s'", group.Topic)

		// Check if group already present in IcbGroups list
		if !icbGroupIsPresent(group) {
			icbAddGroup(group)
			logger.LogDebugf("ICB - Add group '%s' to list of groups", group.Name)
		}

		// Current name of group parsed from ICB datas
		// Used to add in it after parsing users from ICB datas
		icbGroupReceivedCurrent = group.Name

	} else if strings.HasPrefix(data, "Total:") {
		// Output for 'Total:'
		fields := strings.Fields(data)
		// TODO check if not null-terminated string in Join
		logger.LogDebugf("ICB - [Total] %s", strings.Join(fields[1:], " "))

		// TODO Parse content ("57 users in 9 groups")
		// and check values for users and groups

		if IcbMode == IcbModeList {
			// Send signal for completion of ICB command to get groups
			chGroupsReceived <- struct{}{}
		} else if IcbMode == IcbModeNames {
			// Send signal for completion of ICB command to get groups with users
			chUsersReceived <- struct{}{}
		} else {
			logger.LogError("ICB - Output 'Total' received but not in mode for LIST or NAMES")
		}
		IcbMode = IcbModeNone

	} else {
		// Generic command output
		logger.LogTracef("ICB - [Generic] '%s'", data)

		// Case to get topic for current group with no topic defined
		if len(data) != 0 && data == ICB_NOTOPIC {
			logger.LogDebug("ICB - No topic set for current group")
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NOTOPIC"], "%s :No topic is set", utils.GroupToChannel(IcbGroupCurrent))
			return
		}
		// Case to get topic for current group with topic defined
		if len(data) != 0 && strings.HasPrefix(data, ICB_TOPIC) {
			topic := data[len(ICB_TOPIC):]
			logger.LogDebugf("ICB - Get topic for current group = '%s'", topic)
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_TOPIC"], "%s :%s", utils.GroupToChannel(IcbGroupCurrent), topic)
			return
		}

		// Send datas to IRC client via notification
		if len(data) != 0 && data != " " {
			err := irc.IrcSendNotice(irc_conn, "*** :%s", data)
			if err != nil {
				logger.LogErrorf("ICB - Error to send IRC notice message to client - %s", err.Error())
				return
			} else {
				logger.LogDebug("ICB - Send IRC notice message for Generic Command output")
			}
		}
	}
}

// Parse Command outputs (ICB packet type = 'c')
// Inputs:
// - fields ([]string): fields from ICB Generic Command Output
// - irc_conn (net.Conn): connection to IRC client
func parseIcbCommandOutput(fields []string, irc_conn net.Conn) error {
	// Required
	if len(fields) == 0 {
		return fmt.Errorf("invalid Command Output - no type defined")
	}

	switch string(fields[0]) {
	// Generic command output
	case "co":
		parseIcbGenericCommandOutput(fields[1], irc_conn)
	// Indicates end of output data from command
	case "ec":
		logger.LogDebugf("ICB - [End of output data from command] %s", fields[1])
	// In a who listing, a line of output listing a user
	case "wl":
		logger.LogDebugf("ICB - [User] fields = %q", fields[1:])
		user, _ := icbParseUser(fields[1:])
		user.icbPrintUser()

		// Check if group already present in IcbGroups list
		if !icbUserIsPresent(user) {
			icbAddUser(user)
			logger.LogDebugf("ICB - Add user for nick '%s' to list of users", user.Nick)
		}

	// In a who listing, a line of output listing a group
	case "wg":
		group_name := fields[1]
		group_topic := fields[2]
		logger.LogDebugf("ICB - [Group] name = '%s' - topic = '%s'", group_name, group_topic)
	case "wh":
		logger.LogWarn("ICB - [deprecated] header for who listing output")
	case "gh":
		logger.LogWarn("ICB - [deprecated] group header for who listing output")
	case "ch":
		logger.LogWarn("ICB - [deprecated] list all the commands client handles internally")
	case "c":
		logger.LogWarn("ICB - [deprecated] list a single command")
	default:
		logger.LogWarnf("ICB - Unknown Command output '%s'", fields[0])
	}

	return nil
}

// Parse Status Message (ICB packet type = 'd')
// Inputs:
// - category (string): category for the message
// - content (string): content of the message
// - icb_conn (net.Conn): connection to ICB server
// - irc_conn (net.Conn): connection to IRC client
func parseIcbStatus(category string, content string, icb_conn net.Conn, irc_conn net.Conn) error {
	if len(category) == 0 {
		return fmt.Errorf("invalid Status message - no category defined")
	}

	// TODO Parse Status Message: Pass
	// Register - content = 'Nick registered'
	switch category {
	case "Status":
		if !strings.HasPrefix(content, ICB_JOIN) {
			irc.IrcSendNotice(irc_conn, "*** :ICB Status Message: %s", content)
		} else {
			IcbLoggedIn = true
			group := content[len(ICB_JOIN):]

			// First login => send signal to get ICB groups/users and send IRC replies
			if IcbGroupCurrent == "" {
				logger.LogInfof("ICB - No current group - Join group '%s'", group)
				IcbChFirstJoin <- struct{}{}
				IcbGroupCurrent = group
			}

			logger.LogInfof("ICB - Current group = '%s'", group)
			irc.IrcSendNotice(irc_conn, "*** :ICB Status Message: %s", content)
		}
		return nil
	case "Arrive", "Sign-on":
		// content = 'FoxySend (foxsend@host) entered group'
		re, _ := regexp.Compile(`^(.+) \((.+)@(.+)\) entered group$`)
		matches := re.FindStringSubmatch(content)
		if matches == nil {
			logger.LogErrorf("ICB - Status %s: unable to find infos 'nick (user@host)' in content '%s'", category, content)
		} else {
			logger.LogTracef("ICB - User entered group '%s' - nick = '%s' user = '%s' host = '%s'", IcbGroupCurrent, matches[1], matches[2], matches[3])
			irc.IrcSendJoin(irc_conn, matches[1], matches[2], matches[3], utils.GroupToChannel(IcbGroupCurrent))
		}
	case "Depart":
		// content = 'FoxySend (foxsend@host) just left'
		re, _ := regexp.Compile(`^(.+) \((.+)@(.+)\) just left$`)
		matches := re.FindStringSubmatch(content)
		if matches == nil {
			logger.LogErrorf("ICB - Status %s: unable to find infos 'nick (user@host)' in content '%s'", category, content)
		} else {
			logger.LogTracef("ICB - User left group '%s' - nick = '%s' user = '%s' host = '%s'", IcbGroupCurrent, matches[1], matches[2], matches[3])
			irc.IrcSendPart(irc_conn, matches[1], matches[2], matches[3], utils.GroupToChannel(IcbGroupCurrent))
		}
	case "Sign-off":
		// content = 'FoxySend (foxsend@host) has signed off.'
		re, _ := regexp.Compile(`^(.+) \((.+)@(.+)\) (.+)$`)
		matches := re.FindStringSubmatch(content)
		if matches == nil {
			logger.LogErrorf("ICB - Status %s: unable to find infos 'nick (user@host)' in content '%s'", category, content)
		} else {
			logger.LogTracef("ICB - User disconnected from server - nick = '%s' user = '%s' host = '%s'", matches[1], matches[2], matches[3])

			var reason string
			if strings.HasSuffix(matches[4], ".") {
				reason = matches[4][:len(matches[4])-1]
			} else {
				reason = matches[4]
			}
			irc.IrcSendRaw(irc_conn, ":%s!%s@%s QUIT :%s", matches[1], matches[2], matches[3], reason)
		}
	case "Name":
		// content = 'Foxy changed nickname to FoxyNew'
		re, _ := regexp.Compile(`^(.+) changed nickname to (.+)$`)
		matches := re.FindStringSubmatch(content)
		if matches == nil {
			logger.LogErrorf("ICB - Status %s: unable to find infos for nick/new nick in content '%s'", category, content)
		} else {
			irc.IrcNick = matches[2]
			irc.IrcSendRaw(irc_conn, ":%s NICK %s", matches[1], matches[2])
		}

	case "Topic":
		// content = 'Foxy changed the topic to "*slump*"'
		re, _ := regexp.Compile(`^(.+) changed the topic to "(.+)"$`)
		matches := re.FindStringSubmatch(content)
		if matches == nil {
			logger.LogErrorf("ICB - Status %s: unable to find infos for nick/topic in content '%s'", category, content)
		} else {
			logger.LogDebugf("ICB - User changed topic for current group - nick = '%s' topic = '%s'", matches[1], matches[2])
			if matches[2] != ICB_TOPICNONE {
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_TOPIC"], "%s :%s", utils.GroupToChannel(IcbGroupCurrent), matches[2])
			} else {
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NOTOPIC"], "%s :No topic is set", utils.GroupToChannel(IcbGroupCurrent))
			}
		}
	case "Boot":
		// content = '<user> was booted.'
		nick := strings.Split(content, " ")[0]
		moderator := IcbGetGroup(IcbGroupCurrent).icbGetGroupModerator()
		if moderator != "" {
			// Send KICK reply to group's moderator
			irc.IrcSendRaw(irc_conn, ":%s KICK %s %s :booted", moderator, utils.GroupToChannel(IcbGroupCurrent), nick)
		} else {
			irc.IrcSendNotice(irc_conn, "*** :%s was kicked from %s channel", nick, utils.GroupToChannel(IcbGroupCurrent))
		}
		return nil

	case "Server":
		irc.IrcSendNotice(irc_conn, "*** :ICB Message from Server: %s", content)
		return nil
	case "No-Pass":
		irc.IrcSendNotice(irc_conn, "*** :ICB Status Message: %s", content)
		return nil
	case "Timeout":
		irc.IrcSendNotice(irc_conn, "*** :ICB Status Message: %s", content)
		return nil
	case "Idle-Mod":
		irc.IrcSendNotice(irc_conn, "*** :ICB Status Message: %s", content)
		return nil
	default:
		logger.LogWarnf("ICB - Unknown Status message category '%s'", category)
	}

	return nil
}

// Handle ICB packet according to type
// Inputs:
// - icb_conn (net.Conn): handle for connection to ICB server
// - packet (icbPacket): ICB packet received
// - irc_conn (net.Conn): handle for connection to IRC client
func icbHandleType(icb_conn net.Conn, packet icbPacket, irc_conn net.Conn) error {
	switch packet.Type {
	// Login
	case icbPacketType["PKT_LOGINOK"]:
		logger.LogDebug("ICB - Received Login OK packet from server")

		// Send codes to complete IRC client registration
		logger.LogDebug("ICB - Send messages to IRC client for registration")
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_WELCOME"], ":Welcome to %s proxy %s", version.Name, irc.IrcNick)

		// Your host is default.icb.net running ICB Server v1.2c protocol 1
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_YOURHOST"], ":Your host is %s running %s protocol %d", icbProtocolInfo.HostId, icbProtocolInfo.ServerId, icbProtocolInfo.ProtocolLevel)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_CREATED"], ":This server was created recently")
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MYINFO"], "localhost %s-%s", version.Name, version.Version)

		// Send reply to advertise Support with prefix
		// Message format: "<client> <1-13 tokens> :are supported by this server"
		// TODO Send other parameters according to
		// https://defs.ircdocs.horse/defs/isupport.html (NETWORK, CHANTYPES)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ISUPPORT"], "PREFIX=(ov)@+ :are supported by this server")

		// Send MOTD (message of the day)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTDSTART"], ":- %s Message of the day - ", "localhost")
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTD"], ":- Proxy for IRC client to ICB network")
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTD"], ":- Proxy using %s software, version %s", version.Name, version.Version)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTD"], ":- Repository: https://github.com/lcheylus/irc2icb/")
		// ICB server: ICB Server v1.2c
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTD"], ":- ICB server: %s", icbProtocolInfo.ServerId)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFMOTD"], ":End of MOTD command")

	// Open Message
	case icbPacketType["PKT_OPEN"]:
		logger.LogDebug("ICB - Received Open Message")
		fields := getIcbPacketFields(packet.Data)
		nickname := fields[0]
		content := fields[1]
		logger.LogTracef("ICB - Received Open Message packet - nickname = %s - content = '%s'", nickname, content)

		logger.LogInfof("ICB - Send message from nickname = %s", nickname)
		irc.IrcSendMsg(irc_conn, nickname, utils.GroupToChannel(IcbGroupCurrent), content)

	// Personal Message
	case icbPacketType["PKT_PERSONAL"]:
		logger.LogDebug("Received ICB Personal Message")
		fields := getIcbPacketFields(packet.Data)
		nickname := fields[0]
		content := fields[1]
		logger.LogTracef("ICB - Received Personal Message packet - nickname = %s - content = '%s'", nickname, content)

		logger.LogInfof("ICB - Send message from nickname = %s", nickname)
		irc.IrcSendMsg(irc_conn, nickname, irc.IrcNick, content)

	// Status Message
	case icbPacketType["PKT_STATUS"]:
		fields := getIcbPacketFields(packet.Data)
		category := fields[0]
		content := fields[1]
		logger.LogTracef("ICB - Received Status Message packet - category = %s - content = '%s'", category, content)
		err := parseIcbStatus(category, content, icb_conn, irc_conn)
		if err != nil {
			logger.LogErrorf("ICB - invalid Status Message packet - err = %s", err.Error())
		}
	// Error Message
	case icbPacketType["PKT_ERROR"]:
		fields := getIcbPacketFields(packet.Data)
		logger.LogErrorf("ICB - Received Error Message packet - err = '%s'", fields[0])

		if strings.HasPrefix(fields[0], ICB_NOTMODERATOR) {
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_CHANOPRIVSNEEDED"], "%s :You're not channel operator", IcbGroupCurrent)
		} else if strings.HasSuffix(fields[0], ICB_GROUPRESTRICT) {
			logger.LogDebug("ICB - Group restricted => send signal")
			IcbChGroupRestricted <- struct{}{}
		} else if !strings.HasPrefix(fields[0], ICB_SAMEGROUP) {
			irc.IrcSendRaw(irc_conn, "ERROR :ICB Error Message: %s", fields[0])
		}

		// TODO Handle case if ICB connection not closed/reset
		// => ICB Error "Nickname already in use." with reconnection

	// Important Message
	// Example: category = Mod - content = 'You are still mod of group couch'
	case icbPacketType["PKT_IMPORTANT"]:
		fields := getIcbPacketFields(packet.Data)
		category := fields[0]
		content := fields[1]
		logger.LogTracef("ICB - Received Important Message packet - category = %s - content = '%s'", category, content)
		irc.IrcSendNotice(irc_conn, "*** :ICB Important Message: %s - %s", category, content)
	// Exit
	case icbPacketType["PKT_EXIT"]:
		logger.LogDebug("ICB - Received Exit packet")
		IcbLoggedIn = false
		IcbConnected = false
	// Command Output
	case icbPacketType["PKT_CMDOUT"]:
		logger.LogDebug("ICB - Received Command Output packet")
		fields := getIcbPacketFields(packet.Data)
		err := parseIcbCommandOutput(fields, irc_conn)
		if err != nil {
			logger.LogErrorf("ICB - invalid Command Output packet - err = '%s'", err.Error())
		}
	// Protocol
	case icbPacketType["PKT_PROTO"]:
		logger.LogDebug("ICB - Received Protocol packet")
		fields := getIcbPacketFields(packet.Data)
		if len(fields) == 0 {
			return fmt.Errorf("PKT_PROTO message: no protocol level (required)")
		}
		// Protocol Level is int - Required
		protocol_level, err := strconv.Atoi(fields[0])
		if err != nil {
			return fmt.Errorf("PKT_PROTO message: protocol level is not int - value = '%s'", fields[0])
		}
		icbProtocolInfo.ProtocolLevel = protocol_level
		// Host ID optional
		if len(fields) > 1 {
			icbProtocolInfo.HostId = fields[1]
		} else {
			icbProtocolInfo.HostId = "none"
		}
		// Server ID optional
		if len(fields) > 2 {
			icbProtocolInfo.ServerId = fields[2]
		} else {
			icbProtocolInfo.ServerId = "none"
		}

		logger.LogDebugf("ICB - ICB protocol level = %d", icbProtocolInfo.ProtocolLevel)
		logger.LogDebugf("ICB - ICB Host ID = %s", icbProtocolInfo.HostId)
		logger.LogDebugf("ICB - ICB Server ID = %s", icbProtocolInfo.ServerId)

		// IRC password is used to set default group for login
		icbSendLogin(icb_conn, irc.IrcNick, irc.IrcPassword, irc.IrcUser)

	// Beep
	case icbPacketType["PKT_BEEP"]:
		fields := getIcbPacketFields(packet.Data)
		nick := fields[0]
		logger.LogTracef("ICB - Received Beep packet - nick = %s", nick)
		irc.IrcSendNotice(irc_conn, "*** :ICB Beep from %s", nick)
	// Ping from server
	case icbPacketType["PKT_PING"]:
		logger.LogDebug("ICB - Received PING packet")
		fields := getIcbPacketFields(packet.Data)
		if len(fields) > 1 {
			logger.LogWarnf("ICB - Invalid PING fields: %d received (max = 1) - fields = %q", len(fields), fields)
		}
		if len(fields) <= 1 {
			irc.IrcSendNotice(irc_conn, "*** :ICB Ping - fields = %q", fields)
		}
	// Pong from server
	case icbPacketType["PKT_PONG"]:
		logger.LogDebug("ICB - Received PONG packet")
		fields := getIcbPacketFields(packet.Data)
		if len(fields) > 1 {
			logger.LogWarnf("ICB - Invalid PONG fields: %d received (max = 1) - fields = %q", len(fields), fields)
		}
		if len(fields) <= 1 {
			irc.IrcSendNotice(irc_conn, "*** :ICB Pong - fields = %q", fields)
		}
	default:
		logger.LogWarnf("ICB - Unknown command type '%s'", string(packet.Type))
	}

	return nil
}

// After ICB Login OK, wait message to check is initial group is restricted
func IcbWaitGroupRestricted(icb_conn net.Conn, irc_conn net.Conn, group string) {
	for {
		select {
		case <-IcbChGroupRestricted:
			logger.LogWarnf("ICB - Unable to join group '%s' => restricted", group)
			irc.IrcSendRaw(irc_conn, "ERROR :Access to ICB group %s is restricted", group)
			IcbConnected = false
			return

		default:
			if IcbLoggedIn {
				logger.LogDebugf("ICB - No restriction to join group '%s'", group)
				logger.LogInfof("ICB - Logged to server for nick %s in group '%s'", irc.IrcNick, group)
				return
			}
		}
	}
}

// Wait ICB Login OK to send IRC replies to join group
func IcbJoinAfterLogin(icb_conn net.Conn, irc_conn net.Conn) {
	for {
		select {
		case <-IcbChFirstJoin:
			logger.LogInfo("ICB - Received signal to join ICB group after login => query groups/users")
			IcbQueryWho(icb_conn, true)

			logger.LogInfof("IRC - Send replies to JOIN group '%s'", IcbGroupCurrent)
			IcbSendIrcJoinReply(irc_conn, IcbGroupCurrent)

			close(IcbChFirstJoin)
			return
		default:
		}
	}
}

// Send IRC JOIN replies after joining an ICB group
func IcbSendIrcJoinReply(irc_conn net.Conn, group string) {
	icb_group := IcbGetGroup(group)
	logger.LogDebugf("IRC - Send replies to JOIN group '%s' - users = %q", group, icb_group.Users)

	icb_user := IcbGetUser(irc.IrcNick)

	irc.IrcSendJoin(irc_conn, irc.IrcNick, icb_user.Username, icb_user.Hostname, utils.GroupToChannel(group))

	if icb_group.Topic != ICB_TOPICNONE {
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_TOPIC"], "%s :%s", utils.GroupToChannel(group), icb_group.Topic)
	} else {
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NOTOPIC"], "%s :No topic is set", utils.GroupToChannel(group))
	}

	// A list of users currently joined to the channel (with one or more RPL_NAMREPLY (353) numerics
	// followed by a single RPL_ENDOFNAMES (366) numeric).
	// These RPL_NAMREPLY messages sent by the server MUST include the requesting client that has just joined the channel.
	// Format for RPL_NAMREPLY message: "<client> <symbol> <channel> :[prefix]<nick>{ [prefix]<nick>}"
	users := icb_group.Users
	if !icb_group.IcbUserInGroup(irc.IrcNick) {
		users = append(users, irc.IrcNick)
	}

	var icb_tmp_user *IcbUser
	var users_with_prefix []string

	// Send RPL_WHOREPLY codes for each user in group
	for _, user := range users {
		icb_tmp_user = IcbGetUser(user)
		users_with_prefix = append(users_with_prefix, irc.IrcGetNickWithPrefix(user, icb_tmp_user.Moderator))

		// RPL_WHOREPLY message format = "<client> <channel> <username> <host> <server> <nick> <flags> :<hopcount> <realname>"
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_WHOREPLY"], "%s %s %s %s %s H :5 %s",
			utils.GroupToChannel(group), icb_tmp_user.Username, icb_tmp_user.Hostname, GetIcbHostId(),
			icb_tmp_user.Nick, icb_tmp_user.Username)
	}
	// Sort list of users by moderator status
	sort.SliceStable(users_with_prefix, func(i, j int) bool {
		return utils.CompareUser(users_with_prefix[i], users_with_prefix[j])
	})

	irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NAMREPLY"], "= %s :%s", utils.GroupToChannel(group), strings.Join(users_with_prefix, " "))

	irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFNAMES"], "%s :End of /NAMES list", utils.GroupToChannel(group))
	irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFWHO"], "%s :End of /WHO list", utils.GroupToChannel(group))
}

// Add packet's length as prefix (necessary for ICB packet with format 'Ltd')
func preprendPacketLength(packet []byte) []byte {
	if len(packet) > MAX_PKT_LENGTH-1 {
		logger.LogErrorf("ICB - invalid length packet to add prefix - length=%d", len(packet))
	}

	packet = append(packet, 0)
	copy(packet[1:], packet)
	// Packet length does not include L byte
	packet[0] = byte(len(packet) - 1)

	return packet
}

// Send ICB command for open message (to a channel/group)
func IcbSendOpenmsg(conn net.Conn, input string) error {
	// Translate message to standard ASCII
	ascii_msg := utils.TransliterateUnicodeToASCII(input)

	// Split input in n strings with length < MAX_INPUT_LENGTH
	msgs := utils.SplitString(ascii_msg, MAX_INPUT_LENGTH)

	for _, msg := range msgs {
		// TODO Check error
		icbSendSingleOpenmsg(conn, msg)
	}

	return nil
}

// Send single ICB Open message, length of input message must be < MAX_INPUT_SIZE
func icbSendSingleOpenmsg(conn net.Conn, msg string) error {
	logger.LogInfo("ICB - Send command for Open Message packet")

	// TODO Check max size for msg and return error if too long
	// MAX_SIZE_MSG = 246

	packet := []byte{icbPacketType["PKT_OPEN"]}
	packet = append(packet, []byte(msg)...)
	packet = preprendPacketLength(packet)

	logger.LogTracef("ICB - Open Message packet msg = '%s' - packet = %v - length = %d", msg, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Open Message packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebug("ICB - Send Open Message packet to server")
	}

	return err
}

// Send ICB command for personal message (private)
// Inputs:
// - conn (net.Conn): connection to ICB server
// - nick (string): nickname for destination
// - msg (string): content of the message
func IcbSendPrivatemsg(conn net.Conn, nick string, input string) error {
	// Translate message to standard ASCII
	ascii_msg := utils.TransliterateUnicodeToASCII(input)

	// Split input in n strings with length < MAX_INPUT_LENGTH
	msgs := utils.SplitString(ascii_msg, MAX_INPUT_LENGTH)

	for _, msg := range msgs {
		// TODO Check error
		icbSendSinglePrivatemsg(conn, nick, msg)
	}

	return nil
}

// Send ICB command for personal message (private)
// Inputs:
// - conn (net.Conn): connection to ICB server
// - nick (string): nickname for destination
// - msg (string): content of the message, length < MAX_INPUT_SIZE
func icbSendSinglePrivatemsg(conn net.Conn, nick string, msg string) error {
	logger.LogInfo("ICB - Send command for Personal Message packet")

	// TODO Check max size for msg and return error if too long
	// MAX_SIZE_MSG = 246

	packet := []byte(fmt.Sprintf("%cm\001%s ", icbPacketType["PKT_COMMAND"], nick))
	packet = append(packet, []byte(msg)...)
	packet = preprendPacketLength(packet)

	logger.LogTracef("ICB - Personal Message packet msg = '%s' - packet = %v - length = %d", msg, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Personal Message packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebug("ICB - Send Personal Message packet to server")
	}

	return err
}

// Send ICB "login" packet
// Inputs:
// - conn (net.Conn): connection to ICB server
// - nick (string): nickname for login
// - group (string): default group to join
// - username (string): username for login
// No password sent to ICB server for login
//
// Format for login packet (client to server)
// Packet Type: 'a' (Login)
// Fields: Minimum: 5, Maximum: 7
//
//	Field 0: Login id of user. Required.
//	Field 1: Nickname to use upon login into ICB. Required.
//	Field 2: Default group to log into in ICB, or do group who of. A null string for who listing will show all groups. Required.
//	Field 3: Login command. Required. Currently one of the following:
//	  "login" log into ICB
//	  "w" just show who is currently logged into ICB
//	Field 4: Password to authenticate the user to ICB. Required, but often blank.
//	Field 5: If when logging in, default group (field 2) does not exist, create it with this status. Optional.
//	Field 6: Protocol level. Optional. Deprecated.
//
// Thus the ICB Login Packet has the following layout:
// aLoginid^ANickname^ADefaultGroup^ACommand^APassword^AGroupStatus^AProtocolLevel
func icbSendLogin(conn net.Conn, nick string, group string, username string) error {
	const login_cmd = "login"

	// No password => sent blank
	packet := []byte(fmt.Sprintf("%c%s\001%s\001%s\001%s\001%s", icbPacketType["PKT_LOGIN"], username, nick, group, login_cmd, ""))

	// Add packet length as prefix
	if len(packet) > MAX_PKT_LENGTH {
		logger.LogDebugf("ICB - invalid Login packet for nick = %s - length = %d > 255", nick, packet, len(packet)-1)
	}
	packet = preprendPacketLength(packet)

	logger.LogTracef("ICB - Login packet for nick = %s - packet = %v - length = %d", nick, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Login packet for nick = %s", nick)
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Login packet to server - nick = %s", nick)
	}

	return err
}

// Send ICB command to get groups
func IcbSendList(conn net.Conn) error {
	if IcbMode != IcbModeNone {
		return nil
	}

	logger.LogInfo("ICB - Send command to get groups")
	IcbMode = IcbModeList
	err := IcbSendCommand(conn, "-g")

	return err
}

// Send ICB command to get users
func IcbSendNames(conn net.Conn) error {
	if IcbMode != IcbModeNone {
		return nil
	}

	logger.LogInfo("ICB - Send command to get users")
	IcbMode = IcbModeNames
	err := IcbSendCommand(conn, "")

	return err
}

// Send ICB command to join group
func IcbJoinGroup(conn net.Conn, group string) error {
	logger.LogInfof("ICB - Send command to join group '%s'", group)

	packet := []byte(fmt.Sprintf("%cg\001%s", icbPacketType["PKT_COMMAND"], group))
	packet = preprendPacketLength(packet)

	logger.LogTracef("ICB - Command packet group = '%s' - packet = %v - length = %d", group, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Command packet to join group '%s'", group)
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebug("ICB - Send Command packet (join group) to server")
	}

	return err
}

// Send ICB Command packet
func IcbSendCommand(conn net.Conn, args string) error {
	// TODO Send args as slice of bytes instead of string ?
	packet := []byte(fmt.Sprintf("%cw\001%s", icbPacketType["PKT_COMMAND"], args))
	packet = preprendPacketLength(packet)

	logger.LogTracef("ICB - Command packet args = '%s' - packet = %v - length = %d", args, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Command packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Command packet to server")
	}

	return err
}

// Send ICB Command packet to set/get group topic
// If input topic = "", get current topic
// Otherwise, set topic for current group ; topic = "(None)" for undefined
func IcbSendTopic(conn net.Conn, topic string) error {
	const topic_cmd = "topic"

	packet := []byte(fmt.Sprintf("%c%s\001%s", icbPacketType["PKT_COMMAND"], topic_cmd, topic))
	packet = preprendPacketLength(packet)

	// TODO Check packet size < max packet length (255)

	logger.LogTracef("ICB - Command packet to set topic - packet = %v - length = %d", packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Command packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Command packet to server")
	}

	return err
}

// Send ICB Command packet to boot (kick) a user from current group
func IcbSendBoot(conn net.Conn, user string) error {
	const boot_cmd = "boot"

	packet := []byte(fmt.Sprintf("%c%s\001%s", icbPacketType["PKT_COMMAND"], boot_cmd, user))
	packet = preprendPacketLength(packet)

	// TODO Check packet size < max packet length (255)

	logger.LogTracef("ICB - Command packet to boot user from current group - packet = %v - length = %d", packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Command packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Command packet to server")
	}

	return err
}

// Send ICB Command packet to change nick
func IcbSendNick(conn net.Conn, nick string) error {
	const nick_cmd = "name"

	packet := []byte(fmt.Sprintf("%c%s\001%s", icbPacketType["PKT_COMMAND"], nick_cmd, nick))
	packet = preprendPacketLength(packet)

	// TODO Check packet size < max packet length (255)

	logger.LogTracef("ICB - Command packet to change nick - packet = %v - length = %d", packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Command packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Command packet to server")
	}

	return err
}

// Send ICB No-op packet
func IcbSendNoop(conn net.Conn) error {
	packet := []byte{icbPacketType["PKT_NOOP"]}
	packet = preprendPacketLength(packet)

	logger.LogTracef("ICB - No-op packet - packet = %v - length = %d", packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending No-op packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send No-op packet to server")
	}

	return err
}

// Send ICB Ping packet
func icbSendPing(conn net.Conn) error {
	packet := []byte{icbPacketType["PKT_PING"]}
	packet = preprendPacketLength(packet)

	logger.LogTracef("ICB - Ping packet - packet = %v - length = %d", packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Ping packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Ping packet to server")
	}

	return err
}

// Send ICB raw command
// Inputs:
// - conn (net.Conn): connection to ICB server
// - msg (string): raw message to send, ',' char replaced par ICB separator '\001'
// Example: 'hm,nick,msg' => send Personal message to nick
func IcbSendRaw(conn net.Conn, msg string) error {
	logger.LogInfo("ICB - Send ICB raw packet")

	// TODO Check max size for msg and return error if too long
	// MAX_SIZE_MSG = 246

	var packet []byte
	for _, c := range []byte(msg) {
		if c == ',' {
			packet = append(packet, '\001')
		} else {
			packet = append(packet, c)
		}
	}
	packet = append(packet, '\x00')
	packet = preprendPacketLength(packet)

	logger.LogTracef("ICB - Raw packet msg = '%s' - packet = %v - length = %d", msg, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Raw packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebug("ICB - Send Raw packet")
	}

	return err
}

// TCP connection to ICB server
// Inputs:
// - server (string); address for ICB server
// - port (int): port for ICB server
// - irc_conn (net.Conn): handle for connection to IRC client
func IcbConnect(server string, port int) net.Conn {
	addr := fmt.Sprintf("%s:%d", server, port)

	logger.LogDebugf("ICB - Trying to connect to ICB server [%s]", addr)

	// Connect to the server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		logger.LogErrorf("ICB - Unable to connect to ICB server [%s]: err = %s", addr, err.Error())
		return nil
	}

	return conn
}
