// Package for ICB protocol

package icb

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	irc "irc2icb/network/irc"
	logger "irc2icb/utils"
	"irc2icb/version"
)

// Type for ICB message
// Defined as map to get names programmatically
var icbPacketType = map[string]string{
	"M_LOGIN":     "a", // login packet
	"M_LOGINOK":   "a", // login OK packet from server
	"M_OPEN":      "b", // open msg to group
	"M_PERSONAL":  "c", // personal msg
	"M_STATUS":    "d", // status update message
	"M_ERROR":     "e", // error message
	"M_IMPORTANT": "f", // special important announcement
	"M_EXIT":      "g", // tell other side to exit
	"M_COMMAND":   "h", // send a command from user
	"M_CMDOUT":    "i", // output from a command
	"M_PROTO":     "j", // protocol version information
	"M_BEEP":      "k", // beep packet
	"M_PING":      "l", // ping packet
	"M_PONG":      "m", // return for ping packet
	"M_NOOP":      "n", // no-op packet
}

// Type to handle variable parsed from ICB Protocol packet
type icbProtocolInfos struct {
	ProtocolLevel int
	HostId        string
	ServerId      string
}

// Variables for ICB connection
var (
	IcbLoggedIn      bool          // ICB logged in status
	IcbGroups        []IcbGroup    // List of ICB groups
	IcbGroupsChannel chan struct{} // Channel to signal that groups list is populated

	icbProtocolInfo icbProtocolInfos
)

// Get ICB packet type (M_xxx)
// Input: value (string with 1 byte) for type
// Output: type (M_xxx)
func getIcbPacketType(val string) string {
	for name := range icbPacketType {
		if icbPacketType[name] == val {
			return name
		}
	}

	logger.LogWarnf("ICB - getIcbPacketType: unable to get type for value '%s'", val)
	return ""
}

// icbPacket represents a parsed ICB packet
type icbPacket struct {
	Type byte
	Data []byte
}

// icbUser represents a ICB User (datas parsed for Command packet, type='wl')
type icbUser struct {
	Moderator bool
	Nick      string
	Idle      int
	LoginTime time.Time // Unix time_t format - Seconds since Jan. 1, 1970 GMT
	Username  string
	Hostname  string
	RegStatus string
}

// IcbGroup represents a ICB Group (datas parsed for Command packet, type='co'
// with header 'Group:')
type IcbGroup struct {
	Name  string
	Topic string
}

// Loop to read packets from ICB server, called as goroutine
// Inputs:
// - icb_conn (net.Conn): handle for connection to ICB server
// - irc_conn (net.Conn): handle for connection to IRC client
// - icb_closed (chan bool): channel to close connection to ICB server
// TODO return code for errors
func GetIcbPackets(icb_conn net.Conn, irc_conn net.Conn, icb_close chan struct{}) {
	reader := bufio.NewReader(icb_conn)

	for {
		select {
		case <-icb_close:
			// conn.Close called from main via defer
			logger.LogInfof("ICB - Close connection to server %s", icb_conn.RemoteAddr().String())
			goto End
		default:
			msg, err := parseIcbPacket(reader)
			if err != nil {
				if err == io.EOF {
					// TODO Handle reconnection to ICB server
					logger.LogInfo("ICB - connection closed by ICB server")
					goto End
				} else {
					// TODO Handle read error from ICB server
					logger.LogErrorf("ICB - Read error from ICB server - %s", err.Error())
					break
				}
			}

			logger.LogDebugf("ICB - Received ICB Message: Type=%s, Data='%s' (len = %d)", getIcbPacketType(string(msg.Type)), string(msg.Data), len(msg.Data))
			if len(msg.Data) > 1 {
				fields := getIcbPacketFields(msg.Data)
				logger.LogDebugf("ICB - ICB message fields = %s", strings.Join(fields, ","))
			}

			// TODO check errors
			icbHandleType(icb_conn, *msg, irc_conn)
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
	if length < 1 || length > 255 {
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

	return &icbPacket{
		Type: typeByte,
		Data: data,
	}, nil
}

// Utility function to remove last char from string if == '\x00'
// Prevent to get null-terminated string from data
func getIcbString(input string) string {
	return strings.TrimSuffix(input, "\x00")
}

// Get fields from ICB packet datas
// The fields are data separated by ASCII ^A (\001).
// If a field is optional, it (and any fields after it) can merely be left out of the packet.
func getIcbPacketFields(raw []byte) []string {
	fields := strings.Split(string(raw), "\001")
	return fields
}

// Check if a group is not already in groups list
// Return true is group already in groups list, false if not
func icbGroupIsPresent(group IcbGroup) bool {
	for _, grp := range IcbGroups {
		if grp.Name == group.Name {
			return true
		}
	}
	return false
}

// Convert Unix time as string (seconds since Jan. 1, 1970 GMT) to time.Time
func stringToTime(s string) (time.Time, error) {
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(sec, 0), nil
}

// Parse Command Ouput for type = 'wl' and returns ICB User parsed from data
func icbGetUser(fields []string) (*icbUser, error) {
	if len(fields) != 8 {
		return nil, fmt.Errorf("invalid number of fields for user - len(fields) = %d", len(fields))
	}
	var err error
	user := &icbUser{}

	// Check if moderator ('m' or '*')
	user.Moderator = false
	moderator := getIcbString(fields[0])
	if moderator != " " {
		if moderator != "m" && moderator != "*" {
			logger.LogWarnf("ICB - invalid moderator status = '%s'", moderator)
		} else {
			user.Moderator = true
		}
	}
	user.Nick = getIcbString(fields[1])
	user.Idle, err = strconv.Atoi(getIcbString(fields[2]))
	if err != nil {
		logger.LogErrorf("ICB - invalid idle time for user %s - value = %s", user.Nick, getIcbString(fields[2]))
	}
	// Unix time format
	user.LoginTime, err = stringToTime(getIcbString(fields[4]))
	if err != nil {
		logger.LogErrorf("ICB - invalid login time for user %s - value = %s", user.Nick, getIcbString(fields[4]))
	}
	user.Username = getIcbString(fields[5])
	user.Hostname = getIcbString(fields[6])
	user.RegStatus = getIcbString(fields[7])

	return user, nil
}

// Print ICB User
func icbPrintUser(user icbUser) {
	logger.LogDebugf("ICB - [User] Moderator = %v", user.Moderator)
	logger.LogDebugf("ICB - [User] Nick = %s", user.Nick)
	logger.LogDebugf("ICB - [User] Idle = %d", user.Idle)
	logger.LogDebugf("ICB - [User] LoginTime = %s", user.LoginTime.String())
	logger.LogDebugf("ICB - [User] Username = %s", user.Username)
	logger.LogDebugf("ICB - [User] Hostname = %s", user.Hostname)
	logger.LogDebugf("ICB - [User] Registration status = '%s'", user.RegStatus)
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
		group.Name = getIcbString(fields[1])
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
		if !icbGroupIsPresent(*group) {
			IcbGroups = append(IcbGroups, *group)
			logger.LogDebugf("ICB - Add group '%s' to list of groups", group.Name)
		} else {
			logger.LogDebugf("ICB - Group '%s' already present in list of groups", group.Name)
		}

	} else if strings.HasPrefix(data, "Total:") {
		// Output for 'Total:'
		fields := strings.Fields(data)
		// TODO check if not null-terminated string in Join
		logger.LogDebugf("ICB - [Total] %s", strings.Join(fields[1:], " "))

		// Send signal for groups list
		close(IcbGroupsChannel)

	} else {
		// Generic command output
		logger.LogDebugf("ICB - [Generic] '%s'", data)

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

	switch string(getIcbString(fields[0])) {
	// Generic command output
	case "co":
		parseIcbGenericCommandOutput(getIcbString(fields[1]), irc_conn)
	// Indicates end of output data from command
	case "ec":
		logger.LogDebugf("ICB - [End of output data from command] %s", getIcbString(fields[1]))
	// In a who listing, a line of output listing a user
	case "wl":
		// TODO Parse fields for users listing
		logger.LogDebugf("ICB - [User] fields = %v", fields[1:])
		user, _ := icbGetUser(fields[1:])
		icbPrintUser(*user)
	// In a who listing, a line of output listing a group
	case "wg":
		group_name := getIcbString(fields[1])
		group_topic := getIcbString(fields[2])
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
		logger.LogWarnf("ICB - Unknown Command output '%s'", getIcbString(fields[0]))
	}

	return nil
}

// Parse Status Message (ICB packet type = 'd')
// Inputs:
// - category (string): category for the message
// - content (string): content of the message
// - irc_conn (net.Conn): connection to IRC client
func parseIcbStatus(category string, content string, irc_conn net.Conn) error {
	if len(category) == 0 {
		return fmt.Errorf("invalid Status message - no category defined")
	}
	switch category {
	case "Status":
		// TODO Handle message 'You are now in group slac' => send IRC PART
		irc.IrcSendNotice(irc_conn, "*** :ICB Status Message: %s", content)
		return nil
	case "No-Pass":
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
// - msg (icbPacket): ICB packet received
// - irc_conn (net.Conn): handle for connection to IRC client
func icbHandleType(icb_conn net.Conn, msg icbPacket, irc_conn net.Conn) error {
	switch string(msg.Type) {
	// Login
	case icbPacketType["M_LOGINOK"]:
		logger.LogDebug("ICB - Received Login OK packet from server")

		// Send codes to complete IRC client registration
		logger.LogDebug("ICB - Send messages to IRC client for registration")
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_WELCOME"], ":Welcome to %s proxy %s", version.Name, irc.IrcNick)

		// Your host is default.icb.net running ICB Server v1.2c protocol 1
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_YOURHOST"], ":Your host is %s running %s protocol %d", icbProtocolInfo.HostId, icbProtocolInfo.ServerId, icbProtocolInfo.ProtocolLevel)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_CREATED"], ":This server was created recently")
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MYINFO"], "localhost %s-%s", version.Name, version.Version)

		// Send MOTD (message of the day)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTDSTART"], ":- %s Message of the day - ", "localhost")
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTD"], ":- Proxy for IRC client to ICB network")
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTD"], ":- Proxy using %s software, version %s", version.Name, version.Version)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTD"], ":- Repository: https://github.com/lcheylus/irc2icb/")
		// ICB server: ICB Server v1.2c
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_MOTD"], ":- ICB server: %s", icbProtocolInfo.ServerId)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFMOTD"], ":End of MOTD command")

		logger.LogInfo("ICB - Logged to server for nick Foxy")
		IcbLoggedIn = true

		// Test: send ICB Command
		// go timerCommand(conn)

	// Open Message
	case icbPacketType["M_OPEN"]:
		logger.LogDebug("ICB - Received Open Message")
		fields := getIcbPacketFields(msg.Data)
		nickname := getIcbString(fields[0])
		content := getIcbString(fields[1])
		logger.LogDebugf("ICB - Received Open Message packet - nickname = %s - content = %s", nickname, content)
	// Personal Message
	case icbPacketType["M_PERSONAL"]:
		logger.LogDebug("Received ICB Personal Message")
		fields := getIcbPacketFields(msg.Data)
		nickname := getIcbString(fields[0])
		content := getIcbString(fields[1])
		logger.LogDebugf("ICB - Received Personal Message packet - nickname = %s - content = %s", nickname, content)
	// Status Message
	case icbPacketType["M_STATUS"]:
		fields := getIcbPacketFields(msg.Data)
		category := getIcbString(fields[0])
		content := getIcbString(fields[1])
		logger.LogDebugf("ICB - Received Status Message packet - category = %s - content = %s", category, content)
		// TODO Parse Status Message: Status, Arrive, Depart, Sign-Off, Name, Topic, Pass, Boot
		err := parseIcbStatus(category, content, irc_conn)
		if err != nil {
			logger.LogErrorf("ICB - invalid Status Message packet - err = %s", err.Error())
		}
	// Error Message
	case icbPacketType["M_ERROR"]:
		fields := getIcbPacketFields(msg.Data)
		logger.LogErrorf("ICB - Received Error Message packet - err = %s", fields[0])
		// TODO Handle case if ICB connection not closed/reset
		// => ICB Error "Nickname already in use." with reconnection
	// Important Message
	case icbPacketType["M_IMPORTANT"]:
		fields := getIcbPacketFields(msg.Data)
		category := getIcbString(fields[0])
		content := getIcbString(fields[1])
		logger.LogDebugf("ICB - Received Important Message packet - category = %s - content = %s", category, content)
	// Exit
	case icbPacketType["M_EXIT"]:
		logger.LogDebug("ICB - Received Exit packet")
		IcbLoggedIn = false
		// TODO Close connection and exit
	// Command Output
	case icbPacketType["M_CMDOUT"]:
		logger.LogDebug("ICB - Received Command Output packet")
		fields := getIcbPacketFields(msg.Data)
		err := parseIcbCommandOutput(fields, irc_conn)
		if err != nil {
			logger.LogErrorf("ICB - invalid Command Output packet - err = %s", err.Error())
		}
	// Protocol
	case icbPacketType["M_PROTO"]:
		logger.LogDebug("ICB - Received Protocol packet")
		fields := getIcbPacketFields(msg.Data)
		if len(fields) == 0 {
			return fmt.Errorf("M_PROTO message: no protocol level (required)")
		}
		// Protocol Level is int - Required
		protocol_level, err := strconv.Atoi(getIcbString(fields[0]))
		if err != nil {
			return fmt.Errorf("M_PROTO message: protocol level is not int - value = %s", getIcbString(fields[0]))
		}
		icbProtocolInfo.ProtocolLevel = protocol_level
		// Host ID optional
		if len(fields) > 1 {
			icbProtocolInfo.HostId = getIcbString(fields[1])
		} else {
			icbProtocolInfo.HostId = "none"
		}
		// Server ID optional
		if len(fields) > 2 {
			icbProtocolInfo.ServerId = getIcbString(fields[2])
		} else {
			icbProtocolInfo.ServerId = "none"
		}

		logger.LogDebugf("ICB - ICB protocol level = %d", icbProtocolInfo.ProtocolLevel)
		logger.LogDebugf("ICB - ICB Host ID = %s", icbProtocolInfo.HostId)
		logger.LogDebugf("ICB - ICB Server ID = %s", icbProtocolInfo.ServerId)

		icbSendLogin(icb_conn, "Foxy")
	// Beep
	case icbPacketType["M_BEEP"]:
		fields := getIcbPacketFields(msg.Data)
		nick := getIcbString(fields[0])
		logger.LogDebugf("ICB - Received Beep packet - nick = %s", nick)
	// Ping from server
	case icbPacketType["M_PING"]:
		logger.LogDebug("ICB - Received PING packet")
		fields := getIcbPacketFields(msg.Data)
		if len(fields) > 1 {
			logger.LogWarnf("ICB - Invalid PING fields: %d received (max = 1) - fields = %s", len(fields), fields)
		}
		if len(fields) == 1 {
			// case icbMessageId := fields[0]
			// TODO Reply with PONG packet + Message Id
		}
	// Pong from server
	case icbPacketType["M_PONG"]:
		logger.LogDebug("ICB - Received PONG packet")
		fields := getIcbPacketFields(msg.Data)
		if len(fields) > 1 {
			logger.LogWarnf("ICB - Invalid PONG fields: %d received (max = 1) - fields = %s", len(fields), fields)
		}
		if len(fields) == 1 {
			// case icbMessageId := fields[0]
			// TODO Reply + Message Id ?
		}
	default:
		logger.LogWarnf("ICB - Unknown command type '%s'", string(msg.Type))
	}

	return nil
}

// Add packet's length as prefix (necessary for ICB packet with format 'Ltd')
func preprendPacketLength(packet []byte) []byte {
	if len(packet) > 255 {
		logger.LogWarnf("ICB - invalid length packet to add prefix - length=%d", len(packet))
	}

	packet = append(packet, 0)
	copy(packet[1:], packet)
	// Packet length does not include L byte
	packet[0] = byte(len(packet) - 1)

	return packet
}

// Send ICB "login" packet
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
func icbSendLogin(conn net.Conn, nick string) error {
	id := "fox"
	// TODO Handle case if group == ""
	group := "slac"
	login_cmd := "login"

	packet := []byte(fmt.Sprintf("%s%s\001%s\001%s\001%s\001f_pass", icbPacketType["M_LOGIN"], id, nick, group, login_cmd))

	// Add packet length as prefix
	if len(packet) > 255 {
		logger.LogDebugf("ICB - invalid Login packet for nick = %s - length = %d > 255", nick, packet, len(packet)-1)
	}
	packet = preprendPacketLength(packet)

	logger.LogDebugf("ICB - Login packet for nick = %s - packet = %v - length = %d", nick, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Login packet for nick = %s", nick)
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Login packet to server - nick = %s", nick)
	}

	return err
}

// Send ICB Command packet
func IcbSendCommand(conn net.Conn, args string) error {
	packet := []byte(fmt.Sprintf("%sw\001%s", icbPacketType["M_COMMAND"], args))
	packet = preprendPacketLength(packet)

	logger.LogDebugf("ICB - Command packet args = '%s' - packet = %v - length = %d", args, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Command packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Command packet to server")
	}

	return err
}

// TESTS - Function to send Command packet 5 seconds after Login OK
func timerCommand(conn net.Conn) {
	time.Sleep(5 * time.Second)
	// args = '' to list users
	IcbSendCommand(conn, "")

	// args = '-g' to list groups (/LIST IRC command)
	// icbSendCommand(conn, "-g")

	// args = <group name> to list users connected to group (/NAMES IRC command)
	// icbSendCommand(conn, "slac")
}

// TESTS - Function to send Ping packet with timer
// With server default.icb.net, Error message: "Server doesn't handle ICB_M_PING packets"
func timerPing(conn net.Conn) {
	for {
		time.Sleep(5 * time.Second)
		logger.LogDebugf("ICB - Send Ping packet to server")
		icbSendPing(conn)
	}
}

// Send ICB Ping packet
func icbSendPing(conn net.Conn) error {
	packet := []byte(icbPacketType["M_PING"])
	packet = preprendPacketLength(packet)

	logger.LogDebugf("ICB - Ping packet - packet = %v - length = %d", packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("ICB - Error when sending Ping packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("ICB - Send Ping packet to server")
	}

	return err
}

// TCP connection for ICB client
// Inputs:
// - server (string); address for ICB server
// - port (int): port for ICB server
// - irc_conn (net.Conn): handle for connection to IRC client
// func IcbConnect(server string, port int, irc_conn net.Conn) net.Conn {
func IcbConnect(server string, port int) net.Conn {
	addr := fmt.Sprintf("%s:%d", server, port)
	IcbLoggedIn = false

	logger.LogDebugf("ICB - Trying to connect to ICB server [%s]", addr)

	// Connect to the server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		logger.LogErrorf("ICB - Unable to connect to ICB server [%s]: err = %s", addr, err.Error())
		return nil
	}

	return conn
}
