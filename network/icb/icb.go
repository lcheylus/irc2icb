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

	logger "irc2icb/utils"
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

// Get ICB packet type (M_xxx)
// Input: value (string with 1 byte) for type
// Output: type (M_xxx)
func getIcbPacketType(val string) string {
	for name := range icbPacketType {
		if icbPacketType[name] == val {
			return name
		}
	}

	logger.LogWarnf("getIcbPacketType: unable to get type for value '%s'", val)
	return ""
}

// Variables for ICB connection
var (
	IcbProtocolLevel int
	IcbHostId        string
	IcbServerId      string

	IcbLoggedIn bool // ICB logged in status
)

// icbPacket represents a parsed ICB packet
type icbPacket struct {
	Type byte
	Data []byte
}

// icbUser represents a ICB User (datas parsed for Command packet, type='wl')
type icbUser struct {
	Moderator   bool
	Nick        string
	Idle        int
	LoginTime   time.Time // Unix time_t format - Seconds since Jan. 1, 1970 GMT
	Username    string
	Hostname    string
	RegStatus   string
}

// icbGroup represents a ICB Group (datas parsed for Command packet, type='co'
// with header 'Group:')
type icbGroup struct {
	Name  string
	Topic string
}

// Loop to read packets from ICB server
func getIcbPackets(conn net.Conn) {
	reader := bufio.NewReader(conn)

	for {
		msg, err := parseIcbPacket(reader)
		if err != nil {
			if err == io.EOF {
				logger.LogInfo("Connection closed by ICB server")
				break
			}
			logger.LogDebugf("Read error from ICB server: %s", err.Error())
			break
		}

		logger.LogDebugf("Received ICB Message: Type=%s, Data='%s' (len = %d)", getIcbPacketType(string(msg.Type)), string(msg.Data), len(msg.Data))
		if len(msg.Data) > 1 {
			fields := getIcbPacketFields(msg.Data)
			logger.LogDebugf("ICB message fields = %s", strings.Join(fields, ","))
		}

		icbHandleType(conn, *msg)
	}
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

// Get fields from ICB packet datas
// The fields are data separated by ASCII ^A (\001).
// If a field is optional, it (and any fields after it) can merely be left out of the packet.
func getIcbPacketFields(raw []byte) []string {
	fields := strings.Split(string(raw), "\001")
	return fields
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
	if fields[0] != " " {
		if fields[0] != "m" && fields[0] != "*" {
			logger.LogWarnf("invalid moderator status = '%s'", fields[0])
		} else {
			user.Moderator = true
		}
	}
	user.Nick = fields[1]
	user.Idle, err = strconv.Atoi(fields[2])
	if err != nil {
		logger.LogErrorf("invalid idle time for user %s - value = %s", user.Nick, fields[2])
	}
	// Unix time format
	user.LoginTime , err = stringToTime(fields[4])
	if err != nil {
		logger.LogErrorf("invalid login time for user %s - value = %s", user.Nick, fields[4])
	}
	user.Username = fields[5]
	user.Hostname = fields[6]
	user.RegStatus = fields[7]

	return user, nil
}

// Print ICB User
func icbPrintUser(user icbUser) {
	logger.LogDebugf("[User] Moderator = %v", user.Moderator)
	logger.LogDebugf("[User] Nick = %s", user.Nick)
	logger.LogDebugf("[User] Idle = %d", user.Idle)
	logger.LogDebugf("[User] LoginTime = %s", user.LoginTime.String())
	logger.LogDebugf("[User] Username = %s", user.Username)
	logger.LogDebugf("[User] Hostname = %s", user.Hostname)
	logger.LogDebugf("[User] Registration status = '%s'", user.RegStatus)
}

// Parse ICB Generic Command Output (type = 'co')
func parseIcbGenericCommandOutput(data string) {
	if strings.HasPrefix(data, "Group:") {
		// Sample of data for 'Group' output
		// Group: zenomt   (rvl) Mod: zenomt        Topic: (None)
		fields := strings.Fields(data)
		if len(fields) < 2 {
			logger.LogWarn("invalid number of fields for 'Group'")
		}
		logger.LogDebugf("[Group] fields = %s", fields)

		group := &icbGroup{}
		group.Name = fields[1]
		for i, v := range fields {
			if v == "Topic:" {
				group.Topic = strings.Join(fields[i+1:], " ")
			}
		}
		if group.Topic == "" {
			logger.LogWarnf("unable to find topic for group '%s'", group.Name)
		}
		logger.LogDebugf("[Group] Name = %s", group.Name)
		logger.LogDebugf("[Group] Topic = '%s'", group.Topic)

	} else if strings.HasPrefix(data, "Total:") {
		// Output for 'Total:'
		fields := strings.Fields(data)
		logger.LogDebugf("[Total] %s", strings.Join(fields[1:], " "))
	} else {
		// Generic command output
		logger.LogDebugf("[Generic] '%s'", data)
	}

}

// Parse Command outputs (ICB message type = 'c')
func parseIcbCommandOutput(fields []string) error {
	// Required
	if len(fields) == 0 {
		return fmt.Errorf("invalid Command Output - no type defined")
	}

	switch string(fields[0]) {
	// Generic command output
	case "co":
		parseIcbGenericCommandOutput(fields[1])
	// Indicates end of output data from command
	case "ec":
		logger.LogDebugf("[End of output data from command] %s", fields[1])
	// In a who listing, a line of output listing a user
	case "wl":
		// TODO Parse fields for users listing
		logger.LogDebugf("[User] fields = %v", fields[1:])
		user, _ := icbGetUser(fields[1:])
		icbPrintUser(*user)
	// In a who listing, a line of output listing a group
	case "wg":
		group_name := fields[1]
		group_topic := fields[2]
		logger.LogDebugf("[Group] name = '%s' - topic = '%s'", group_name, group_topic)
	case "wh":
		logger.LogWarn("[deprecated] header for who listing output")
	case "gh":
		logger.LogWarn("[deprecated] group header for who listing output")
	case "ch":
		logger.LogWarn("[deprecated] list all the commands client handles internally")
	case "c":
		logger.LogWarn("[deprecated] list a single command")
	default:
		logger.LogWarnf("Unknown ICB command output '%s'", fields[0])
	}

	return nil
}

// Handle ICB packet according to type
func icbHandleType(conn net.Conn, msg icbPacket) error {
	switch string(msg.Type) {
	// Login
	case icbPacketType["M_LOGINOK"]:
		logger.LogDebugf("Received ICB Login OK packet from server")

		// TODO: send IRC messages for Registration + MOTD
		IcbLoggedIn = true

		// Test: send ICB Command
		go timerCommand(conn)

	// Open Message
	case icbPacketType["M_OPEN"]:
		logger.LogDebugf("Received ICB Open Message")
		fields := getIcbPacketFields(msg.Data)
		nickname := fields[0]
		content := fields[1]
		logger.LogDebugf("Received ICB Open Message packet - nickname = %s - content = %s", nickname, content)
	// Personal Message
	case icbPacketType["M_PERSONAL"]:
		logger.LogDebugf("Received ICB Personal Message")
		fields := getIcbPacketFields(msg.Data)
		nickname := fields[0]
		content := fields[1]
		logger.LogDebugf("Received ICB Personal Message packet - nickname = %s - content = %s", nickname, content)
	// Status Message
	case icbPacketType["M_STATUS"]:
		fields := getIcbPacketFields(msg.Data)
		category := fields[0]
		content := fields[1]
		logger.LogDebugf("Received ICB Status Message packet - category = %s - content = %s", category, content)
		// TODO Parse Status Message: Status, Arrive, Depart, Sign-Off, Name, Topic, Pass, Boot
	// Error Message
	case icbPacketType["M_ERROR"]:
		fields := getIcbPacketFields(msg.Data)
		logger.LogDebugf("Received ICB Error Message packet - err = %s", fields[0])
	// Important Message
	case icbPacketType["M_IMPORTANT"]:
		fields := getIcbPacketFields(msg.Data)
		category := fields[0]
		content := fields[1]
		logger.LogDebugf("Received ICB Important Message packet - category = %s - content = %s", category, content)
	// Exit
	case icbPacketType["M_EXIT"]:
		logger.LogDebugf("Received ICB Exit packet")
		IcbLoggedIn = false
		// TODO Close connection and exit
	// Command Output
	case icbPacketType["M_CMDOUT"]:
		logger.LogDebugf("Received ICB Command Output packet")
		fields := getIcbPacketFields(msg.Data)
		err := parseIcbCommandOutput(fields)
		if err != nil {
			logger.LogErrorf("invalid ICB Command Output packet - err = %s", err.Error())
		}
	// Protocol
	case icbPacketType["M_PROTO"]:
		logger.LogDebugf("Received ICB Protocol packet")
		fields := getIcbPacketFields(msg.Data)
		if len(fields) == 0 {
			return fmt.Errorf("M_PROTO message: no protocol level (required)")
		}
		// Protocol Level is int - Required
		IcbProtocolLevel, err := strconv.Atoi(fields[0])
		if err != nil {
			return fmt.Errorf("M_PROTO message: protocol level is not int - value = %s", fields[1])
		}
		logger.LogDebugf("ICB protocol level = %d", IcbProtocolLevel)
		// Host ID optional
		if len(fields) > 1 {
			IcbHostId = fields[1]
		} else {
			IcbHostId = "none"
		}
		logger.LogDebugf("ICB Host ID = %s", IcbHostId)
		// Server ID optional
		if len(fields) > 2 {
			IcbServerId = fields[2]
		} else {
			IcbServerId = "none"
		}
		IcbServerId = fields[2]
		logger.LogDebugf("ICB Server ID = %s", IcbServerId)

		icbSendLogin(conn, "Foxy")
	// Beep
	case icbPacketType["M_BEEP"]:
		fields := getIcbPacketFields(msg.Data)
		nick := fields[0]
		logger.LogDebugf("Received ICB Beep packet - nick = %s", nick)
	// Ping from server
	case icbPacketType["M_PING"]:
		logger.LogDebugf("Received ICB PING packet")
		fields := getIcbPacketFields(msg.Data)
		if len(fields) > 1 {
			logger.LogWarnf("Invalid ICB PING fields: %d received (max = 1) - fields = %s", len(fields), fields)
		}
		if len(fields) == 1 {
			// case icbMessageId := fields[0]
			// TODO Reply with PONG packet + Message Id
		}
	// Pong from server
	case icbPacketType["M_PONG"]:
		logger.LogDebugf("Received ICB PONG packet")
		fields := getIcbPacketFields(msg.Data)
		if len(fields) > 1 {
			logger.LogWarnf("Invalid ICB PONG fields: %d received (max = 1) - fields = %s", len(fields), fields)
		}
		if len(fields) == 1 {
			// case icbMessageId := fields[0]
			// TODO Reply + Message Id ?
		}
	default:
		logger.LogWarnf("Unknown ICB command type '%s'", string(msg.Type))
	}

	return nil
}

// Add packet's length as prefix (necessary for ICB packet with format 'Ltd')
func preprendPacketLength(packet []byte) []byte {
	if len(packet) > 255 {
		logger.LogWarnf("invalid length packet to add prefix - length=%d", len(packet))
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
		logger.LogDebugf("ICB invalid login packet for nick = %s - length = %d > 255", nick, packet, len(packet)-1)
	}
	packet = preprendPacketLength(packet)

	logger.LogDebugf("ICB login packet for nick = %s - packet = %v - length = %d", nick, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("Error when sending ICB login message for nick = %s", nick)
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("Send ICB login packet to server - nick = %s", nick)
	}

	return err
}

// Send ICB Command packet
func icbSendCommand(conn net.Conn, args string) error {
	packet := []byte(fmt.Sprintf("%sw\001%s", icbPacketType["M_COMMAND"], args))
	packet = preprendPacketLength(packet)

	logger.LogDebugf("ICB Command packet args = '%s' - packet = %v - length = %d", args, packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("Error when sending ICB Command packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("Send ICB Command packet to server")
	}

	return err
}

// TESTS - Function to send Command packet 5 seconds after Login OK
func timerCommand(conn net.Conn) {
	time.Sleep(5 * time.Second)
	// args = '' to list users
	icbSendCommand(conn, "")

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
		logger.LogDebugf("Send Ping packet to server")
		icbSendPing(conn)
	}
}

// Send ICB Ping packet
func icbSendPing(conn net.Conn) error {
	packet := []byte(icbPacketType["M_PING"])
	packet = preprendPacketLength(packet)

	logger.LogDebugf("ICB Ping packet - packet = %v - length = %d", packet, len(packet)-1)

	_, err := conn.Write(packet)
	if err != nil {
		logger.LogDebugf("Error when sending ICB Ping packet")
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("Send ICB Ping packet to server")
	}

	return err
}

// TCP connection for ICB client
func IcbConnect(server string, port int) {
	addr := fmt.Sprintf("%s:%d", server, port)
	IcbLoggedIn = false

	logger.LogDebugf("Trying to connect to ICB server [%s]", addr)

	// Connect to the server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		logger.LogErrorf("Unable to connect to ICB server [%s]: err = %s", addr, err.Error())
		return
	}
	defer conn.Close()

	ip := strings.Split(conn.RemoteAddr().String(), ":")[0]
	logger.LogInfof("Connected to ICB server %s (%s) port %d", server, ip, port)

	// Loop to read ICB packets from server
	logger.LogInfo("Start loop to read packets from ICB server")
	go getIcbPackets(conn)

	// logger.LogInfo("Start loop to send Ping packets to ICB server")
	// go timerPing(conn)

	// Loop => not exit program
	for {
	}

	// Read commands from stdin and send to server
	/* scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "/quit" {
			logger.LogInfo("Received /quit command")
			os.Exit(0)
		}
		// TODO Send command to server for disconnection
	} */
}
