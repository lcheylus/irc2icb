// Package to handle IRC messages
// RFC 2812 - Internet Relay Chat: Client Protocol
// https://www.rfc-editor.org/rfc/rfc2812.html

package irc

import (
	"fmt"
	"net"
	"strings"

	logger "irc2icb/utils"
)

// Variables for IRC nick, pass, username and realname
var (
	IrcNick     string
	IrcPassword string
	IrcUser     string
	IrcRealname string
)

// Return code for IRC command
const (
	IrcCommandNop = iota // Type for command without outputs
	IrcCommandPass
	IrcCommandNick
	IrcCommandUser
	IrcCommandUnknown
)

// Numeric codes for IRC reply (RFC 2812, section 5.1)
// Defined as map to get key programmatically
var IrcReplyCodes = map[string]string{
	"RPL_WELCOME":  "001",
	"RPL_YOURHOST": "002",
	"RPL_CREATED":  "003",
	"RPL_MYINFO":   "004",

	"RPL_AWAY":    "301",
	"RPL_UNAWAY":  "305",
	"RPL_NOWAWAY": "306",

	"RPL_MOTDSTART": "375",
	"RPL_MOTD":      "372",
	"RPL_ENDOFMOTD": "376",

	"RPL_LISTSTART": "321",
	"RPL_LIST":      "322",
	"RPL_LISTEND":   "323",
}

// Get IRC reply code by key (RPL_xxx)
// Input: numeric value (as string) for code
// Output: code (string RPL_xxx)
func getIrcReplyCode(val string) string {
	for name := range IrcReplyCodes {
		if IrcReplyCodes[name] == val {
			return name
		}
	}

	logger.LogWarnf("IRC - getIrcReplyCode: unable to get key for code '%s'", val)
	return ""
}

// ircMessage represents a parsed IRC message
type ircMessage struct {
	Prefix   string // optional
	Command  string
	Params   []string
	Trailing string // optional
}

// ircParseMessage parses a raw IRC line into a ircMessage struct
func ircParseMessage(line string) (*ircMessage, error) {
	msg := &ircMessage{}
	original := line

	// Prefix (optional, starts with ':')
	if strings.HasPrefix(line, ":") {
		split := strings.SplitN(line[1:], " ", 2)
		if len(split) < 2 {
			return nil, fmt.Errorf("invalid message: %s", original)
		}
		msg.Prefix = split[0]
		line = split[1]
	}

	// Split trailing parameter (starts with " :")
	var trailing string
	if idx := strings.Index(line, " :"); idx != -1 {
		trailing = line[idx+2:]
		line = line[:idx]
	}

	// Remaining tokens: command and params
	tokens := strings.Fields(line)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no command found: %s", original)
	}

	msg.Command = tokens[0]
	if len(tokens) > 1 {
		msg.Params = tokens[1:]
	}
	msg.Trailing = trailing

	return msg, nil
}

// Handle IRC command
// Inputs:
//   - conn: handle to IRC client connection
//   - data: datas received from IRC server
//
// Outputs:
//   - type of IRC command (int for IrcCommandxxx)
//   - datas parsed from IRC commands: params and traling ([]string)
func IrcCommand(conn net.Conn, data string) (int, []string) {
	msg, err := ircParseMessage(data)
	if err != nil {
		logger.LogDebug(err.Error())
	}

	switch msg.Command {
	case "PASS":
		IrcPassword = msg.Params[0]
		logger.LogDebugf("IRC - Received PASS command  - password = %s", IrcPassword)
		return IrcCommandPass, []string{IrcPassword}
	case "NICK":
		IrcNick = msg.Params[0]
		logger.LogDebugf("IRC - Received NICK command  - nick = %s", IrcNick)
		return IrcCommandNick, []string{IrcNick}
	case "USER":
		IrcUser = msg.Params[0]
		IrcRealname = msg.Trailing
		logger.LogDebugf("IRC - Received USER command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandUser, []string{IrcUser, IrcRealname}
	case "QUIT":
		logger.LogDebugf("IRC - Received QUIT command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandNop, nil
	case "PING":
		logger.LogDebugf("IRC - Received PING command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		IrcSendMsg(conn, "PONG %s", msg.Params[0])
		logger.LogDebugf("IRC - Send PONG message")
		return IrcCommandNop, nil
	// Send fake reply for LIST command
	case "LIST":
		logger.LogDebugf("IRC - Received LIST command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		IrcSendCode(conn, IrcNick, IrcReplyCodes["RPL_LIST"], "#channel1 10 :topic for channel1")
		IrcSendCode(conn, IrcNick, IrcReplyCodes["RPL_LIST"], "#channel2 20 :topic for channel2")
		IrcSendCode(conn, IrcNick, IrcReplyCodes["RPL_LISTEND"], ":End of /LIST")
		logger.LogDebugf("IRC - Send reply to LIST command - nick = %s", IrcNick)
		return IrcCommandNop, nil
	default:
		logger.LogWarnf("IRC - Received unknown command '%s'", msg.Command)
	}

	// JOIN
	// PART
	// PRIVMSG

	return IrcCommandUnknown, []string{msg.Command}
}

// Send notification message to IRC connection
func IrcSendNotice(conn net.Conn, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	_, err := conn.Write([]byte("NOTICE " + msg + "\r\n"))
	return err
}

// Send message with code to IRC connection
// Example for RPL_WELCOME (001) code message: "001 <NICK> :Welcome to irc2icb proxy <NICK>"
func IrcSendCode(conn net.Conn, nick string, code string, format string, args ...interface{}) error {
	if nick == "" {
		logger.LogWarn("IRC - nick not defined in irc.IrcSendCode function")
	}

	prefix := fmt.Sprintf("%s %s ", code, nick)
	msg := fmt.Sprintf(format, args...)

	_, err := conn.Write([]byte(prefix + msg + "\r\n"))
	if err != nil {
		logger.LogDebugf("IRC - Error when sending message for %s code", getIrcReplyCode(code))
		// TODO how to handle error if unable to send message
	} else {
		logger.LogDebugf("IRC - Send %s message to client - nick = %s", getIrcReplyCode(code), nick)
	}

	return err
}

// Send message to IRC connection
func IrcSendMsg(conn net.Conn, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	_, err := conn.Write([]byte(msg + "\r\n"))
	return err
}
