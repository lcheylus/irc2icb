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


// Numeric codes for IRC reply (RFC 2812, section 5.1)
const (
	RPL_WELCOME = "001"
	RPL_YOURHOST = "002"
	RPL_CREATED = "003"
	RPL_MYINFO = "004"

	RPL_AWAY = "301"
	RPL_UNAWAY = "305"
	RPL_NOWAWAY = "306"

	RPL_MOTDSTART = "375"
	RPL_MOTD = "372"
	RPL_ENDOFMOTD = "376"

	RPL_LISTSTART = "321"
	RPL_LIST = "322"
	RPL_LISTEND = "323"
)


// Return code for IRC command
const (
	IrcCommandNop = iota  // Type for command without outputs
	IrcCommandNick
	IrcCommandUser
	IrcCommandUnknown
)

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
// Outputs:
//   - type of IRC command (int)
//   - datas parsed from IRC commands: params and traling ([]string)
func IrcCommand(conn net.Conn, data string) (int, []string) {
	msg, err := ircParseMessage(data)
	if err != nil {
		logger.LogDebug(err.Error())
	}

	switch msg.Command {
	case "NICK":
		logger.LogDebugf("Received IRC NICK command  - nick = %s", msg.Params[0])
		return IrcCommandNick, msg.Params
	case "USER":
		logger.LogDebugf("Received IRC USER command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandUser, []string{msg.Params[0], msg.Trailing}
	case "QUIT":
		logger.LogDebugf("Received IRC QUIT command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandNop, nil
	case "PING":
		logger.LogDebugf("Received IRC PING command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		IrcSendMsg(conn, "PONG %s", msg.Params[0])
		logger.LogDebugf("Send IRC PONG message")
		return IrcCommandNop, nil
	// Send fake reply for LIST command
	case "LIST":
		logger.LogDebugf("Received IRC LIST command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		// TODO: get Nick from inputs
		IrcSendCode(conn, "Foxy", RPL_LIST, "#channel1 10 :topic for channel1")
		IrcSendCode(conn, "Foxy", RPL_LIST, "#channel2 20 :topic for channel2")
		IrcSendCode(conn, "Foxy", RPL_LISTEND, ":End of /LIST")
		logger.LogDebugf("Send IRC reply to LIST command")
		return IrcCommandNop, nil
	default:
		logger.LogDebugf("Received unknown IRC command '%s'", msg.Command)
	}

	// PASS
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
func IrcSendCode(conn net.Conn, nick string, code string, format string, args ...interface{}) error {
	// Exemple with 001 code message "001 <NICK> :Welcome to irc2icb proxy <NICK>"
	prefix := fmt.Sprintf("%s %s ", code, nick)
	msg := fmt.Sprintf(format, args...)
	_, err := conn.Write([]byte(prefix + msg + "\r\n"))
	return err
}

// Send message to IRC connection
func IrcSendMsg(conn net.Conn, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	_, err := conn.Write([]byte(msg + "\r\n"))
	return err
}
