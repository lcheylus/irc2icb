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

// Return code for IRC command
const (
	IrcNop = iota
	IrcNick
	IrcUser
	IrcUnknown
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
func IrcCommand(conn net.Conn, data string) (int, []string) {
	msg, err := ircParseMessage(data)
	if err != nil {
		logger.LogDebug(err.Error())
	}

	switch msg.Command {
	case "NICK":
		logger.LogDebugf("Received IRC NICK command  - nick = %s", msg.Params[0])
		return IrcNick, msg.Params
	case "USER":
		logger.LogDebugf("Received IRC USER command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcUser, []string{msg.Params[0], msg.Trailing}
	case "QUIT":
		logger.LogDebugf("Received IRC QUIT command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcNop, nil
	case "PING":
		logger.LogDebugf("Received IRC PING command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		IrcSendMsg(conn, "PONG %s", msg.Params[0])
		logger.LogDebugf("Send IRC PONG message")
		return IrcNop, nil
	// TODO Send fake responses for LIST command
	case "LIST":
		logger.LogDebugf("Received IRC LIST command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		IrcSendCode(conn, "", "322", "channel1 # channel1 :topic for channel1")
		IrcSendCode(conn, "", "323", ":End of LIST")
		logger.LogDebugf("Send IRC response to LIST command")
		return IrcNop, nil
	default:
		logger.LogDebugf("Received unknown IRC command '%s'", msg.Command)
	}

	// USER
	// JOIN

	return IrcUnknown, []string{msg.Command}
}

// Send notification message to IRC connection
func IrcSendNotice(conn net.Conn, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	_, err := conn.Write([]byte("NOTICE " + msg + "\r\n"))
	return err
}

// Send messages with code to IRC connection
func IrcSendCode(conn net.Conn, nick string, code string, format string, args ...interface{}) error {
	// Exemple with 001 code message "001 <NICK> :Welcome to irc2icb proxy <NICK>"
	prefix := fmt.Sprintf("%s %s :", code, nick)
	msg := fmt.Sprintf(format, args...)
	_, err := conn.Write([]byte(prefix + msg + "\r\n"))
	return err
}

// Send messages to IRC connection
func IrcSendMsg(conn net.Conn, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	_, err := conn.Write([]byte(msg + "\r\n"))
	return err
}
