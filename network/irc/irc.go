// Package to handle IRC messages
// RFC 2812 - Internet Relay Chat: Client Protocol
// https://www.rfc-editor.org/rfc/rfc2812.html

package irc

import (
	"fmt"
	"net"
	"strings"

	logger "irc2icb/utils"
	utils "irc2icb/utils"
)

// TODO Create IRCConn type and adapt IRCSendXXX methods

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
	IrcCommandNick
	IrcCommandPass
	IrcCommandUser
	IrcCommandJoin
	IrcCommandList
	IrcCommandNames
	IrcCommandMsg // Type for private messages and to a channel/group
	IrcCommandMode
	IrcCommandWho
	IrcCommandWhois
	IrcCommandTopic
	IrcCommandPing
	IrcCommandQuit
	IrcCommandUnknown
)

// Get nick with prefix to reply to JOIN/NAMES command
// Prefix format advertise via RPL_ISUPPORT code replies
// Prefix = @ for operator, + for voice, none for regular user
func IrcGetNickWithPrefix(nick string, moderator bool) string {
	if moderator {
		return fmt.Sprintf("@%s", nick)
	} else {
		return fmt.Sprintf("%s", nick)
	}
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
// Note: IRC/ICB replies must be in main code (prevent Go import cycle with
// icb/irc packages)
//
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
	case "PRIVMSG":
		logger.LogTracef("IRC - Received PRIVMSG command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandMsg, []string{msg.Params[0], msg.Trailing}
	case "PASS":
		IrcPassword = msg.Params[0]
		logger.LogTracef("IRC - Received PASS command  - password = %s", IrcPassword)
		return IrcCommandPass, []string{IrcPassword}
	case "NICK":
		IrcNick = msg.Params[0]
		logger.LogTracef("IRC - Received NICK command  - nick = %s", IrcNick)
		return IrcCommandNick, []string{IrcNick}
	case "USER":
		IrcUser = msg.Params[0]
		IrcRealname = msg.Trailing
		logger.LogTracef("IRC - Received USER command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandUser, []string{IrcUser, IrcRealname}
	case "JOIN":
		logger.LogTracef("IRC - Received JOIN command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		// TODO Handle case with multiple groups in params
		return IrcCommandJoin, msg.Params
	case "PART":
		logger.LogTracef("IRC - Received PART command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		if !utils.IsValidIrcChannel(msg.Params[0]) {
			logger.LogErrorf("IRC - invalid channel '%s' in PART command, don't start with #", msg.Params[0])
		}
		// Don't need to get channel the user is leaving, == current ICB group
		return IrcCommandNop, nil
	case "LIST":
		logger.LogTracef("IRC - Received LIST command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandList, nil
	case "NAMES":
		logger.LogTracef("IRC - Received NAMES command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandNames, []string{msg.Params[0]}
	case "MODE":
		logger.LogTracef("IRC - Received MODE command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandMode, msg.Params
	case "WHO":
		logger.LogTracef("IRC - Received WHO command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandWho, msg.Params
	case "WHOIS":
		logger.LogTracef("IRC - Received WHOIS command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandWhois, msg.Params
	case "TOPIC":
		logger.LogTracef("IRC - Received TOPIC command  - params = %s - trailing = '%s'", msg.Params, msg.Trailing)
		// Case for get topic => no trailing
		if msg.Trailing == "" && !strings.HasSuffix(data, ":") {
			return IrcCommandTopic, []string{msg.Params[0]}
		} else {
			return IrcCommandTopic, []string{msg.Params[0], msg.Trailing}
		}
	case "PING":
		logger.LogTracef("IRC - Received PING command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandPing, []string{msg.Params[0]}
	case "QUIT":
		logger.LogTracef("IRC - Received QUIT command  - params = %s - trailing = %s", msg.Params, msg.Trailing)
		return IrcCommandQuit, nil
	default:
		logger.LogWarnf("IRC - Received unknown command '%s'", msg.Command)
	}

	// PART
	// PRIVMSG

	return IrcCommandUnknown, []string{msg.Command}
}

// Send message to IRC connection
// Inputs:
// - src (string): source
// - dst (string): destination
// - msg (string): content
func IrcSendMsg(conn net.Conn, src string, dst string, msg string) error {
	_, err := conn.Write([]byte(fmt.Sprintf(":%s PRIVMSG %s :%s\r\n", src, dst, msg)))
	return err
}

// Send JOIN message to IRC connection
// Inputs:
// - nick (string): nick who is joining
// - user (string): username for user
// - host (string): hostname for user
// - channel (string): channel which that client has joined
func IrcSendJoin(conn net.Conn, nick string, user string, host string, channel string) error {
	msg := fmt.Sprintf(":%s!%s@%s JOIN :%s\r\n", nick, user, host, channel)
	_, err := conn.Write([]byte(msg))
	return err
}

// Send PART message to IRC connection
// Inputs:
// - nick (string): nick who is leaving
// - user (string): username for user
// - host (string): hostname for user
// - channel (string): channel which that client has left, prefixed with #
func IrcSendPart(conn net.Conn, nick string, user string, host string, channel string) error {
	logger.LogDebugf("IRC - Send PART message '%s!%s@%s' leave channel '%s'", nick, user, host, channel)
	msg := fmt.Sprintf(":%s!%s@%s PART %s\r\n", nick, user, host, channel)
	_, err := conn.Write([]byte(msg))
	return err
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

	// TODO Add target as ICB HostId
	// RFC 2812 section 2.4
	// The numeric reply MUST be sent as one message consisting of the sender prefix,
	// the three-digit numeric, and the target of the reply.
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

// Send raw message to IRC connection
func IrcSendRaw(conn net.Conn, format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	_, err := conn.Write([]byte(msg + "\r\n"))
	logger.LogTracef("IRC - Send raw messages '%s'", msg)

	return err
}
