// Package to handle IRC messages
// RFC 2812 - Internet Relay Chat: Client Protocol
// https://www.rfc-editor.org/rfc/rfc2812.html

package irc

import logger "irc2icb/utils"

// Numeric codes for IRC reply (RFC 2812, section 5.1)
// Defined as map to get key programmatically
var IrcReplyCodes = map[string]string{
	"RPL_WELCOME":  "001",
	"RPL_YOURHOST": "002",
	"RPL_CREATED":  "003",
	"RPL_MYINFO":   "004",
	"RPL_ISUPPORT": "005",

	"RPL_AWAY":    "301",
	"RPL_UNAWAY":  "305",
	"RPL_NOWAWAY": "306",

	"RPL_MOTDSTART": "375",
	"RPL_MOTD":      "372",
	"RPL_ENDOFMOTD": "376",

	"RPL_LISTSTART": "321",
	"RPL_LIST":      "322",
	"RPL_LISTEND":   "323",

	"RPL_WHOREPLY": "352",
	"RPL_ENDOFWHO": "315",

	"RPL_WHOISUSER":     "311",
	"RPL_WHOISSERVER":   "312",
	"RPL_WHOISCHANNELS": "319",
	"RPL_WHOISIDLE":     "317",
	"RPL_ENDOFWHOIS":    "318",

	"RPL_NOTOPIC":    "331",
	"RPL_TOPIC":      "332",
	"RPL_NAMREPLY":   "353",
	"RPL_ENDOFNAMES": "366",

	"ERR_NOSUCHNICK":       "401",
	"ERR_NOSUCHCHANNEL":    "403",
	"ERR_CANNOTSENDTOCHAN": "404",
	"ERR_ERRONEUSNICKNAME": "432",
	"ERR_NICKNAMEINUSE":    "433",
	"ERR_USERNOTINCHANNEL": "441",
	"ERR_NOTONCHANNEL":     "442",
	"ERR_NEEDMOREPARAMS":   "461",
	"ERR_CHANOPRIVSNEEDED": "482",
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
	logger.LogWarnf("getIrcReplyCode: unable to get key for code '%s'", val)
	return ""
}
