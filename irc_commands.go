// Functions to handle IRC commands
// The functions cannot be in 'irc' package. Otherwise, there is an error with
// "import cycle" bettwen irc and icb packages.

package main

import (
	"net"
	"sort"
	"strconv"
	"strings"

	logger "irc2icb/utils"
	utils "irc2icb/utils"

	icb "irc2icb/network/icb"
	irc "irc2icb/network/irc"
)

// Handle IRC LIST command
// Inputs:
// - irc_conn (net.Conn): connection to IRC client
// - icb_conn (net.Conn): connection to ICB server
// - params ([]string): parameters from LIST command
func ircCommandList(irc_conn net.Conn, icb_conn net.Conn, params []string) {
	// TODO Add cache with duration => not query ICB server for
	// groups/users for each LIST command

	// Filter channels/groups with IRC command "LIST" paramaters
	var query string
	if len(params) == 0 {
		query = ""
	} else {
		query = params[0]
	}
	valid_channels, invalid_channels, err := irc.IrcFilterList(query)
	if err != nil {
		irc.IrcSendRaw(irc_conn, "ERROR :%s", err.Error())
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_LISTEND"], ":End of /LIST")
		// break
		return
	}

	logger.LogInfo("LIST command => send ICB command to get groups and users")
	icb.IcbQueryGroupsUsers(icb_conn, true)

	var valid_groups []*icb.IcbGroup

	// LIST command for all channels
	if len(valid_channels) == 0 && len(invalid_channels) == 0 {
		for _, group := range icb.IcbGroups {
			valid_groups = append(valid_groups, group)
		}
		goto SendListReplies
	}

	// LIST request ">N" => return groups with more than N users
	if len(valid_channels) == 1 && strings.HasPrefix(valid_channels[0], ">") {
		n_users, _ := strconv.Atoi(valid_channels[0][1:])
		for _, group := range icb.IcbGroups {
			if len(group.Users) >= n_users {
				valid_groups = append(valid_groups, group)
			}
		}
		goto SendListReplies
	}

	// LIST command to filter channels with pattern ('#chan*')
	if len(valid_channels) == 1 && strings.HasSuffix(valid_channels[0], "*") {
		prefix := strings.Trim(valid_channels[0], "*")
		for _, group := range icb.IcbGroups {
			if strings.HasPrefix(group.Name, utils.GroupFromChannel(prefix)) {
				valid_groups = append(valid_groups, group)
			}
		}
		goto SendListReplies
	}

	for _, irc_channel := range valid_channels {
		group := icb.IcbGetGroup(utils.GroupFromChannel(irc_channel))
		if group != nil {
			valid_groups = append(valid_groups, group)
		} else {
			irc.IrcSendNotice(irc_conn, "*** :Unknown ICB group '%s' in LIST command", utils.GroupFromChannel(irc_channel))
		}
	}
	goto SendListReplies

SendListReplies:
	logger.LogDebugf("Send reply to LIST command - nick = %s", irc.IrcNick)

	// Send IRC numeric reply RPL_LIST for each valid group
	for _, group := range valid_groups {
		logger.LogDebugf("[Group] Name = %s - Topic = '%s' - %d users %q", group.Name, group.Topic, len(group.Users), group.Users)
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_LIST"], "%s %d :%s", utils.GroupToChannel(group.Name), len(group.Users), group.Topic)
	}
	irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_LISTEND"], ":End of /LIST")

	// Send IRC notice for each invalid channel
	for _, irc_channel := range invalid_channels {
		irc.IrcSendNotice(irc_conn, "*** :Invalid channel '%s' in LIST command", irc_channel)
	}
}

// Handle IRC NAMES command
// Inputs:
// - irc_conn (net.Conn): connection to IRC client
// - icb_conn (net.Conn): connection to ICB server
// - params (string): parameters from NAMES command
func ircCommandNames(irc_conn net.Conn, icb_conn net.Conn, params string) {
	logger.LogInfof("NAMES command => parameters = %s", params)
	channels := strings.Split(params, ",")

	icb.IcbQueryGroupsUsers(icb_conn, false)

	var group *icb.IcbGroup

	for _, irc_channel := range channels {
		// If the channel name is invalid or the channel does not exist,
		// one RPL_ENDOFNAMES numeric containing the given channel name should be returned
		if !utils.IsValidIrcChannel(irc_channel) {
			logger.LogErrorf("invalid parameter '%s' for NAMES command", irc_channel)
			irc.IrcSendRaw(irc_conn, "ERROR :Invalid parameter '%s' for NAMES command", irc_channel)
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFNAMES"], "%s :End of /NAMES list", irc_channel)
			break
		} else {
			group = icb.IcbGetGroup(utils.GroupFromChannel(irc_channel))
			if group == nil {
				irc.IrcSendNotice(irc_conn, "*** :Unknown group '%s' in NAMES command", utils.GroupFromChannel(irc_channel))
				irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFNAMES"], "%s :End of /NAMES list", irc_channel)
				break
			}
		}

		// returns one RPL_NAMREPLY numeric containing the users joined to the channel
		// and a single RPL_ENDOFNAMES numeric
		var icb_user *icb.IcbUser
		var users_with_prefix []string

		for _, user := range group.Users {
			icb_user = icb.IcbGetUser(user)
			users_with_prefix = append(users_with_prefix, irc.IrcGetNickWithPrefix(user, icb_user.Moderator))
		}
		// Sort list of users by moderator status
		sort.SliceStable(users_with_prefix, func(i, j int) bool {
			return utils.CompareUser(users_with_prefix[i], users_with_prefix[j])
		})
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NAMREPLY"], "= %s :%s", irc_channel, strings.Join(users_with_prefix, " "))
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_ENDOFNAMES"], "%s :End of /NAMES list", irc_channel)
	}
}

// Handle IRC WHOIS command
// Inputs:
// - irc_conn (net.Conn): connection to IRC client
// - icb_conn (net.Conn): connection to ICB server
// - nick (string): parameter from WHOIS command
// TODO Handle case for multiple nicks in WHOIS command
func ircCommandWhois(irc_conn net.Conn, icb_conn net.Conn, nick string) {
	// This command is used to query information about a particular user.
	// The server SHOULD answer this command with numeric messages with information about the nick.
	logger.LogInfof("WHOIS command => nick = %s", nick)

	icb.IcbQueryGroupsUsers(icb_conn, false)

	icb_user := icb.IcbGetUser(nick)
	if icb_user == nil {
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOSUCHNICK"], "%s :No such nick", nick)
		return
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
}

///
