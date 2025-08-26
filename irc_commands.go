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

// Handle IRC MODE command
// TODO: implementation to complete for all cases

// Inputs:
// - irc_conn (net.Conn): connection to IRC client
// - icb_conn (net.Conn): connection to ICB server
// - params ([]string): parameter from MODE command
func ircCommandMode(irc_conn net.Conn, icb_conn net.Conn, params []string) {
	logger.LogInfof("MODE command => parameters = %q", params)
	if !utils.IsValidIrcChannel(params[0]) || utils.GroupFromChannel(params[0]) != icb.IcbGroupCurrent {
		logger.LogDebugf("MODE command not for current ICB group => nothing to do - params = %q", params)
		// TODO Return message for error
		return
	}

	if len(params) == 1 {
		// No need to send IRC reply RPL_CHANNELMODEIS (324)
		// TODO Send ICB command to get users ?
		// see https://github.com/lcheylus/icbirc-portable/blob/5117d377af58aedc94caf89208df477c2aa8a722/src/irc.c#L159
		logger.LogDebugf("MODE command for group '%s' => TODO: get ICB users", params[0])
		return
	}

	// Case for <modestring> defined
	if len(params) > 1 {
		if params[1] != "+o" {
			logger.LogErrorf("MODE command: invalid args '%s'", params[1])
			return
		} else if len(params) < 3 {
			logger.LogError("MODE command: no nick to pass moderation (+o)")
			return
		} else {
			logger.LogDebugf("MODE command to pass moderation to '%s' (TODO)", params[2])
			// TODO Command MODE +o <nick> => pass moderation to nick, send ICB command
			// Check if user exists in ICBUsers
			// icb_send_pass(server_fd, argv[3])
		}
	}
}

// Handle IRC WHO command
// Inputs:
// - irc_conn (net.Conn): connection to IRC client
// - icb_conn (net.Conn): connection to ICB server
// - params ([]string): parameter from WHO command
func ircCommandWho(irc_conn net.Conn, icb_conn net.Conn, params []string) {
	// In the absence of the <mask> parameter, all visible (users who aren't invisible (user mode +i)
	// and who don't have a common channel with the requesting client) are listed.
	// The same result can be achieved by using a <mask> of "0" or any wildcard which will end up
	// matching every visible user.
	logger.LogInfof("WHO command => params = %q", params)

	if len(params) == 0 || params[0] == "0" {
		logger.LogInfo("WHO command => (TODO) case not handled to list all visible users")
		return
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
			return
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
		return
	}
	// TODO Case if mask != channel
	logger.LogInfof("WHO command => (TODO) case not handled for mask '%s'", params[0])
}

// Handle IRC WHOIS command
// Inputs:
// - irc_conn (net.Conn): connection to IRC client
// - icb_conn (net.Conn): connection to ICB server
// - params (string): parameter from WHOIS command
func ircCommandWhois(irc_conn net.Conn, icb_conn net.Conn, params string) {
	// This command is used to query information about a particular user.
	// The server SHOULD answer this command with numeric messages with information about the nick.
	logger.LogInfof("WHOIS command => params = '%s'", params)

	icb.IcbQueryGroupsUsers(icb_conn, false)

	nicks := strings.Split(params, ",")

	for _, nick := range nicks {
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
}

// Handle IRC KICK command
// Inputs:
// - irc_conn (net.Conn): connection to IRC client
// - icb_conn (net.Conn): connection to ICB server
// - params ([]string): parameter from KICK command
func ircCommandKick(irc_conn net.Conn, icb_conn net.Conn, params []string) {
	// params[0] = channel
	// params[1] = "user *( "," user)"
	logger.LogInfof("KICK command to kick nicks '%s' from channel '%s'", params[1], params[0])
	if len(params) != 2 {
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NEEDMOREPARAMS"], "%s :Invalid KICK command, needs more parameters", params[0])
		return
	}
	if params[0] != utils.GroupToChannel(icb.IcbGroupCurrent) {
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOTONCHANNEL"], "%s :You're not on that channel", params[0])
		return
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
}

// Handle IRC TOPIC command
// Inputs:
// - irc_conn (net.Conn): connection to IRC client
// - icb_conn (net.Conn): connection to ICB server
// - params ([]string): parameter from TOPIC command
func ircCommandTopic(irc_conn net.Conn, icb_conn net.Conn, params []string) {
	logger.LogInfof("TOPIC command params = %q", params)

	// Get topic for current group => get topic from ICB with topic = ""
	// Reply from parsing Generic command output
	if len(params) == 1 && params[0] == utils.GroupToChannel(icb.IcbGroupCurrent) {
		icb.IcbSendTopic(icb_conn, "")
		return
	}
	// Get topic for another group
	if len(params) == 1 && params[0] != utils.GroupToChannel(icb.IcbGroupCurrent) {
		group := icb.IcbGetGroup(utils.GroupFromChannel(params[0]))
		if group == nil {
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOSUCHCHANNEL"], "%s :No such channel", params[0])
			return
		}
		if group.Topic == icb.ICB_TOPICNONE {
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_NOTOPIC"], "%s :No topic is set", utils.GroupToChannel(group.Name))
			return
		} else {
			irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["RPL_TOPIC"], "%s :%s", utils.GroupToChannel(group.Name), group.Topic)
			return
		}
	}

	// Set/delete topic
	if params[0] != utils.GroupToChannel(icb.IcbGroupCurrent) {
		logger.LogWarnf("invalid channel '%s' for TOPIC command", params[0])
		irc.IrcSendCode(irc_conn, irc.IrcNick, irc.IrcReplyCodes["ERR_NOTONCHANNEL"], "%s :You're not on that channel", params[0])
		return
	}
	if params[1] == "" {
		// Case to "delete" topic for current group
		icb.IcbSendTopic(icb_conn, icb.ICB_TOPICNONE)
	} else {
		icb.IcbSendTopic(icb_conn, params[1])
	}
}
