// Types and functions to handle ICB groups and users

package icb

import (
	"fmt"
	"net"
	"strconv"
	"time"
	"unicode"

	logger "irc2icb/utils"
)

const (
	MAX_AGE_INFOS int = 5 // Duration in minutes before refresh of groups/users from ICB server
)

var (
	// TODO Use map instead with key = group's name
	IcbGroups       []*IcbGroup // List of ICB groups
	IcbGroupCurrent string      // Name of current group (for LIST and NAMES replies)
	// TODO Use map instead with key = user's nick
	IcbUsers []*IcbUser // List of ICB users

	icbGroupReceivedCurrent string        // Name of current group parsed from ICB Generic Command Output
	chGroupsReceived        chan struct{} // Channel to signal reception of groups list
	chUsersReceived         chan struct{} // Channel to signal reception of groups list with users
	icbInfosLastRefresh     time.Time     // Last date for refresh of ICB groups/users from server
	IcbInfosForceRefresh    bool          // Force refresh of infos from server
)

// IcbUser represents a ICB User (datas parsed for Command packet, type='wl')
type IcbUser struct {
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
	Users []string // List of users (by nick) member of this group
}

// Reset global list of ICB groups
// Remove all ICBGroup in list for GC
func icbResetGroups() {
	for i := range IcbGroups {
		IcbGroups[i] = nil
	}
	IcbGroups = IcbGroups[:0]
}

// Reset global list of ICB users
// Remove all ICBUser in list for GC
func icbResetUsers() {
	for i := range IcbUsers {
		IcbUsers[i] = nil
	}
	IcbUsers = IcbUsers[:0]
}

// Get ICB lists of groups and users
// If lists are empty, query infos from ICB server. If not, infos are sent from
// a cache managed with a duration before refresh.
// Refresh infos from ICB server can be forced via 'force' parameter.
//
// Inputs:
// - icb_conn (net.Conn): connection to ICB server
// - force (bool): force to refresh groups/users list from ICB server
// Append group in IcbGroups list and user in IcbUsers list
func IcbQueryGroupsUsers(icb_conn net.Conn, force bool) {
	if icbInfosLastRefresh.IsZero() {
		icbInfosLastRefresh = time.Now()
	}

	duration := time.Now().Sub(icbInfosLastRefresh)
	minutes := int(duration / time.Minute)
	seconds := int((duration % time.Minute) / time.Second)

	if !IcbInfosForceRefresh && !force && (len(IcbGroups) != 0) && (duration <= time.Duration(MAX_AGE_INFOS)*time.Minute) {
		logger.LogDebugf("[IcbQueryGroupsUsers] Get infos for groups/users - last refresh = %d minutes, %d seconds (<= %d minutes) => no query to ICB server", minutes, seconds, MAX_AGE_INFOS)
		return
	}

	if IcbInfosForceRefresh || force || (len(IcbGroups) == 0) {
		logger.LogDebugf("[IcbQueryGroupsUsers] Get infos for groups/users => query from ICB server")
	} else {
		logger.LogDebugf("[IcbQueryGroupsUsers] Get infos for groups/users - last refresh = %d minutes, %d seconds (> %d minutes) => query to ICB server", minutes, seconds, MAX_AGE_INFOS)
	}

	icbResetGroups()
	icbResetUsers()

	// Send ICB command to list groups
	chGroupsReceived = make(chan struct{})
	IcbSendList(icb_conn)
	// Wait reception of groups via ICB
	<-chGroupsReceived
	logger.LogInfo("List of groups received")

	// Send ICB command to list users
	chUsersReceived = make(chan struct{})
	IcbSendNames(icb_conn)

	// Wait reception of users via ICB
	<-chUsersReceived
	logger.LogInfo("List of users received")

	// Dump list of groups and users received from ICB server
	var groups []string
	var users []string

	for _, group := range IcbGroups {
		groups = append(groups, group.Name)
	}
	for _, user := range IcbUsers {
		users = append(users, user.Nick)
	}
	logger.LogInfof("%d groups - %q", len(groups), groups)
	logger.LogInfof("%d users - %q", len(users), users)

	icbInfosLastRefresh = time.Now()
	IcbInfosForceRefresh = false
}

// Add group in global list of groups
func icbAddGroup(group *IcbGroup) {
	IcbGroups = append(IcbGroups, group)
}

// Check if a group is not already in groups list
// Return true is group already in groups list, false if not
func icbGroupIsPresent(group *IcbGroup) bool {
	for _, grp := range IcbGroups {
		if grp.Name == group.Name {
			return true
		}
	}
	return false
}

// Get nick of user who is moderator for group
func (group *IcbGroup) icbGetGroupModerator() string {
	for _, user_nick := range group.Users {
		user := IcbGetUser(user_nick)
		if user.Moderator {
			return user.Nick
		}
	}
	logger.LogWarnf("[icbGetGroupModerator] unable to find moderator of group %s", group.Name)
	return ""
}

// Get group by name in list of groups
// Inputs:
// - name (string): name of group to find
// Return pointer to IcbGroup found, nil if none
func IcbGetGroup(name string) *IcbGroup {
	for _, group := range IcbGroups {
		if group.Name == name {
			return group
		}
	}
	logger.LogWarnf("[icbGetGroup] unable to find group '%s' in list of groups", name)
	return nil
}

// Check if a user's nick is not already in users for group
// Inputs:
// - nick (string): user nick
// Return true is user already in group, false if not
func (group *IcbGroup) IcbUserInGroup(nick string) bool {
	for _, user := range group.Users {
		if user == nick {
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

// Return code for validation of ICB nick
const (
	ICB_NICK_VALID = iota
	ICB_NICK_TOOLONG
	ICB_NICK_INVALID
)

// Function to check if a string is a valid ICB nickname
// Return:
// - ICB_NICK_VALID if nick is valid
// - ICB_NICK_TOOLONG if nick is too long
// - ICB_NICK_INVALID if nick is invalid
func IcbValidNickname(nick string) int {
	// If nick length > MAX_NICKLEN, truncated to length = MAX_NICKLEN
	if len(nick) == 0 || len(nick) > MAX_NICKLEN {
		return ICB_NICK_TOOLONG
	}

	// Only alphanumeric characters and "-" or "_"
	for _, ch := range nick {
		if unicode.IsLetter(ch) || unicode.IsDigit(ch) || ch == '-' || ch == '_' {
			continue
		}
		return ICB_NICK_INVALID
	}

	return ICB_NICK_VALID
}

// Add user in global list of users
func icbAddUser(user *IcbUser) {
	IcbUsers = append(IcbUsers, user)
}

// Check if a user is not already in users list, query by nick
// Return true is user already in users list, false if not
func icbUserIsPresent(user *IcbUser) bool {
	for _, tmp_user := range IcbUsers {
		if tmp_user.Nick == user.Nick {
			return true
		}
	}
	return false
}

// Get user by nick in list of users
// Inputs:
// - nick (string): nick of user to find
// Return pointer to IcbGroup found, nil if none
func IcbGetUser(nick string) *IcbUser {
	for _, user := range IcbUsers {
		if user.Nick == nick {
			return user
		}
	}
	logger.LogWarnf("[icbGetUser] unable to find user for nick '%s' in list of users", nick)
	return nil
}

// Print ICB User
func (user *IcbUser) icbPrintUser() {
	logger.LogDebugf("[User] Moderator = %v", user.Moderator)
	logger.LogDebugf("[User] Nick = %s", user.Nick)
	logger.LogDebugf("[User] Idle = %d", user.Idle)
	logger.LogDebugf("[User] LoginTime = %s", user.LoginTime.String())
	logger.LogDebugf("[User] Username = %s", user.Username)
	logger.LogDebugf("[User] Hostname = %s", user.Hostname)
	logger.LogDebugf("[User] Registration status = '%s'", user.RegStatus)
	logger.LogDebugf("[User] Current group = '%s'", icbGroupReceivedCurrent)
}

// Parse Command Output for type = 'wl' and returns ICB User parsed from data
func icbParseUser(fields []string) (*IcbUser, error) {
	if len(fields) != 8 {
		return nil, fmt.Errorf("invalid number of fields for user - len(fields) = %d", len(fields))
	}
	var err error
	user := &IcbUser{}

	// Check if moderator ('m' or '*')
	user.Moderator = false
	moderator := fields[0]
	if moderator != " " {
		if moderator != "m" && moderator != "*" {
			logger.LogWarnf("invalid moderator status = '%s'", moderator)
		} else {
			user.Moderator = true
		}
	}
	user.Nick = fields[1]
	user.Idle, err = strconv.Atoi(fields[2])
	if err != nil {
		logger.LogErrorf("invalid idle time for user %s - value = %s", user.Nick, fields[2])
		user.Idle = 0
	}
	// Unix time format
	user.LoginTime, err = stringToTime(fields[4])
	if err != nil {
		logger.LogErrorf("invalid login time for user %s - value = %s", user.Nick, fields[4])
	}
	user.Username = fields[5]
	user.Hostname = fields[6]
	user.RegStatus = fields[7]

	// Add user nick in current group parsed from ICB Generic Command Output if not already present
	// TODO Check error (return == nil)
	group := IcbGetGroup(icbGroupReceivedCurrent)

	if !group.IcbUserInGroup(user.Nick) {
		group.Users = append(group.Users, user.Nick)
	}

	return user, nil
}
