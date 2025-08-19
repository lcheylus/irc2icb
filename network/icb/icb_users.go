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

var (
	// TODO Use map instead with key = group's name
	IcbGroups       []*IcbGroup // List of ICB groups
	IcbGroupCurrent string      // Name of current group (for LIST and NAMES replies)
	// TODO Use map instead with key = user's nick
	IcbUsers []*IcbUser // List of ICB users

	icbGroupReceivedCurrent string        // Name of current group parsed from ICB Generic Command Output
	icbGroupsReceived       chan struct{} // Channel to signal reception of groups list
	icbUsersReceived        chan struct{} // Channel to signal reception of groups list with users
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
func IcbResetGroups() {
	for i := range IcbGroups {
		IcbGroups[i] = nil
	}
	IcbGroups = IcbGroups[:0]
}

// Reset global list of ICB users
// Remove all ICBUser in list for GC
func IcbResetUsers() {
	for i := range IcbUsers {
		IcbUsers[i] = nil
	}
	IcbUsers = IcbUsers[:0]
}

// Get ICB groups and users via ICB Command
// Inputs:
// - icb_conn (net.Conn): connection to ICB server
// Append group in IcbGroups list and user in IcbUsers list
func IcbQueryWho(icb_conn net.Conn) {
	// Send ICB command to list groups
	icbGroupsReceived = make(chan struct{})
	IcbSendList(icb_conn)
	// Wait reception of groups via ICB
	<-icbGroupsReceived
	logger.LogInfo("ICB - List of groups received")

	// Send ICB command to list users
	icbUsersReceived = make(chan struct{})
	IcbSendNames(icb_conn)

	// Wait reception of users via ICB
	<-icbUsersReceived
	logger.LogInfo("ICB - List of users received")

	// Dump list of groups and users received from ICB server
	var groups []string
	var users []string

	for _, group := range IcbGroups {
		groups = append(groups, group.Name)
	}
	for _, user := range IcbUsers {
		users = append(users, user.Nick)
	}
	logger.LogInfof("ICB - %d groups - %q", len(groups), groups)
	logger.LogInfof("ICB - %d users - %q", len(users), users)
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
	logger.LogWarnf("ICB - [icbGetGroupModerator] unable to find moderator of group %s", group.Name)
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
	logger.LogWarnf("ICB - [icbGetGroup] unable to find group '%s' in list of groups", name)
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
	// If nick length > 12, truncated to length = 12
	if len(nick) == 0 || len(nick) > 12 {
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
	logger.LogWarnf("ICB - [icbGetUser] unable to find user for nick '%s' in list of users", nick)
	return nil
}

// Print ICB User
func (user *IcbUser) icbPrintUser() {
	logger.LogDebugf("ICB - [User] Moderator = %v", user.Moderator)
	logger.LogDebugf("ICB - [User] Nick = %s", user.Nick)
	logger.LogDebugf("ICB - [User] Idle = %d", user.Idle)
	logger.LogDebugf("ICB - [User] LoginTime = %s", user.LoginTime.String())
	logger.LogDebugf("ICB - [User] Username = %s", user.Username)
	logger.LogDebugf("ICB - [User] Hostname = %s", user.Hostname)
	logger.LogDebugf("ICB - [User] Registration status = '%s'", user.RegStatus)
	logger.LogDebugf("ICB - [User] Current group = '%s'", icbGroupReceivedCurrent)
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

	// Add user nick in current group parsed from ICB Generic Command Output if not already present
	// TODO Check error (return == nil)
	group := IcbGetGroup(icbGroupReceivedCurrent)

	if !group.IcbUserInGroup(user.Nick) {
		group.Users = append(group.Users, user.Nick)
	}

	return user, nil
}
