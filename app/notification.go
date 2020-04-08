// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
	"github.com/vnforks/kid/v5/utils"
	"github.com/vnforks/kid/v5/utils/markdown"
)

func (a *App) SendNotifications(post *model.Post, branch *model.Branch, class *model.Class, sender *model.User, parentPostList *model.PostList) ([]string, error) {
	// Do not send notifications in archived classes
	if class.DeleteAt > 0 {
		return []string{}, nil
	}

	pchan := make(chan store.StoreResult, 1)
	go func() {
		props, err := a.Srv().Store.User().GetAllProfilesInClass(class.Id, true)
		pchan <- store.StoreResult{Data: props, Err: err}
		close(pchan)
	}()

	cmnchan := make(chan store.StoreResult, 1)
	go func() {
		props, err := a.Srv().Store.Class().GetAllClassMembersNotifyPropsForClass(class.Id, true)
		cmnchan <- store.StoreResult{Data: props, Err: err}
		close(cmnchan)
	}()

	var fchan chan store.StoreResult
	if len(post.FileIds) != 0 {
		fchan = make(chan store.StoreResult, 1)
		go func() {
			fileInfos, err := a.Srv().Store.FileInfo().GetForPost(post.Id, true, false, true)
			fchan <- store.StoreResult{Data: fileInfos, Err: err}
			close(fchan)
		}()
	}

	result := <-pchan
	if result.Err != nil {
		return nil, result.Err
	}
	profileMap := result.Data.(map[string]*model.User)

	result = <-cmnchan
	if result.Err != nil {
		return nil, result.Err
	}
	classMemberNotifyPropsMap := result.Data.(map[string]model.StringMap)

	mentions := &ExplicitMentions{}
	allActivityPushUserIds := []string{}

	allowClassMentions := a.allowClassMentions(post, len(profileMap))
	keywords := a.getMentionKeywordsInClass(profileMap, allowClassMentions, classMemberNotifyPropsMap)

	mentions = getExplicitMentions(post, keywords)

	// Add an implicit mention when a user is added to a class
	// even if the user has set 'username mentions' to false in account settings.
	if post.Type == model.POST_ADD_TO_CLASS {
		addedUserId, ok := post.GetProp(model.POST_PROPS_ADDED_USER_ID).(string)
		if ok {
			mentions.addMention(addedUserId, KeywordMention)
		}
	}

	// get users that have comment thread mentions enabled
	// if len(post.RootId) > 0 && parentPostList != nil {
	// 	for _, threadPost := range parentPostList.Posts {
	// 		profile := profileMap[threadPost.UserId]
	// 		if profile != nil && (profile.NotifyProps[model.COMMENTS_NOTIFY_PROP] == model.COMMENTS_NOTIFY_ANY || (profile.NotifyProps[model.COMMENTS_NOTIFY_PROP] == model.COMMENTS_NOTIFY_ROOT && threadPost.Id == parentPostList.Order[0])) {
	// 			mentionType := ThreadMention
	// 			if threadPost.Id == parentPostList.Order[0] {
	// 				mentionType = CommentMention
	// 			}

	// 			mentions.addMention(threadPost.UserId, mentionType)
	// 		}
	// 	}
	// }

	// prevent the user from mentioning themselves
	if post.GetProp("from_webhook") != "true" {
		mentions.removeMention(post.UserId)
	}

	go func() {
		_, err := a.sendOutOfClassMentions(sender, post, class, mentions.OtherPotentialMentions)
		if err != nil {
			mlog.Error("Failed to send warning for out of class mentions", mlog.String("user_id", sender.Id), mlog.String("post_id", post.Id), mlog.Err(err))
		}
	}()

	// find which users in the class are set up to always receive mobile notifications
	for _, profile := range profileMap {
		if (profile.NotifyProps[model.PUSH_NOTIFY_PROP] == model.USER_NOTIFY_ALL ||
			classMemberNotifyPropsMap[profile.Id][model.PUSH_NOTIFY_PROP] == model.CLASS_NOTIFY_ALL) &&
			(post.UserId != profile.Id || post.GetProp("from_webhook") == "true") &&
			!post.IsSystemMessage() {
			allActivityPushUserIds = append(allActivityPushUserIds, profile.Id)
		}
	}

	mentionedUsersList := make([]string, 0, len(mentions.Mentions))
	// updateMentionChans := []chan *model.AppError{}

	// for id := range mentions.Mentions {
	// 	mentionedUsersList = append(mentionedUsersList, id)
	//
	// 	umc := make(chan *model.AppError, 1)
	// 	go func(userId string) {
	// 		umc <- a.Srv().Store.Class().IncrementMentionCount(post.ClassId, userId)
	// 		close(umc)
	// 	}(id)
	// 	updateMentionChans = append(updateMentionChans, umc)
	// }

	notification := &PostNotification{
		Post:       post,
		Class:      class,
		ProfileMap: profileMap,
		Sender:     sender,
	}
	/*
		if *a.Config().EmailSettings.SendEmailNotifications {
			for _, id := range mentionedUsersList {
				if profileMap[id] == nil {
					continue
				}

				//If email verification is required and user email is not verified don't send email.
				if *a.Config().EmailSettings.RequireEmailVerification && !profileMap[id].EmailVerified {
					mlog.Error("Skipped sending notification email, address not verified.", mlog.String("user_email", profileMap[id].Email), mlog.String("user_id", id))
					continue
				}

				if a.userAllowsEmail(profileMap[id], classMemberNotifyPropsMap[id], post) {
					a.sendNotificationEmail(notification, profileMap[id], branch)
				}
			}
		}
	*/
	// Check for class-wide mentions in classes that have too many members for those to work
	if int64(len(profileMap)) > *a.Config().BranchSettings.MaxNotificationsPerClass {
		T := utils.GetUserTranslations(sender.Locale)

		if mentions.HereMentioned {
			a.SendEphemeralPost(
				post.UserId,
				&model.Post{
					ClassId:  post.ClassId,
					Message:  T("api.post.disabled_here", map[string]interface{}{"Users": *a.Config().BranchSettings.MaxNotificationsPerClass}),
					CreateAt: post.CreateAt + 1,
				},
			)
		}

		if mentions.ClassMentioned {
			a.SendEphemeralPost(
				post.UserId,
				&model.Post{
					ClassId:  post.ClassId,
					Message:  T("api.post.disabled_class", map[string]interface{}{"Users": *a.Config().BranchSettings.MaxNotificationsPerClass}),
					CreateAt: post.CreateAt + 1,
				},
			)
		}

		if mentions.AllMentioned {
			a.SendEphemeralPost(
				post.UserId,
				&model.Post{
					ClassId:  post.ClassId,
					Message:  T("api.post.disabled_all", map[string]interface{}{"Users": *a.Config().BranchSettings.MaxNotificationsPerClass}),
					CreateAt: post.CreateAt + 1,
				},
			)
		}
	}

	// Make sure all mention updates are complete to prevent race
	// Probably better to batch these DB updates in the future
	// MUST be completed before push notifications send
	// or _, umc := range updateMentionChans {
	// 	if err := <-umc; err != nil {
	// 		mlog.Warn(
	// 			"Failed to update mention count",
	// 			mlog.String("post_id", post.Id),
	// 			mlog.String("class_id", post.ClassId),
	// 			mlog.Err(err),
	// 		)
	// 	}
	//

	// sendPushNotifications := false
	if *a.Config().EmailSettings.SendPushNotifications {
		pushServer := *a.Config().EmailSettings.PushNotificationServer
		if license := a.License(); pushServer == model.MHPNS && (license == nil || !*license.Features.MHPNS) {
			mlog.Warn("Push notifications are disabled. Go to System Console > Notifications > Mobile Push to enable them.")
			// sendPushNotifications = false
		} else {
			// sendPushNotifications = true
		}
	}

	/*if sendPushNotifications {
		for _, id := range mentionedUsersList {
			if profileMap[id] == nil {
				continue
			}

			var status *model.Status
			var err *model.AppError
			if status, err = a.GetStatus(id); err != nil {
				status = &model.Status{UserId: id, Status: model.STATUS_OFFLINE, Manual: false, LastActivityAt: 0, ActiveClass: ""}
			}

			if ShouldSendPushNotification(profileMap[id], classMemberNotifyPropsMap[id], true, status, post) {
				mentionType := mentions.Mentions[id]

				replyToThreadType := ""
				if mentionType == ThreadMention {
					replyToThreadType = model.COMMENTS_NOTIFY_ANY
				} else if mentionType == CommentMention {
					replyToThreadType = model.COMMENTS_NOTIFY_ROOT
				}

				a.sendPushNotification(
					notification,
					profileMap[id],
					mentionType == KeywordMention || mentionType == ClassMention || mentionType == DMMention,
					mentionType == ClassMention,
					replyToThreadType,
				)
			} else {
				// register that a notification was not sent
				a.NotificationsLog().Warn("Notification not sent",
					mlog.String("ackId", ""),
					mlog.String("type", model.PUSH_TYPE_MESSAGE),
					mlog.String("userId", id),
					mlog.String("postId", post.Id),
					mlog.String("status", model.PUSH_NOT_SENT),
				)
			}
		}

		for _, id := range allActivityPushUserIds {
			if profileMap[id] == nil {
				continue
			}

			if _, ok := mentions.Mentions[id]; !ok {
				var status *model.Status
				var err *model.AppError
				if status, err = a.GetStatus(id); err != nil {
					status = &model.Status{UserId: id, Status: model.STATUS_OFFLINE, Manual: false, LastActivityAt: 0, ActiveClass: ""}
				}

				if ShouldSendPushNotification(profileMap[id], classMemberNotifyPropsMap[id], false, status, post) {
					a.sendPushNotification(
						notification,
						profileMap[id],
						false,
						false,
						"",
					)
				} else {
					// register that a notification was not sent
					a.NotificationsLog().Warn("Notification not sent",
						mlog.String("ackId", ""),
						mlog.String("type", model.PUSH_TYPE_MESSAGE),
						mlog.String("userId", id),
						mlog.String("postId", post.Id),
						mlog.String("status", model.PUSH_NOT_SENT),
					)
				}
			}
		}
	}*/

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_POSTED, "", post.ClassId, "", nil)

	// Note that PreparePostForClient should've already been called by this point
	message.Add("post", post.ToJson())

	message.Add("class_display_name", notification.GetClassName(model.SHOW_USERNAME, ""))
	message.Add("class_name", class.Name)
	message.Add("sender_name", notification.GetSenderName(model.SHOW_USERNAME, *a.Config().ServiceSettings.EnablePostUsernameOverride))
	message.Add("branch_id", branch.Id)

	if len(post.FileIds) != 0 && fchan != nil {
		message.Add("otherFile", "true")

		var infos []*model.FileInfo
		if result := <-fchan; result.Err != nil {
			mlog.Warn("Unable to get fileInfo for push notifications.", mlog.String("post_id", post.Id), mlog.Err(result.Err))
		} else {
			infos = result.Data.([]*model.FileInfo)
		}

		for _, info := range infos {
			if info.IsImage() {
				message.Add("image", "true")
				break
			}
		}
	}

	if len(mentionedUsersList) != 0 {
		message.Add("mentions", model.ArrayToJson(mentionedUsersList))
	}

	a.Publish(message)
	return mentionedUsersList, nil
}

func (a *App) userAllowsEmail(user *model.User, classMemberNotificationProps model.StringMap, post *model.Post) bool {
	userAllowsEmails := user.NotifyProps[model.EMAIL_NOTIFY_PROP] != "false"
	if classEmail, ok := classMemberNotificationProps[model.EMAIL_NOTIFY_PROP]; ok {
		if classEmail != model.CLASS_NOTIFY_DEFAULT {
			userAllowsEmails = classEmail != "false"
		}
	}

	// Remove the user as recipient when the user has muted the class.
	if classMuted, ok := classMemberNotificationProps[model.MARK_UNREAD_NOTIFY_PROP]; ok {
		if classMuted == model.CLASS_MARK_UNREAD_MENTION {
			mlog.Debug("Class muted for user", mlog.String("user_id", user.Id), mlog.String("class_mute", classMuted))
			userAllowsEmails = false
		}
	}

	var status *model.Status
	var err *model.AppError
	if status, err = a.GetStatus(user.Id); err != nil {
		status = &model.Status{
			UserId:         user.Id,
			Status:         model.STATUS_OFFLINE,
			Manual:         false,
			LastActivityAt: 0,
			ActiveClass:    "",
		}
	}

	autoResponderRelated := status.Status == model.STATUS_OUT_OF_OFFICE || post.Type == model.POST_AUTO_RESPONDER
	emailNotificationsAllowedForStatus := status.Status != model.STATUS_ONLINE && status.Status != model.STATUS_DND

	return userAllowsEmails && emailNotificationsAllowedForStatus && user.DeleteAt == 0 && !autoResponderRelated
}

// sendOutOfClassMentions sends an ephemeral post to the sender of a post if any of the given potential mentions
// are outside of the post's class. Returns whether or not an ephemeral post was sent.
func (a *App) sendOutOfClassMentions(sender *model.User, post *model.Post, class *model.Class, potentialMentions []string) (bool, error) {
	outOfClassUsers, outOfGroupsUsers, err := a.filterOutOfClassMentions(sender, post, class, potentialMentions)
	if err != nil {
		return false, err
	}

	if len(outOfClassUsers) == 0 && len(outOfGroupsUsers) == 0 {
		return false, nil
	}

	a.SendEphemeralPost(post.UserId, makeOutOfClassMentionPost(sender, post, outOfClassUsers, outOfGroupsUsers))

	return true, nil
}

func (a *App) filterOutOfClassMentions(sender *model.User, post *model.Post, class *model.Class, potentialMentions []string) ([]*model.User, []*model.User, error) {
	if post.IsSystemMessage() {
		return nil, nil, nil
	}

	if class.BranchId == "" {
		return nil, nil, nil
	}

	if len(potentialMentions) == 0 {
		return nil, nil, nil
	}

	users, err := a.Srv().Store.User().GetProfilesByUsernames(potentialMentions, &model.ViewUsersRestrictions{Branches: []string{class.BranchId}})
	if err != nil {
		return nil, nil, err
	}

	// Filter out inactive users and bots
	allUsers := model.UserSlice(users).FilterByActive(true)
	allUsers = allUsers.FilterWithoutBots()

	if len(allUsers) == 0 {
		return nil, nil, nil
	}

	// Differentiate between users who can and can't be added to the class
	var outOfClassUsers model.UserSlice
	var outOfGroupsUsers model.UserSlice

	outOfClassUsers = users

	return outOfClassUsers, outOfGroupsUsers, nil
}

func makeOutOfClassMentionPost(sender *model.User, post *model.Post, outOfClassUsers, outOfGroupsUsers []*model.User) *model.Post {
	allUsers := model.UserSlice(append(outOfClassUsers, outOfGroupsUsers...))

	ocUsers := model.UserSlice(outOfClassUsers)
	ocUsernames := ocUsers.Usernames()
	ocUserIDs := ocUsers.IDs()

	ogUsers := model.UserSlice(outOfGroupsUsers)
	ogUsernames := ogUsers.Usernames()

	T := utils.GetUserTranslations(sender.Locale)

	ephemeralPostId := model.NewId()
	var message string
	if len(outOfClassUsers) == 1 {
		message = T("api.post.check_for_out_of_class_mentions.message.one", map[string]interface{}{
			"Username": ocUsernames[0],
		})
	} else if len(outOfClassUsers) > 1 {
		preliminary, final := splitAtFinal(ocUsernames)

		message = T("api.post.check_for_out_of_class_mentions.message.multiple", map[string]interface{}{
			"Usernames":    strings.Join(preliminary, ", @"),
			"LastUsername": final,
		})
	}

	if len(outOfGroupsUsers) == 1 {
		if len(message) > 0 {
			message += "\n"
		}

		message += T("api.post.check_for_out_of_class_groups_mentions.message.one", map[string]interface{}{
			"Username": ogUsernames[0],
		})
	} else if len(outOfGroupsUsers) > 1 {
		preliminary, final := splitAtFinal(ogUsernames)

		if len(message) > 0 {
			message += "\n"
		}

		message += T("api.post.check_for_out_of_class_groups_mentions.message.multiple", map[string]interface{}{
			"Usernames":    strings.Join(preliminary, ", @"),
			"LastUsername": final,
		})
	}

	props := model.StringInterface{
		model.PROPS_ADD_CLASS_MEMBER: model.StringInterface{
			"post_id": ephemeralPostId,

			"usernames":              allUsers.Usernames(), // Kept for backwards compatibility of mobile app.
			"not_in_class_usernames": ocUsernames,

			"user_ids":              allUsers.IDs(), // Kept for backwards compatibility of mobile app.
			"not_in_class_user_ids": ocUserIDs,

			"not_in_groups_usernames": ogUsernames,
			"not_in_groups_user_ids":  ogUsers.IDs(),
		},
	}

	return &model.Post{
		Id:       ephemeralPostId,
		ClassId:  post.ClassId,
		Message:  message,
		CreateAt: post.CreateAt + 1,
		Props:    props,
	}
}

func splitAtFinal(items []string) (preliminary []string, final string) {
	if len(items) == 0 {
		return
	}
	preliminary = items[:len(items)-1]
	final = items[len(items)-1]
	return
}

type ExplicitMentions struct {
	// Mentions contains the ID of each user that was mentioned and how they were mentioned.
	Mentions map[string]MentionType

	// OtherPotentialMentions contains a list of strings that looked like mentions, but didn't have
	// a corresponding keyword.
	OtherPotentialMentions []string

	// HereMentioned is true if the message contained @here.
	HereMentioned bool

	// AllMentioned is true if the message contained @all.
	AllMentioned bool

	// ClassMentioned is true if the message contained @class.
	ClassMentioned bool
}

type MentionType int

const (
	// Different types of mentions ordered by their priority from lowest to highest

	// A placeholder that should never be used in practice
	NoMention MentionType = iota

	// The post is in a thread that the user has commented on
	ThreadMention

	// The post is a comment on a thread started by the user
	CommentMention

	// The post contains an at-class, at-all, or at-here
	ClassMention

	// The post is a DM
	DMMention

	// The post contains an at-mention for the user
	KeywordMention
)

func (m *ExplicitMentions) addMention(userId string, mentionType MentionType) {
	if m.Mentions == nil {
		m.Mentions = make(map[string]MentionType)
	}

	if currentType, ok := m.Mentions[userId]; ok && currentType >= mentionType {
		return
	}

	m.Mentions[userId] = mentionType
}

func (m *ExplicitMentions) addMentions(userIds []string, mentionType MentionType) {
	for _, userId := range userIds {
		m.addMention(userId, mentionType)
	}
}

func (m *ExplicitMentions) removeMention(userId string) {
	delete(m.Mentions, userId)
}

// Given a message and a map mapping mention keywords to the users who use them, returns a map of mentioned
// users and a slice of potential mention users not in the class and whether or not @here was mentioned.
func getExplicitMentions(post *model.Post, keywords map[string][]string) *ExplicitMentions {
	ret := &ExplicitMentions{}

	buf := ""
	mentionsEnabledFields := getMentionsEnabledFields(post)
	for _, message := range mentionsEnabledFields {
		markdown.Inspect(message, func(node interface{}) bool {
			text, ok := node.(*markdown.Text)
			if !ok {
				ret.processText(buf, keywords)
				buf = ""
				return true
			}
			buf += text.Text
			return false
		})
	}
	ret.processText(buf, keywords)

	return ret
}

// Given a post returns the values of the fields in which mentions are possible.
// post.message, preText and text in the attachment are enabled.
func getMentionsEnabledFields(post *model.Post) model.StringArray {
	ret := []string{}

	ret = append(ret, post.Message)
	for _, attachment := range post.Attachments() {

		if len(attachment.Pretext) != 0 {
			ret = append(ret, attachment.Pretext)
		}
		if len(attachment.Text) != 0 {
			ret = append(ret, attachment.Text)
		}
	}
	return ret
}

// allowClassMentions returns whether or not the class mentions are allowed for the given post.
func (a *App) allowClassMentions(post *model.Post, numProfiles int) bool {
	if !a.HasPermissionToClass(post.UserId, post.ClassId, model.PERMISSION_USE_CLASS_MENTIONS) {
		return false
	}

	if post.Type == model.POST_HEADER_CHANGE || post.Type == model.POST_PURPOSE_CHANGE {
		return false
	}

	if int64(numProfiles) >= *a.Config().BranchSettings.MaxNotificationsPerClass {
		return false
	}

	return true
}

// Given a map of user IDs to profiles, returns a list of mention
// keywords for all users in the class.
func (a *App) getMentionKeywordsInClass(profiles map[string]*model.User, allowClassMentions bool, classMemberNotifyPropsMap map[string]model.StringMap) map[string][]string {
	keywords := make(map[string][]string)

	for _, profile := range profiles {
		addMentionKeywordsForUser(
			keywords,
			profile,
			classMemberNotifyPropsMap[profile.Id],
			a.GetStatusFromCache(profile.Id),
			allowClassMentions,
		)
	}

	return keywords
}

// addMentionKeywordsForUser adds the mention keywords for a given user to the given keyword map. Returns the provided keyword map.
func addMentionKeywordsForUser(keywords map[string][]string, profile *model.User, classNotifyProps map[string]string, status *model.Status, allowClassMentions bool) map[string][]string {
	userMention := "@" + strings.ToLower(profile.Username)
	keywords[userMention] = append(keywords[userMention], profile.Id)

	// Add all the user's mention keys
	for _, k := range profile.GetMentionKeys() {
		// note that these are made lower case so that we can do a case insensitive check for them
		key := strings.ToLower(k)

		if key != "" {
			keywords[key] = append(keywords[key], profile.Id)
		}
	}

	// If turned on, add the user's case sensitive first name
	if profile.NotifyProps[model.FIRST_NAME_NOTIFY_PROP] == "true" {
		keywords[profile.FirstName] = append(keywords[profile.FirstName], profile.Id)
	}

	// Add @class and @all to keywords if user has them turned on and the server allows them
	if allowClassMentions {
		ignoreClassMentions := classNotifyProps[model.IGNORE_CLASS_MENTIONS_NOTIFY_PROP] == model.IGNORE_CLASS_MENTIONS_ON

		if profile.NotifyProps[model.CLASS_MENTIONS_NOTIFY_PROP] == "true" && !ignoreClassMentions {
			keywords["@class"] = append(keywords["@class"], profile.Id)
			keywords["@all"] = append(keywords["@all"], profile.Id)

			if status != nil && status.Status == model.STATUS_ONLINE {
				keywords["@here"] = append(keywords["@here"], profile.Id)
			}
		}
	}

	return keywords
}

// Represents either an email or push notification and contains the fields required to send it to any user.
type PostNotification struct {
	Class      *model.Class
	Post       *model.Post
	ProfileMap map[string]*model.User
	Sender     *model.User
}

// Returns the name of the class for this notification. For direct messages, this is the sender's name
// preceded by an at sign. For group messages, this is a comma-separated list of the members of the
// class, with an option to exclude the recipient of the message from that list.
func (n *PostNotification) GetClassName(userNameFormat, excludeId string) string {
	return n.Class.DisplayName
}

// Returns the name of the sender of this notification, accounting for things like system messages
// and whether or not the username has been overridden by an integration.
func (n *PostNotification) GetSenderName(userNameFormat string, overridesAllowed bool) string {
	if n.Post.IsSystemMessage() {
		return utils.T("system.message.name")
	}

	if overridesAllowed {
		if value, ok := n.Post.GetProps()["override_username"]; ok && n.Post.GetProp("from_webhook") == "true" {
			return value.(string)
		}
	}

	return n.Sender.GetDisplayNameWithPrefix(userNameFormat, "@")
}

// checkForMention checks if there is a mention to a specific user or to the keywords here / class / all
func (m *ExplicitMentions) checkForMention(word string, keywords map[string][]string) bool {
	var mentionType MentionType

	switch strings.ToLower(word) {
	case "@here":
		m.HereMentioned = true
		mentionType = ClassMention
	case "@class":
		m.ClassMentioned = true
		mentionType = ClassMention
	case "@all":
		m.AllMentioned = true
		mentionType = ClassMention
	default:
		mentionType = KeywordMention
	}

	if ids, match := keywords[strings.ToLower(word)]; match {
		m.addMentions(ids, mentionType)
		return true
	}

	// Case-sensitive check for first name
	if ids, match := keywords[word]; match {
		m.addMentions(ids, mentionType)
		return true
	}

	return false
}

// isKeywordMultibyte checks if a word containing a multibyte character contains a multibyte keyword
func isKeywordMultibyte(keywords map[string][]string, word string) ([]string, bool) {
	ids := []string{}
	match := false
	var multibyteKeywords []string
	for keyword := range keywords {
		if len(keyword) != utf8.RuneCountInString(keyword) {
			multibyteKeywords = append(multibyteKeywords, keyword)
		}
	}

	if len(word) != utf8.RuneCountInString(word) {
		for _, key := range multibyteKeywords {
			if strings.Contains(word, key) {
				ids, match = keywords[key]
			}
		}
	}
	return ids, match
}

// Processes text to filter mentioned users and other potential mentions
func (m *ExplicitMentions) processText(text string, keywords map[string][]string) {
	systemMentions := map[string]bool{"@here": true, "@class": true, "@all": true}

	for _, word := range strings.FieldsFunc(text, func(c rune) bool {
		// Split on any whitespace or punctuation that can't be part of an at mention or emoji pattern
		return !(c == ':' || c == '.' || c == '-' || c == '_' || c == '@' || unicode.IsLetter(c) || unicode.IsNumber(c))
	}) {
		// skip word with format ':word:' with an assumption that it is an emoji format only
		if word[0] == ':' && word[len(word)-1] == ':' {
			continue
		}

		word = strings.TrimLeft(word, ":.-_")

		if m.checkForMention(word, keywords) {
			continue
		}

		foundWithoutSuffix := false
		wordWithoutSuffix := word
		for len(wordWithoutSuffix) > 0 && strings.LastIndexAny(wordWithoutSuffix, ".-:_") == (len(wordWithoutSuffix)-1) {
			wordWithoutSuffix = wordWithoutSuffix[0 : len(wordWithoutSuffix)-1]

			if m.checkForMention(wordWithoutSuffix, keywords) {
				foundWithoutSuffix = true
				break
			}
		}

		if foundWithoutSuffix {
			continue
		}

		if _, ok := systemMentions[word]; !ok && strings.HasPrefix(word, "@") {
			// No need to bother about unicode as we are looking for ASCII characters.
			last := word[len(word)-1]
			switch last {
			// If the word is possibly at the end of a sentence, remove that character.
			case '.', '-', ':':
				word = word[:len(word)-1]
			}
			m.OtherPotentialMentions = append(m.OtherPotentialMentions, word[1:])
		} else if strings.ContainsAny(word, ".-:") {
			// This word contains a character that may be the end of a sentence, so split further
			splitWords := strings.FieldsFunc(word, func(c rune) bool {
				return c == '.' || c == '-' || c == ':'
			})

			for _, splitWord := range splitWords {
				if m.checkForMention(splitWord, keywords) {
					continue
				}
				if _, ok := systemMentions[splitWord]; !ok && strings.HasPrefix(splitWord, "@") {
					m.OtherPotentialMentions = append(m.OtherPotentialMentions, splitWord[1:])
				}
			}
		}

		if ids, match := isKeywordMultibyte(keywords, word); match {
			m.addMentions(ids, KeywordMention)
		}
	}
}

func (a *App) GetNotificationNameFormat(user *model.User) string {
	if !*a.Config().PrivacySettings.ShowFullName {
		return model.SHOW_USERNAME
	}

	data, err := a.Srv().Store.Preference().Get(user.Id, model.PREFERENCE_CATEGORY_DISPLAY_SETTINGS, model.PREFERENCE_NAME_NAME_FORMAT)
	if err != nil {
		return *a.Config().BranchSettings.BranchmateNameDisplay
	}

	return data.Value
}
