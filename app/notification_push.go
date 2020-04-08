// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"hash/fnv"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/mattermost/go-i18n/i18n"
	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/utils"
)

type notificationType string

const (
	notificationTypeClear       notificationType = "clear"
	notificationTypeMessage     notificationType = "message"
	notificationTypeUpdateBadge notificationType = "update_badge"
)

const PUSH_NOTIFICATION_HUB_WORKERS = 1000
const PUSH_NOTIFICATIONS_HUB_BUFFER_PER_WORKER = 50

type PushNotificationsHub struct {
	Classes []chan PushNotification
}

type PushNotification struct {
	notificationType  notificationType
	currentSessionId  string
	userId            string
	classId           string
	post              *model.Post
	user              *model.User
	class             *model.Class
	senderName        string
	className         string
	explicitMention   bool
	classWideMention  bool
	replyToThreadType string
}

func (hub *PushNotificationsHub) GetGoClassFromUserId(userId string) chan PushNotification {
	h := fnv.New32a()
	h.Write([]byte(userId))
	chanIdx := h.Sum32() % PUSH_NOTIFICATION_HUB_WORKERS
	return hub.Classes[chanIdx]
}

func (a *App) sendPushNotificationSync(post *model.Post, user *model.User, class *model.Class, className string, senderName string,
	explicitMention bool, classWideMention bool, replyToThreadType string) *model.AppError {
	cfg := a.Config()
	msg, err := a.BuildPushNotificationMessage(
		*cfg.EmailSettings.PushNotificationContents,
		post,
		user,
		class,
		className,
		senderName,
		explicitMention,
		classWideMention,
		replyToThreadType,
	)
	if err != nil {
		return err
	}

	return a.sendPushNotificationToAllSessions(msg, user.Id, "")
}

func (a *App) sendPushNotificationToAllSessions(msg *model.PushNotification, userId string, skipSessionId string) *model.AppError {
	sessions, err := a.getMobileAppSessions(userId)
	if err != nil {
		return err
	}

	if msg == nil {
		return model.NewAppError(
			"pushNotification",
			"api.push_notifications.message.parse.app_error",
			nil,
			"",
			http.StatusBadRequest,
		)
	}

	notification, parseError := model.PushNotificationFromJson(strings.NewReader(msg.ToJson()))
	if parseError != nil {
		return model.NewAppError(
			"pushNotification",
			"api.push_notifications.message.parse.app_error",
			nil,
			parseError.Error(),
			http.StatusInternalServerError,
		)
	}

	for _, session := range sessions {
		// Don't send notifications to this session if it's expired or we want to skip it
		if session.IsExpired() || (skipSessionId != "" && skipSessionId == session.Id) {
			continue
		}

		// We made a copy to avoid decoding and parsing all the time
		tmpMessage := notification
		tmpMessage.SetDeviceIdAndPlatform(session.DeviceId)
		tmpMessage.AckId = model.NewId()

		err := a.sendToPushProxy(*tmpMessage, session)
		if err != nil {
			a.NotificationsLog().Error("Notification error",
				mlog.String("ackId", tmpMessage.AckId),
				mlog.String("type", tmpMessage.Type),
				mlog.String("userId", session.UserId),
				mlog.String("postId", tmpMessage.PostId),
				mlog.String("classId", tmpMessage.ClassId),
				mlog.String("deviceId", tmpMessage.DeviceId),
				mlog.String("status", err.Error()),
			)

			continue
		}

		a.NotificationsLog().Info("Notification sent",
			mlog.String("ackId", tmpMessage.AckId),
			mlog.String("type", tmpMessage.Type),
			mlog.String("userId", session.UserId),
			mlog.String("postId", tmpMessage.PostId),
			mlog.String("classId", tmpMessage.ClassId),
			mlog.String("deviceId", tmpMessage.DeviceId),
			mlog.String("status", model.PUSH_SEND_SUCCESS),
		)

		if a.Metrics() != nil {
			a.Metrics().IncrementPostSentPush()
		}
	}

	return nil
}

func (a *App) sendPushNotification(notification *PostNotification, user *model.User, explicitMention, classWideMention bool, replyToThreadType string) {
	cfg := a.Config()
	class := notification.Class
	post := notification.Post

	nameFormat := a.GetNotificationNameFormat(user)

	className := notification.GetClassName(nameFormat, user.Id)
	senderName := notification.GetSenderName(nameFormat, *cfg.ServiceSettings.EnablePostUsernameOverride)

	c := a.Srv().PushNotificationsHub.GetGoClassFromUserId(user.Id)
	c <- PushNotification{
		notificationType:  notificationTypeMessage,
		post:              post,
		user:              user,
		class:             class,
		senderName:        senderName,
		className:         className,
		explicitMention:   explicitMention,
		classWideMention:  classWideMention,
		replyToThreadType: replyToThreadType,
	}
}

func (a *App) getPushNotificationMessage(contentsConfig, postMessage string, explicitMention, classWideMention, hasFiles bool,
	senderName, className, replyToThreadType string, userLocale i18n.TranslateFunc) string {

	// If the post only has images then push an appropriate message
	if len(postMessage) == 0 && hasFiles {
		return senderName + userLocale("api.post.send_notifications_and_forget.push_image_only")
	}

	if contentsConfig == model.FULL_NOTIFICATION {
		return senderName + ": " + model.ClearMentionTags(postMessage)
	}

	if classWideMention {
		return senderName + userLocale("api.post.send_notification_and_forget.push_class_mention")
	}

	if explicitMention {
		return senderName + userLocale("api.post.send_notifications_and_forget.push_explicit_mention")
	}

	if replyToThreadType == model.COMMENTS_NOTIFY_ROOT {
		return senderName + userLocale("api.post.send_notification_and_forget.push_comment_on_post")
	}

	if replyToThreadType == model.COMMENTS_NOTIFY_ANY {
		return senderName + userLocale("api.post.send_notification_and_forget.push_comment_on_thread")
	}

	return senderName + userLocale("api.post.send_notifications_and_forget.push_general_message")
}

func (a *App) clearPushNotificationSync(currentSessionId, userId, classId string) *model.AppError {
	msg := &model.PushNotification{
		Type:             model.PUSH_TYPE_CLEAR,
		Version:          model.PUSH_MESSAGE_V2,
		ClassId:          classId,
		ContentAvailable: 1,
	}

	unreadCount, err := a.Srv().Store.User().GetUnreadCount(userId)
	if err != nil {
		return err
	}

	msg.Badge = int(unreadCount)

	return a.sendPushNotificationToAllSessions(msg, userId, currentSessionId)
}

func (a *App) clearPushNotification(currentSessionId, userId, classId string) {
	class := a.Srv().PushNotificationsHub.GetGoClassFromUserId(userId)
	class <- PushNotification{
		notificationType: notificationTypeClear,
		currentSessionId: currentSessionId,
		userId:           userId,
		classId:          classId,
	}
}

func (a *App) updateMobileAppBadgeSync(userId string) *model.AppError {
	msg := &model.PushNotification{
		Type:             model.PUSH_TYPE_UPDATE_BADGE,
		Version:          model.PUSH_MESSAGE_V2,
		Sound:            "none",
		ContentAvailable: 1,
	}

	unreadCount, err := a.Srv().Store.User().GetUnreadCount(userId)
	if err != nil {
		return err
	}

	msg.Badge = int(unreadCount)

	return a.sendPushNotificationToAllSessions(msg, userId, "")
}

func (a *App) UpdateMobileAppBadge(userId string) {
	class := a.Srv().PushNotificationsHub.GetGoClassFromUserId(userId)
	class <- PushNotification{
		notificationType: notificationTypeUpdateBadge,
		userId:           userId,
	}
}

func (a *App) createPushNotificationsHub() {
	hub := PushNotificationsHub{
		Classes: []chan PushNotification{},
	}
	for x := 0; x < PUSH_NOTIFICATION_HUB_WORKERS; x++ {
		hub.Classes = append(hub.Classes, make(chan PushNotification, PUSH_NOTIFICATIONS_HUB_BUFFER_PER_WORKER))
	}
	a.Srv().PushNotificationsHub = hub
}

func (a *App) pushNotificationWorker(notifications chan PushNotification) {
	for notification := range notifications {
		var err *model.AppError
		switch notification.notificationType {
		case notificationTypeClear:
			err = a.clearPushNotificationSync(notification.currentSessionId, notification.userId, notification.classId)
		case notificationTypeMessage:
			err = a.sendPushNotificationSync(
				notification.post,
				notification.user,
				notification.class,
				notification.className,
				notification.senderName,
				notification.explicitMention,
				notification.classWideMention,
				notification.replyToThreadType,
			)
		case notificationTypeUpdateBadge:
			err = a.updateMobileAppBadgeSync(notification.userId)
		default:
			mlog.Error("Invalid notification type", mlog.String("notification_type", string(notification.notificationType)))
		}

		if err != nil {
			mlog.Error("Unable to send push notification", mlog.String("notification_type", string(notification.notificationType)), mlog.Err(err))
		}
	}
}

func (a *App) StartPushNotificationsHubWorkers() {
	for x := 0; x < PUSH_NOTIFICATION_HUB_WORKERS; x++ {
		class := a.Srv().PushNotificationsHub.Classes[x]
		a.Srv().Go(func() { a.pushNotificationWorker(class) })
	}
}

func (a *App) StopPushNotificationsHubWorkers() {
	for _, class := range a.Srv().PushNotificationsHub.Classes {
		close(class)
	}
}

func (a *App) sendToPushProxy(msg model.PushNotification, session *model.Session) error {
	msg.ServerId = a.DiagnosticId()

	a.NotificationsLog().Info("Notification will be sent",
		mlog.String("ackId", msg.AckId),
		mlog.String("type", msg.Type),
		mlog.String("userId", session.UserId),
		mlog.String("postId", msg.PostId),
		mlog.String("status", model.PUSH_SEND_PREPARE),
	)

	url := strings.TrimRight(*a.Config().EmailSettings.PushNotificationServer, "/") + model.API_URL_SUFFIX_V1 + "/send_push"
	request, err := http.NewRequest("POST", url, strings.NewReader(msg.ToJson()))
	if err != nil {
		return err
	}

	resp, err := a.Srv().pushNotificationClient.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	pushResponse := model.PushResponseFromJson(resp.Body)

	switch pushResponse[model.PUSH_STATUS] {
	case model.PUSH_STATUS_REMOVE:
		a.AttachDeviceId(session.Id, "", session.ExpiresAt)
		a.ClearSessionCacheForUser(session.UserId)
		return errors.New("Device was reported as removed")
	case model.PUSH_STATUS_FAIL:
		return errors.New(pushResponse[model.PUSH_STATUS_ERROR_MSG])
	}
	return nil
}

func (a *App) SendAckToPushProxy(ack *model.PushNotificationAck) error {
	if ack == nil {
		return nil
	}

	a.NotificationsLog().Info("Notification received",
		mlog.String("ackId", ack.Id),
		mlog.String("type", ack.NotificationType),
		mlog.String("deviceType", ack.ClientPlatform),
		mlog.Int64("receivedAt", ack.ClientReceivedAt),
		mlog.String("status", model.PUSH_RECEIVED),
	)

	request, err := http.NewRequest(
		"POST",
		strings.TrimRight(*a.Config().EmailSettings.PushNotificationServer, "/")+model.API_URL_SUFFIX_V1+"/ack",
		strings.NewReader(ack.ToJson()),
	)

	if err != nil {
		return err
	}

	resp, err := a.HTTPService().MakeClient(true).Do(request)
	if err != nil {
		return err
	}

	resp.Body.Close()
	return nil

}

func (a *App) getMobileAppSessions(userId string) ([]*model.Session, *model.AppError) {
	return a.Srv().Store.Session().GetSessionsWithActiveDeviceIds(userId)
}

func ShouldSendPushNotification(user *model.User, classNotifyProps model.StringMap, wasMentioned bool, status *model.Status, post *model.Post) bool {
	return DoesNotifyPropsAllowPushNotification(user, classNotifyProps, post, wasMentioned) &&
		DoesStatusAllowPushNotification(user.NotifyProps, status, post.ClassId)
}

func DoesNotifyPropsAllowPushNotification(user *model.User, classNotifyProps model.StringMap, post *model.Post, wasMentioned bool) bool {
	userNotifyProps := user.NotifyProps
	userNotify := userNotifyProps[model.PUSH_NOTIFY_PROP]
	classNotify, ok := classNotifyProps[model.PUSH_NOTIFY_PROP]
	if !ok || classNotify == "" {
		classNotify = model.CLASS_NOTIFY_DEFAULT
	}

	// If the class is muted do not send push notifications
	if classNotifyProps[model.MARK_UNREAD_NOTIFY_PROP] == model.CLASS_MARK_UNREAD_MENTION {
		return false
	}

	if post.IsSystemMessage() {
		return false
	}

	if classNotify == model.USER_NOTIFY_NONE {
		return false
	}

	if classNotify == model.CLASS_NOTIFY_MENTION && !wasMentioned {
		return false
	}

	if userNotify == model.USER_NOTIFY_MENTION && classNotify == model.CLASS_NOTIFY_DEFAULT && !wasMentioned {
		return false
	}

	if (userNotify == model.USER_NOTIFY_ALL || classNotify == model.CLASS_NOTIFY_ALL) &&
		(post.UserId != user.Id || post.GetProp("from_webhook") == "true") {
		return true
	}

	if userNotify == model.USER_NOTIFY_NONE &&
		classNotify == model.CLASS_NOTIFY_DEFAULT {
		return false
	}

	return true
}

func DoesStatusAllowPushNotification(userNotifyProps model.StringMap, status *model.Status, classId string) bool {
	// If User status is DND or OOO return false right away
	if status.Status == model.STATUS_DND || status.Status == model.STATUS_OUT_OF_OFFICE {
		return false
	}

	pushStatus, ok := userNotifyProps[model.PUSH_STATUS_NOTIFY_PROP]
	if (pushStatus == model.STATUS_ONLINE || !ok) && (status.ActiveClass != classId || model.GetMillis()-status.LastActivityAt > model.STATUS_CLASS_TIMEOUT) {
		return true
	}

	if pushStatus == model.STATUS_AWAY && (status.Status == model.STATUS_AWAY || status.Status == model.STATUS_OFFLINE) {
		return true
	}

	if pushStatus == model.STATUS_OFFLINE && status.Status == model.STATUS_OFFLINE {
		return true
	}

	return false
}

func (a *App) BuildPushNotificationMessage(contentsConfig string, post *model.Post, user *model.User, class *model.Class, className string, senderName string,
	explicitMention bool, classWideMention bool, replyToThreadType string) (*model.PushNotification, *model.AppError) {

	var msg *model.PushNotification

	notificationInterface := a.Srv().Notification
	if (notificationInterface == nil || notificationInterface.CheckLicense() != nil) && contentsConfig == model.ID_LOADED_NOTIFICATION {
		contentsConfig = model.GENERIC_NOTIFICATION
	}

	if contentsConfig == model.ID_LOADED_NOTIFICATION {
		msg = a.buildIdLoadedPushNotificationMessage(post, user)
	} else {
		msg = a.buildFullPushNotificationMessage(contentsConfig, post, user, class, className, senderName, explicitMention, classWideMention, replyToThreadType)
	}

	unreadCount, err := a.Srv().Store.User().GetUnreadCount(user.Id)
	if err != nil {
		return nil, err
	}
	msg.Badge = int(unreadCount)

	return msg, nil
}

func (a *App) buildIdLoadedPushNotificationMessage(post *model.Post, user *model.User) *model.PushNotification {
	userLocale := utils.GetUserTranslations(user.Locale)
	msg := &model.PushNotification{
		PostId:     post.Id,
		ClassId:    post.ClassId,
		Category:   model.CATEGORY_CAN_REPLY,
		Version:    model.PUSH_MESSAGE_V2,
		Type:       model.PUSH_TYPE_MESSAGE,
		IsIdLoaded: true,
		SenderId:   user.Id,
		Message:    userLocale("api.push_notification.id_loaded.default_message"),
	}

	return msg
}

func (a *App) buildFullPushNotificationMessage(contentsConfig string, post *model.Post, user *model.User, class *model.Class, className string, senderName string,
	explicitMention bool, classWideMention bool, replyToThreadType string) *model.PushNotification {

	msg := &model.PushNotification{
		Category:   model.CATEGORY_CAN_REPLY,
		Version:    model.PUSH_MESSAGE_V2,
		Type:       model.PUSH_TYPE_MESSAGE,
		BranchId:   class.BranchId,
		ClassId:    class.Id,
		PostId:     post.Id,
		SenderId:   post.UserId,
		IsIdLoaded: false,
	}

	cfg := a.Config()
	if contentsConfig != model.GENERIC_NO_CLASS_NOTIFICATION {
		msg.ClassName = className
	}

	msg.SenderName = senderName
	if ou, ok := post.GetProp("override_username").(string); ok && *cfg.ServiceSettings.EnablePostUsernameOverride {
		msg.OverrideUsername = ou
		msg.SenderName = ou
	}

	if oi, ok := post.GetProp("override_icon_url").(string); ok && *cfg.ServiceSettings.EnablePostIconOverride {
		msg.OverrideIconUrl = oi
	}

	if fw, ok := post.GetProp("from_webhook").(string); ok {
		msg.FromWebhook = fw
	}

	userLocale := utils.GetUserTranslations(user.Locale)
	hasFiles := post.FileIds != nil && len(post.FileIds) > 0

	msg.Message = a.getPushNotificationMessage(contentsConfig, post.Message, explicitMention, classWideMention, hasFiles, msg.SenderName, className, replyToThreadType, userLocale)

	return msg
}
