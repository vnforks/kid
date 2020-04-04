// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

const (
	CLASS_NOTIFY_DEFAULT              = "default"
	CLASS_NOTIFY_ALL                  = "all"
	CLASS_NOTIFY_MENTION              = "mention"
	CLASS_NOTIFY_NONE                 = "none"
	CLASS_MARK_UNREAD_ALL             = "all"
	CLASS_MARK_UNREAD_MENTION         = "mention"
	IGNORE_CLASS_MENTIONS_DEFAULT     = "default"
	IGNORE_CLASS_MENTIONS_OFF         = "off"
	IGNORE_CLASS_MENTIONS_ON          = "on"
	IGNORE_CLASS_MENTIONS_NOTIFY_PROP = "ignore_channel_mentions"
)

type ClassMember struct {
	ClassId       string    `json:"channel_id"`
	UserId        string    `json:"user_id"`
	Roles         string    `json:"roles"`
	NotifyProps   StringMap `json:"notify_props"`
	LastUpdateAt  int64     `json:"last_update_at"`
	SchemeUser    bool      `json:"scheme_user"`
	SchemeAdmin   bool      `json:"scheme_admin"`
	ExplicitRoles string    `json:"explicit_roles"`
}

type ClassMembers []ClassMember

type ClassMemberForExport struct {
	ClassMember
	ClassName string
	Username  string
}

func (o *ClassMembers) ToJson() string {
	if b, err := json.Marshal(o); err != nil {
		return "[]"
	} else {
		return string(b)
	}
}

func ClassMembersFromJson(data io.Reader) *ClassMembers {
	var o *ClassMembers
	json.NewDecoder(data).Decode(&o)
	return o
}

func (o *ClassMember) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func ClassMemberFromJson(data io.Reader) *ClassMember {
	var o *ClassMember
	json.NewDecoder(data).Decode(&o)
	return o
}

func (o *ClassMember) IsValid() *AppError {

	if len(o.ClassId) != 26 {
		return NewAppError("ClassMember.IsValid", "model.channel_member.is_valid.channel_id.app_error", nil, "", http.StatusBadRequest)
	}

	if len(o.UserId) != 26 {
		return NewAppError("ClassMember.IsValid", "model.channel_member.is_valid.user_id.app_error", nil, "", http.StatusBadRequest)
	}

	notifyLevel := o.NotifyProps[DESKTOP_NOTIFY_PROP]
	if len(notifyLevel) > 20 || !IsClassNotifyLevelValid(notifyLevel) {
		return NewAppError("ClassMember.IsValid", "model.channel_member.is_valid.notify_level.app_error", nil, "notify_level="+notifyLevel, http.StatusBadRequest)
	}

	if pushLevel, ok := o.NotifyProps[PUSH_NOTIFY_PROP]; ok {
		if len(pushLevel) > 20 || !IsClassNotifyLevelValid(pushLevel) {
			return NewAppError("ClassMember.IsValid", "model.channel_member.is_valid.push_level.app_error", nil, "push_notification_level="+pushLevel, http.StatusBadRequest)
		}
	}

	if sendEmail, ok := o.NotifyProps[EMAIL_NOTIFY_PROP]; ok {
		if len(sendEmail) > 20 || !IsSendEmailValid(sendEmail) {
			return NewAppError("ClassMember.IsValid", "model.channel_member.is_valid.email_value.app_error", nil, "push_notification_level="+sendEmail, http.StatusBadRequest)
		}
	}

	return nil
}

func (o *ClassMember) PreSave() {
	o.LastUpdateAt = GetMillis()
}

func (o *ClassMember) PreUpdate() {
	o.LastUpdateAt = GetMillis()
}

func (o *ClassMember) GetRoles() []string {
	return strings.Fields(o.Roles)
}

func IsClassNotifyLevelValid(notifyLevel string) bool {
	return notifyLevel == CLASS_NOTIFY_DEFAULT ||
		notifyLevel == CLASS_NOTIFY_ALL ||
		notifyLevel == CLASS_NOTIFY_MENTION ||
		notifyLevel == CLASS_NOTIFY_NONE
}

func IsSendEmailValid(sendEmail string) bool {
	return sendEmail == CLASS_NOTIFY_DEFAULT || sendEmail == "true" || sendEmail == "false"
}

func IsIgnoreClassMentionsValid(ignoreClassMentions string) bool {
	return ignoreClassMentions == IGNORE_CLASS_MENTIONS_ON || ignoreClassMentions == IGNORE_CLASS_MENTIONS_OFF || ignoreClassMentions == IGNORE_CLASS_MENTIONS_DEFAULT
}

func GetDefaultClassNotifyProps() StringMap {
	return StringMap{
		DESKTOP_NOTIFY_PROP:               CLASS_NOTIFY_DEFAULT,
		MARK_UNREAD_NOTIFY_PROP:           CLASS_MARK_UNREAD_ALL,
		PUSH_NOTIFY_PROP:                  CLASS_NOTIFY_DEFAULT,
		EMAIL_NOTIFY_PROP:                 CLASS_NOTIFY_DEFAULT,
		IGNORE_CLASS_MENTIONS_NOTIFY_PROP: IGNORE_CLASS_MENTIONS_DEFAULT,
	}
}
