// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import "github.com/vnforks/kid/v5/model"

// Import Data Models

type LineImportData struct {
	Type    string            `json:"type"`
	Scheme  *SchemeImportData `json:"scheme,omitempty"`
	Branch  *BranchImportData `json:"branch,omitempty"`
	Class   *ClassImportData  `json:"class,omitempty"`
	User    *UserImportData   `json:"user,omitempty"`
	Version *int              `json:"version,omitempty"`
}

type BranchImportData struct {
	Name        *string `json:"name"`
	DisplayName *string `json:"display_name"`
	Type        *string `json:"type"`
	Description *string `json:"description,omitempty"`
	Scheme      *string `json:"scheme,omitempty"`
}

type ClassImportData struct {
	Branch      *string `json:"branch"`
	Name        *string `json:"name"`
	DisplayName *string `json:"display_name"`
	Header      *string `json:"header,omitempty"`
	Purpose     *string `json:"purpose,omitempty"`
	Scheme      *string `json:"scheme,omitempty"`
}

type UserImportData struct {
	ProfileImage       *string `json:"profile_image,omitempty"`
	Username           *string `json:"username"`
	Email              *string `json:"email"`
	AuthService        *string `json:"auth_service"`
	AuthData           *string `json:"auth_data,omitempty"`
	Password           *string `json:"password,omitempty"`
	Nickname           *string `json:"nickname"`
	FirstName          *string `json:"first_name"`
	LastName           *string `json:"last_name"`
	Position           *string `json:"position"`
	Roles              *string `json:"roles"`
	Locale             *string `json:"locale"`
	UseMarkdownPreview *string `json:"feature_enabled_markdown_preview,omitempty"`
	UseFormatting      *string `json:"formatting,omitempty"`
	ShowUnreadSection  *string `json:"show_unread_section,omitempty"`
	DeleteAt           *int64  `json:"delete_at,omitempty"`

	Branches *[]UserBranchImportData `json:"branches,omitempty"`

	Theme            *string `json:"theme,omitempty"`
	UseMilitaryTime  *string `json:"military_time,omitempty"`
	CollapsePreviews *string `json:"link_previews,omitempty"`
	MessageDisplay   *string `json:"message_display,omitempty"`
	ClassDisplayMode *string `json:"class_display_mode,omitempty"`
	TutorialStep     *string `json:"tutorial_step,omitempty"`
	EmailInterval    *string `json:"email_interval,omitempty"`

	NotifyProps *UserNotifyPropsImportData `json:"notify_props,omitempty"`
}

type UserNotifyPropsImportData struct {
	Desktop      *string `json:"desktop"`
	DesktopSound *string `json:"desktop_sound"`

	Email *string `json:"email"`

	Mobile           *string `json:"mobile"`
	MobilePushStatus *string `json:"mobile_push_status"`

	ClassTrigger    *string `json:"class"`
	CommentsTrigger *string `json:"comments"`
	MentionKeys     *string `json:"mention_keys"`
}

type UserBranchImportData struct {
	Name    *string                `json:"name"`
	Roles   *string                `json:"roles"`
	Theme   *string                `json:"theme,omitempty"`
	Classes *[]UserClassImportData `json:"classes,omitempty"`
}

type UserClassImportData struct {
	Name        *string                         `json:"name"`
	Roles       *string                         `json:"roles"`
	NotifyProps *UserClassNotifyPropsImportData `json:"notify_props,omitempty"`
	Favorite    *bool                           `json:"favorite,omitempty"`
}

type UserClassNotifyPropsImportData struct {
	Desktop    *string `json:"desktop"`
	Mobile     *string `json:"mobile"`
	MarkUnread *string `json:"mark_unread"`
}

type EmojiImportData struct {
	Name  *string `json:"name"`
	Image *string `json:"image"`
}

type ReactionImportData struct {
	User      *string `json:"user"`
	CreateAt  *int64  `json:"create_at"`
	EmojiName *string `json:"emoji_name"`
}

type ReplyImportData struct {
	User *string `json:"user"`

	Message  *string `json:"message"`
	CreateAt *int64  `json:"create_at"`

	FlaggedBy   *[]string               `json:"flagged_by,omitempty"`
	Reactions   *[]ReactionImportData   `json:"reactions,omitempty"`
	Attachments *[]AttachmentImportData `json:"attachments,omitempty"`
}

type PostImportData struct {
	Branch *string `json:"branch"`
	Class  *string `json:"class"`
	User   *string `json:"user"`

	Message  *string                `json:"message"`
	Props    *model.StringInterface `json:"props"`
	CreateAt *int64                 `json:"create_at"`

	FlaggedBy   *[]string               `json:"flagged_by,omitempty"`
	Reactions   *[]ReactionImportData   `json:"reactions,omitempty"`
	Replies     *[]ReplyImportData      `json:"replies,omitempty"`
	Attachments *[]AttachmentImportData `json:"attachments,omitempty"`
}

type DirectClassImportData struct {
	Members     *[]string `json:"members"`
	FavoritedBy *[]string `json:"favorited_by"`

	Header *string `json:"header"`
}

type DirectPostImportData struct {
	ClassMembers *[]string `json:"class_members"`
	User         *string   `json:"user"`

	Message  *string                `json:"message"`
	Props    *model.StringInterface `json:"props"`
	CreateAt *int64                 `json:"create_at"`

	FlaggedBy   *[]string               `json:"flagged_by"`
	Reactions   *[]ReactionImportData   `json:"reactions"`
	Replies     *[]ReplyImportData      `json:"replies"`
	Attachments *[]AttachmentImportData `json:"attachments"`
}

type SchemeImportData struct {
	Name                   *string         `json:"name"`
	DisplayName            *string         `json:"display_name"`
	Description            *string         `json:"description"`
	Scope                  *string         `json:"scope"`
	DefaultBranchAdminRole *RoleImportData `json:"default_branch_admin_role"`
	DefaultBranchUserRole  *RoleImportData `json:"default_branch_user_role"`
	DefaultClassAdminRole  *RoleImportData `json:"default_class_admin_role"`
	DefaultClassUserRole   *RoleImportData `json:"default_class_user_role"`
	DefaultBranchGuestRole *RoleImportData `json:"default_branch_guest_role"`
	DefaultClassGuestRole  *RoleImportData `json:"default_class_guest_role"`
}

type RoleImportData struct {
	Name        *string   `json:"name"`
	DisplayName *string   `json:"display_name"`
	Description *string   `json:"description"`
	Permissions *[]string `json:"permissions"`
}

type LineImportWorkerData struct {
	LineImportData
	LineNumber int
}

type LineImportWorkerError struct {
	Error      *model.AppError
	LineNumber int
}

type AttachmentImportData struct {
	Path *string `json:"path"`
}

type ComparablePreference struct {
	Category string
	Name     string
}
