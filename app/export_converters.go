// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"strings"

	"github.com/vnforks/kid/v5/model"
)

func ImportLineFromBranch(branch *model.BranchForExport) *LineImportData {
	return &LineImportData{
		Type: "branch",
		Branch: &BranchImportData{
			Name:        &branch.Name,
			DisplayName: &branch.DisplayName,
			Description: &branch.Description,
			Scheme:      branch.SchemeName,
		},
	}
}

func ImportLineFromClass(class *model.ClassForExport) *LineImportData {
	return &LineImportData{
		Type: "class",
		Class: &ClassImportData{
			Branch:      &class.BranchName,
			Name:        &class.Name,
			DisplayName: &class.DisplayName,
			Header:      &class.Header,
			Purpose:     &class.Purpose,
			Scheme:      class.SchemeName,
		},
	}
}

func ImportLineFromUser(user *model.User, exportedPrefs map[string]*string) *LineImportData {
	// Bulk Importer doesn't accept "empty string" for AuthService.
	var authService *string
	if user.AuthService != "" {
		authService = &user.AuthService
	}

	return &LineImportData{
		Type: "user",
		User: &UserImportData{
			Username:           &user.Username,
			Email:              &user.Email,
			AuthService:        authService,
			AuthData:           user.AuthData,
			Nickname:           &user.Nickname,
			FirstName:          &user.FirstName,
			LastName:           &user.LastName,
			Position:           &user.Position,
			Roles:              &user.Roles,
			Locale:             &user.Locale,
			UseMarkdownPreview: exportedPrefs["UseMarkdownPreview"],
			UseFormatting:      exportedPrefs["UseFormatting"],
			ShowUnreadSection:  exportedPrefs["ShowUnreadSection"],
			Theme:              exportedPrefs["Theme"],
			UseMilitaryTime:    exportedPrefs["UseMilitaryTime"],
			CollapsePreviews:   exportedPrefs["CollapsePreviews"],
			MessageDisplay:     exportedPrefs["MessageDisplay"],
			ClassDisplayMode:   exportedPrefs["ClassDisplayMode"],
			TutorialStep:       exportedPrefs["TutorialStep"],
			EmailInterval:      exportedPrefs["EmailInterval"],
			DeleteAt:           &user.DeleteAt,
		},
	}
}

func ImportUserBranchDataFromBranchMember(member *model.BranchMemberForExport) *UserBranchImportData {
	rolesList := strings.Fields(member.Roles)
	if member.SchemeAdmin {
		rolesList = append(rolesList, model.BRANCH_ADMIN_ROLE_ID)
	}
	if member.SchemeUser {
		rolesList = append(rolesList, model.BRANCH_USER_ROLE_ID)
	}
	roles := strings.Join(rolesList, " ")
	return &UserBranchImportData{
		Name:  &member.BranchName,
		Roles: &roles,
	}
}

func ImportUserClassDataFromClassMemberAndPreferences(member *model.ClassMemberForExport, preferences *model.Preferences) *UserClassImportData {
	rolesList := strings.Fields(member.Roles)
	if member.SchemeAdmin {
		rolesList = append(rolesList, model.CLASS_ADMIN_ROLE_ID)
	}
	if member.SchemeUser {
		rolesList = append(rolesList, model.CLASS_USER_ROLE_ID)
	}
	props := member.NotifyProps
	notifyProps := UserClassNotifyPropsImportData{}

	desktop, exist := props[model.DESKTOP_NOTIFY_PROP]
	if exist {
		notifyProps.Desktop = &desktop
	}
	mobile, exist := props[model.PUSH_NOTIFY_PROP]
	if exist {
		notifyProps.Mobile = &mobile
	}
	markUnread, exist := props[model.MARK_UNREAD_NOTIFY_PROP]
	if exist {
		notifyProps.MarkUnread = &markUnread
	}

	favorite := false
	for _, preference := range *preferences {
		if member.ClassId == preference.Name {
			favorite = true
		}
	}

	roles := strings.Join(rolesList, " ")
	return &UserClassImportData{
		Name:        &member.ClassName,
		Roles:       &roles,
		NotifyProps: &notifyProps,
		Favorite:    &favorite,
	}
}
