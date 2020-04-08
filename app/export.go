// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
)

// We use this map to identify the exportable preferences.
// Here we link the preference category and name, to the name of the relevant field in the import struct.
var exportablePreferences = map[ComparablePreference]string{{
	Category: model.PREFERENCE_CATEGORY_THEME,
	Name:     "",
}: "Theme", {
	Category: model.PREFERENCE_CATEGORY_ADVANCED_SETTINGS,
	Name:     "feature_enabled_markdown_preview",
}: "UseMarkdownPreview", {
	Category: model.PREFERENCE_CATEGORY_ADVANCED_SETTINGS,
	Name:     "formatting",
}: "UseFormatting", {
	Category: model.PREFERENCE_CATEGORY_SIDEBAR_SETTINGS,
	Name:     "show_unread_section",
}: "ShowUnreadSection", {
	Category: model.PREFERENCE_CATEGORY_DISPLAY_SETTINGS,
	Name:     model.PREFERENCE_NAME_USE_MILITARY_TIME,
}: "UseMilitaryTime", {
	Category: model.PREFERENCE_CATEGORY_DISPLAY_SETTINGS,
	Name:     model.PREFERENCE_NAME_COLLAPSE_SETTING,
}: "CollapsePreviews", {
	Category: model.PREFERENCE_CATEGORY_DISPLAY_SETTINGS,
	Name:     model.PREFERENCE_NAME_MESSAGE_DISPLAY,
}: "MessageDisplay", {
	Category: model.PREFERENCE_CATEGORY_DISPLAY_SETTINGS,
	Name:     "class_display_mode",
}: "ClassDisplayMode", {
	Category: model.PREFERENCE_CATEGORY_TUTORIAL_STEPS,
	Name:     "",
}: "TutorialStep", {
	Category: model.PREFERENCE_CATEGORY_NOTIFICATIONS,
	Name:     model.PREFERENCE_NAME_EMAIL_INTERVAL,
}: "EmailInterval",
}

func (a *App) BulkExport(writer io.Writer, file string, pathToEmojiDir string, dirNameToExportEmoji string) *model.AppError {
	mlog.Info("Bulk export: exporting version")
	if err := a.exportVersion(writer); err != nil {
		return err
	}

	mlog.Info("Bulk export: exporting branches")
	if err := a.exportAllBranches(writer); err != nil {
		return err
	}

	mlog.Info("Bulk export: exporting classes")
	if err := a.exportAllClasses(writer); err != nil {
		return err
	}

	mlog.Info("Bulk export: exporting users")
	if err := a.exportAllUsers(writer); err != nil {
		return err
	}

	return nil
}

func (a *App) exportWriteLine(writer io.Writer, line *LineImportData) *model.AppError {
	b, err := json.Marshal(line)
	if err != nil {
		return model.NewAppError("BulkExport", "app.export.export_write_line.json_marshall.error", nil, "err="+err.Error(), http.StatusBadRequest)
	}

	if _, err := writer.Write(append(b, '\n')); err != nil {
		return model.NewAppError("BulkExport", "app.export.export_write_line.io_writer.error", nil, "err="+err.Error(), http.StatusBadRequest)
	}

	return nil
}

func (a *App) exportVersion(writer io.Writer) *model.AppError {
	version := 1
	versionLine := &LineImportData{
		Type:    "version",
		Version: &version,
	}

	return a.exportWriteLine(writer, versionLine)
}

func (a *App) exportAllBranches(writer io.Writer) *model.AppError {
	afterId := strings.Repeat("0", 26)
	for {
		branches, err := a.Srv().Store.Branch().GetAllForExportAfter(1000, afterId)

		if err != nil {
			return err
		}

		if len(branches) == 0 {
			break
		}

		for _, branch := range branches {
			afterId = branch.Id

			// Skip deleted.
			if branch.DeleteAt != 0 {
				continue
			}

			branchLine := ImportLineFromBranch(branch)
			if err := a.exportWriteLine(writer, branchLine); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *App) exportAllClasses(writer io.Writer) *model.AppError {
	afterId := strings.Repeat("0", 26)
	for {
		classes, err := a.Srv().Store.Class().GetAllClassesForExportAfter(1000, afterId)

		if err != nil {
			return err
		}

		if len(classes) == 0 {
			break
		}

		for _, class := range classes {
			afterId = class.Id

			// Skip deleted.
			if class.DeleteAt != 0 {
				continue
			}

			classLine := ImportLineFromClass(class)
			if err := a.exportWriteLine(writer, classLine); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *App) exportAllUsers(writer io.Writer) *model.AppError {
	afterId := strings.Repeat("0", 26)
	for {
		users, err := a.Srv().Store.User().GetAllAfter(1000, afterId)

		if err != nil {
			return err
		}

		if len(users) == 0 {
			break
		}

		for _, user := range users {
			afterId = user.Id

			// Gathering here the exportable preferences to pass them on to ImportLineFromUser
			exportedPrefs := make(map[string]*string)
			allPrefs, err := a.GetPreferencesForUser(user.Id)
			if err != nil {
				return err
			}
			for _, pref := range allPrefs {
				// We need to manage the special cases
				// Here we manage Tutorial steps
				if pref.Category == model.PREFERENCE_CATEGORY_TUTORIAL_STEPS {
					pref.Name = ""
					// Then the email interval
				} else if pref.Category == model.PREFERENCE_CATEGORY_NOTIFICATIONS && pref.Name == model.PREFERENCE_NAME_EMAIL_INTERVAL {
					switch pref.Value {
					case model.PREFERENCE_EMAIL_INTERVAL_NO_BATCHING_SECONDS:
						pref.Value = model.PREFERENCE_EMAIL_INTERVAL_IMMEDIATELY
					case model.PREFERENCE_EMAIL_INTERVAL_FIFTEEN_AS_SECONDS:
						pref.Value = model.PREFERENCE_EMAIL_INTERVAL_FIFTEEN
					case model.PREFERENCE_EMAIL_INTERVAL_HOUR_AS_SECONDS:
						pref.Value = model.PREFERENCE_EMAIL_INTERVAL_HOUR
					case "0":
						pref.Value = ""
					}
				}
				id, ok := exportablePreferences[ComparablePreference{
					Category: pref.Category,
					Name:     pref.Name,
				}]
				if ok {
					prefPtr := pref.Value
					if prefPtr != "" {
						exportedPrefs[id] = &prefPtr
					} else {
						exportedPrefs[id] = nil
					}
				}
			}

			userLine := ImportLineFromUser(user, exportedPrefs)

			userLine.User.NotifyProps = a.buildUserNotifyProps(user.NotifyProps)

			// Do the Branch Memberships.
			members, err := a.buildUserBranchAndClassMemberships(user.Id)
			if err != nil {
				return err
			}

			userLine.User.Branches = members

			if err := a.exportWriteLine(writer, userLine); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *App) buildUserBranchAndClassMemberships(userId string) (*[]UserBranchImportData, *model.AppError) {
	var memberships []UserBranchImportData

	members, err := a.Srv().Store.Branch().GetBranchMembersForExport(userId)

	if err != nil {
		return nil, err
	}

	for _, member := range members {
		// Skip deleted.
		if member.DeleteAt != 0 {
			continue
		}

		memberData := ImportUserBranchDataFromBranchMember(member)

		// Do the Class Memberships.
		classMembers, err := a.buildUserClassMemberships(userId, member.BranchId)
		if err != nil {
			return nil, err
		}

		// Get the user theme
		themePreference, err := a.Srv().Store.Preference().Get(member.UserId, model.PREFERENCE_CATEGORY_THEME, member.BranchId)
		if err == nil {
			memberData.Theme = &themePreference.Value
		}

		memberData.Classes = classMembers

		memberships = append(memberships, *memberData)
	}

	return &memberships, nil
}

func (a *App) buildUserClassMemberships(userId string, branchId string) (*[]UserClassImportData, *model.AppError) {
	var memberships []UserClassImportData

	members, err := a.Srv().Store.Class().GetClassMembersForExport(userId, branchId)
	if err != nil {
		return nil, err
	}

	category := model.PREFERENCE_CATEGORY_FAVORITE_CLASS
	preferences, err := a.GetPreferenceByCategoryForUser(userId, category)
	if err != nil && err.StatusCode != http.StatusNotFound {
		return nil, err
	}

	for _, member := range members {
		memberships = append(memberships, *ImportUserClassDataFromClassMemberAndPreferences(member, &preferences))
	}
	return &memberships, nil
}

func (a *App) buildUserNotifyProps(notifyProps model.StringMap) *UserNotifyPropsImportData {

	getProp := func(key string) *string {
		if v, ok := notifyProps[key]; ok {
			return &v
		}
		return nil
	}

	return &UserNotifyPropsImportData{
		Desktop:          getProp(model.DESKTOP_NOTIFY_PROP),
		DesktopSound:     getProp(model.DESKTOP_SOUND_NOTIFY_PROP),
		Email:            getProp(model.EMAIL_NOTIFY_PROP),
		Mobile:           getProp(model.PUSH_NOTIFY_PROP),
		MobilePushStatus: getProp(model.PUSH_STATUS_NOTIFY_PROP),
		ClassTrigger:     getProp(model.PUSH_NOTIFY_PROP),
		CommentsTrigger:  getProp(model.COMMENTS_NOTIFY_PROP),
		MentionKeys:      getProp(model.MENTION_KEYS_NOTIFY_PROP),
	}
}
