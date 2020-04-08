// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"fmt"
	"strings"

	goi18n "github.com/mattermost/go-i18n/i18n"
	"github.com/vnforks/kid/v5/model"
)

type groupmsgProvider struct {
}

const (
	CMD_GROUPMSG = "groupmsg"
)

func init() {
	RegisterCommandProvider(&groupmsgProvider{})
}

func (me *groupmsgProvider) GetTrigger() string {
	return CMD_GROUPMSG
}

func (me *groupmsgProvider) GetCommand(a *App, T goi18n.TranslateFunc) *model.Command {
	return &model.Command{
		Trigger:          CMD_GROUPMSG,
		AutoComplete:     true,
		AutoCompleteDesc: T("api.command_groupmsg.desc"),
		AutoCompleteHint: T("api.command_groupmsg.hint"),
		DisplayName:      T("api.command_groupmsg.name"),
	}
}

func (me *groupmsgProvider) DoCommand(a *App, args *model.CommandArgs, message string) *model.CommandResponse {
	targetUsers := map[string]*model.User{}
	targetUsersSlice := []string{args.UserId}
	invalidUsernames := []string{}

	users, parsedMessage := groupMsgUsernames(message)

	for _, username := range users {
		username = strings.TrimSpace(username)
		username = strings.TrimPrefix(username, "@")
		targetUser, err := a.Srv().Store.User().GetByUsername(username)
		if err != nil {
			invalidUsernames = append(invalidUsernames, username)
			continue
		}

		canSee, err := a.UserCanSeeOtherUser(args.UserId, targetUser.Id)
		if err != nil {
			return &model.CommandResponse{Text: args.T("api.command_groupmsg.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
		}

		if !canSee {
			invalidUsernames = append(invalidUsernames, username)
			continue
		}

		_, exists := targetUsers[targetUser.Id]
		if !exists && targetUser.Id != args.UserId {
			targetUsers[targetUser.Id] = targetUser
			targetUsersSlice = append(targetUsersSlice, targetUser.Id)
		}
	}

	if len(invalidUsernames) > 0 {
		invalidUsersString := map[string]interface{}{
			"Users": "@" + strings.Join(invalidUsernames, ", @"),
		}
		return &model.CommandResponse{
			Text:         args.T("api.command_groupmsg.invalid_user.app_error", len(invalidUsernames), invalidUsersString),
			ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL,
		}
	}

	if len(targetUsersSlice) == 2 {
		return GetCommandProvider("msg").DoCommand(a, args, fmt.Sprintf("%s %s", targetUsers[targetUsersSlice[1]].Username, parsedMessage))
	}

	branch, err := a.GetBranch(args.BranchId)
	if err != nil {
		return &model.CommandResponse{Text: args.T("api.command_groupmsg.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
	}

	return &model.CommandResponse{GotoLocation: args.SiteURL + "/" + branch.Name + "/classes/", Text: "", ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
}

func groupMsgUsernames(message string) ([]string, string) {
	result := []string{}
	resultMessage := ""
	for idx, part := range strings.Split(message, ",") {
		clean := strings.TrimPrefix(strings.TrimSpace(part), "@")
		split := strings.Fields(clean)
		if len(split) > 0 {
			result = append(result, split[0])
		}
		if len(split) > 1 {
			splitted := strings.SplitN(message, ",", idx+1)
			resultMessage = strings.TrimPrefix(strings.TrimSpace(splitted[len(splitted)-1]), "@")
			resultMessage = strings.TrimSpace(strings.TrimPrefix(resultMessage, split[0]))
			break
		}
	}
	return result, resultMessage
}
