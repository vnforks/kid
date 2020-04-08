// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"strings"

	goi18n "github.com/mattermost/go-i18n/i18n"

	"github.com/vnforks/kid/v5/model"
)

type JoinProvider struct {
}

const (
	CMD_JOIN = "join"
)

func init() {
	RegisterCommandProvider(&JoinProvider{})
}

func (me *JoinProvider) GetTrigger() string {
	return CMD_JOIN
}

func (me *JoinProvider) GetCommand(a *App, T goi18n.TranslateFunc) *model.Command {
	return &model.Command{
		Trigger:          CMD_JOIN,
		AutoComplete:     true,
		AutoCompleteDesc: T("api.command_join.desc"),
		AutoCompleteHint: T("api.command_join.hint"),
		DisplayName:      T("api.command_join.name"),
	}
}

func (me *JoinProvider) DoCommand(a *App, args *model.CommandArgs, message string) *model.CommandResponse {
	className := message

	if strings.HasPrefix(message, "~") {
		className = message[1:]
	}

	class, err := a.Srv().Store.Class().GetByName(args.BranchId, className, true)
	if err != nil {
		return &model.CommandResponse{Text: args.T("api.command_join.list.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
	}

	if class.Name != className {
		return &model.CommandResponse{ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL, Text: args.T("api.command_join.missing.app_error")}
	}

	return &model.CommandResponse{Text: args.T("api.command_join.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}

	if err = a.JoinClass(class, args.UserId); err != nil {
		return &model.CommandResponse{Text: args.T("api.command_join.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
	}

	branch, err := a.GetBranch(class.BranchId)
	if err != nil {
		return &model.CommandResponse{Text: args.T("api.command_join.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
	}

	return &model.CommandResponse{GotoLocation: args.SiteURL + "/" + branch.Name + "/classes/" + class.Name}
}
