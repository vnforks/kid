// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	goi18n "github.com/mattermost/go-i18n/i18n"
	"github.com/vnforks/kid/v5/model"
)

type LeaveProvider struct {
}

const (
	CMD_LEAVE = "leave"
)

func init() {
	RegisterCommandProvider(&LeaveProvider{})
}

func (me *LeaveProvider) GetTrigger() string {
	return CMD_LEAVE
}

func (me *LeaveProvider) GetCommand(a *App, T goi18n.TranslateFunc) *model.Command {
	return &model.Command{
		Trigger:          CMD_LEAVE,
		AutoComplete:     true,
		AutoCompleteDesc: T("api.command_leave.desc"),
		DisplayName:      T("api.command_leave.name"),
	}
}

func (me *LeaveProvider) DoCommand(a *App, args *model.CommandArgs, message string) *model.CommandResponse {
	var class *model.Class
	var noClassErr *model.AppError
	if class, noClassErr = a.GetClass(args.ClassId); noClassErr != nil {
		return &model.CommandResponse{Text: args.T("api.command_leave.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
	}

	branch, err := a.GetBranch(args.BranchId)
	if err != nil {
		return &model.CommandResponse{Text: args.T("api.command_leave.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
	}

	err = a.LeaveClass(args.ClassId, args.UserId)
	if err != nil {
		if class.Name == model.DEFAULT_CLASS {
			return &model.CommandResponse{Text: args.T("api.class.leave.default.app_error", map[string]interface{}{"Class": model.DEFAULT_CLASS}), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
		}
		return &model.CommandResponse{Text: args.T("api.command_leave.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
	}

	member, err := a.GetBranchMember(branch.Id, args.UserId)
	if err != nil || member.DeleteAt != 0 {
		return &model.CommandResponse{GotoLocation: args.SiteURL + "/"}
	}

	user, err := a.GetUser(args.UserId)
	if err != nil {
		return &model.CommandResponse{Text: args.T("api.command_leave.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
	}

	if user.IsGuest() {
		members, err := a.GetClassMembersForUser(branch.Id, args.UserId)
		if err != nil || len(*members) == 0 {
			return &model.CommandResponse{Text: args.T("api.command_leave.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
		}
		class, err := a.GetClass((*members)[0].ClassId)
		if err != nil {
			return &model.CommandResponse{Text: args.T("api.command_leave.fail.app_error"), ResponseType: model.COMMAND_RESPONSE_TYPE_EPHEMERAL}
		}
		return &model.CommandResponse{GotoLocation: args.SiteURL + "/" + branch.Name + "/classes/" + class.Name}
	}

	return &model.CommandResponse{GotoLocation: args.SiteURL + "/" + branch.Name + "/classes/" + model.DEFAULT_CLASS}
}
