// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package api4

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/vnforks/kid/v5/audit"
	"github.com/vnforks/kid/v5/model"
)

func (api *API) InitCommand() {
	api.BaseRoutes.Commands.Handle("", api.ApiSessionRequired(createCommand)).Methods("POST")
	api.BaseRoutes.Commands.Handle("", api.ApiSessionRequired(listCommands)).Methods("GET")
	api.BaseRoutes.Commands.Handle("/execute", api.ApiSessionRequired(executeCommand)).Methods("POST")

	api.BaseRoutes.Command.Handle("", api.ApiSessionRequired(getCommand)).Methods("GET")
	api.BaseRoutes.Command.Handle("", api.ApiSessionRequired(updateCommand)).Methods("PUT")
	api.BaseRoutes.Command.Handle("/move", api.ApiSessionRequired(moveCommand)).Methods("PUT")
	api.BaseRoutes.Command.Handle("", api.ApiSessionRequired(deleteCommand)).Methods("DELETE")

	api.BaseRoutes.Branch.Handle("/commands/autocomplete", api.ApiSessionRequired(listAutocompleteCommands)).Methods("GET")
	api.BaseRoutes.Command.Handle("/regen_token", api.ApiSessionRequired(regenCommandToken)).Methods("PUT")
}

func createCommand(c *Context, w http.ResponseWriter, r *http.Request) {
	cmd := model.CommandFromJson(r.Body)
	if cmd == nil {
		c.SetInvalidParam("command")
		return
	}

	auditRec := c.MakeAuditRecord("createCommand", audit.Fail)
	defer c.LogAuditRec(auditRec)
	c.LogAudit("attempt")

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), cmd.BranchId, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SLASH_COMMANDS)
		return
	}

	cmd.CreatorId = c.App.Session().UserId

	rcmd, err := c.App.CreateCommand(cmd)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	auditRec.AddMeta("command_id", rcmd.Id)
	c.LogAudit("success")

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(rcmd.ToJson()))
}

func updateCommand(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireCommandId()
	if c.Err != nil {
		return
	}

	cmd := model.CommandFromJson(r.Body)
	if cmd == nil || cmd.Id != c.Params.CommandId {
		c.SetInvalidParam("command")
		return
	}

	auditRec := c.MakeAuditRecord("updateCommand", audit.Fail)
	auditRec.AddMeta("command_id", c.Params.CommandId)
	defer c.LogAuditRec(auditRec)
	c.LogAudit("attempt")

	oldCmd, err := c.App.GetCommand(c.Params.CommandId)
	if err != nil {
		c.SetCommandNotFoundError()
		return
	}

	if cmd.BranchId != oldCmd.BranchId {
		c.Err = model.NewAppError("updateCommand", "api.command.branch_mismatch.app_error", nil, "user_id="+c.App.Session().UserId, http.StatusBadRequest)
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), oldCmd.BranchId, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
		c.LogAudit("fail - inappropriate permissions")
		// here we return Not_found instead of a permissions error so we don't leak the existence of
		// a command to someone without permissions for the branch it belongs to.
		c.SetCommandNotFoundError()
		return
	}

	if c.App.Session().UserId != oldCmd.CreatorId && !c.App.SessionHasPermissionToBranch(*c.App.Session(), oldCmd.BranchId, model.PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS) {
		c.LogAudit("fail - inappropriate permissions")
		c.SetPermissionError(model.PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS)
		return
	}

	rcmd, err := c.App.UpdateCommand(oldCmd, cmd)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("success")

	w.Write([]byte(rcmd.ToJson()))
}

func moveCommand(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireCommandId()
	if c.Err != nil {
		return
	}

	cmr, err := model.CommandMoveRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("branch_id")
		return
	}

	auditRec := c.MakeAuditRecord("moveCommand", audit.Fail)
	auditRec.AddMeta("command_id", c.Params.CommandId)
	auditRec.AddMeta("to_branch_id", cmr.BranchId)
	defer c.LogAuditRec(auditRec)
	c.LogAudit("attempt")

	newBranch, appErr := c.App.GetBranch(cmr.BranchId)
	if appErr != nil {
		c.Err = appErr
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), newBranch.Id, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
		c.LogAudit("fail - inappropriate permissions")
		c.SetPermissionError(model.PERMISSION_MANAGE_SLASH_COMMANDS)
		return
	}

	cmd, appErr := c.App.GetCommand(c.Params.CommandId)
	if appErr != nil {
		c.SetCommandNotFoundError()
		return
	}
	auditRec.AddMeta("from_branch_id", cmd.BranchId)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), cmd.BranchId, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
		c.LogAudit("fail - inappropriate permissions")
		// here we return Not_found instead of a permissions error so we don't leak the existence of
		// a command to someone without permissions for the branch it belongs to.
		c.SetCommandNotFoundError()
		return
	}

	if appErr = c.App.MoveCommand(newBranch, cmd); appErr != nil {
		c.Err = appErr
		return
	}

	auditRec.Success()
	c.LogAudit("success")

	ReturnStatusOK(w)
}

func deleteCommand(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireCommandId()
	if c.Err != nil {
		return
	}

	auditRec := c.MakeAuditRecord("deleteCommand", audit.Fail)
	auditRec.AddMeta("command_id", c.Params.CommandId)
	defer c.LogAuditRec(auditRec)
	c.LogAudit("attempt")

	cmd, err := c.App.GetCommand(c.Params.CommandId)
	if err != nil {
		c.SetCommandNotFoundError()
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), cmd.BranchId, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
		c.LogAudit("fail - inappropriate permissions")
		// here we return Not_found instead of a permissions error so we don't leak the existence of
		// a command to someone without permissions for the branch it belongs to.
		c.SetCommandNotFoundError()
		return
	}

	if c.App.Session().UserId != cmd.CreatorId && !c.App.SessionHasPermissionToBranch(*c.App.Session(), cmd.BranchId, model.PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS) {
		c.LogAudit("fail - inappropriate permissions")
		c.SetPermissionError(model.PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS)
		return
	}

	err = c.App.DeleteCommand(cmd.Id)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("success")

	ReturnStatusOK(w)
}

func listCommands(c *Context, w http.ResponseWriter, r *http.Request) {
	customOnly, failConv := strconv.ParseBool(r.URL.Query().Get("custom_only"))
	if failConv != nil {
		customOnly = false
	}

	branchId := r.URL.Query().Get("branch_id")
	if len(branchId) == 0 {
		c.SetInvalidParam("branch_id")
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), branchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	var commands []*model.Command
	var err *model.AppError
	if customOnly {
		if !c.App.SessionHasPermissionToBranch(*c.App.Session(), branchId, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
			c.SetPermissionError(model.PERMISSION_MANAGE_SLASH_COMMANDS)
			return
		}
		commands, err = c.App.ListBranchCommands(branchId)
		if err != nil {
			c.Err = err
			return
		}
	} else {
		//User with no permission should see only system commands
		if !c.App.SessionHasPermissionToBranch(*c.App.Session(), branchId, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
			commands, err = c.App.ListAutocompleteCommands(branchId, c.App.T)
			if err != nil {
				c.Err = err
				return
			}
		} else {
			commands, err = c.App.ListAllCommands(branchId, c.App.T)
			if err != nil {
				c.Err = err
				return
			}
		}
	}

	w.Write([]byte(model.CommandListToJson(commands)))
}

func getCommand(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireCommandId()
	if c.Err != nil {
		return
	}

	cmd, err := c.App.GetCommand(c.Params.CommandId)
	if err != nil {
		c.SetCommandNotFoundError()
		return
	}

	// check for permissions to view this command; must have perms to view branch and
	// PERMISSION_MANAGE_SLASH_COMMANDS for the branch the command belongs to.

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), cmd.BranchId, model.PERMISSION_VIEW_BRANCH) {
		// here we return Not_found instead of a permissions error so we don't leak the existence of
		// a command to someone without permissions for the branch it belongs to.
		c.SetCommandNotFoundError()
		return
	}
	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), cmd.BranchId, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
		// again, return not_found to ensure id existence does not leak.
		c.SetCommandNotFoundError()
		return
	}
	w.Write([]byte(cmd.ToJson()))
}

func executeCommand(c *Context, w http.ResponseWriter, r *http.Request) {
	commandArgs := model.CommandArgsFromJson(r.Body)
	if commandArgs == nil {
		c.SetInvalidParam("command_args")
		return
	}

	if len(commandArgs.Command) <= 1 || strings.Index(commandArgs.Command, "/") != 0 || len(commandArgs.ClassId) != 26 {
		c.Err = model.NewAppError("executeCommand", "api.command.execute_command.start.app_error", nil, "", http.StatusBadRequest)
		return
	}

	// checks that user is a member of the specified class, and that they have permission to use slash commands in it
	if !c.App.SessionHasPermissionToClass(*c.App.Session(), commandArgs.ClassId, model.PERMISSION_USE_SLASH_COMMANDS) {
		c.SetPermissionError(model.PERMISSION_USE_SLASH_COMMANDS)
		return
	}

	class, err := c.App.GetClass(commandArgs.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	commandArgs.BranchId = class.BranchId

	commandArgs.UserId = c.App.Session().UserId
	commandArgs.T = c.App.T
	commandArgs.Session = *c.App.Session()
	commandArgs.SiteURL = c.GetSiteURLHeader()

	response, err := c.App.ExecuteCommand(commandArgs)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(response.ToJson()))
}

func listAutocompleteCommands(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	commands, err := c.App.ListAutocompleteCommands(c.Params.BranchId, c.App.T)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(model.CommandListToJson(commands)))
}

func regenCommandToken(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireCommandId()
	if c.Err != nil {
		return
	}

	auditRec := c.MakeAuditRecord("regenCommandToken", audit.Fail)
	auditRec.AddMeta("command_id", c.Params.CommandId)
	defer c.LogAuditRec(auditRec)
	c.LogAudit("attempt")

	cmd, err := c.App.GetCommand(c.Params.CommandId)
	if err != nil {
		c.SetCommandNotFoundError()
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), cmd.BranchId, model.PERMISSION_MANAGE_SLASH_COMMANDS) {
		c.LogAudit("fail - inappropriate permissions")
		// here we return Not_found instead of a permissions error so we don't leak the existence of
		// a command to someone without permissions for the branch it belongs to.
		c.SetCommandNotFoundError()
		return
	}

	if c.App.Session().UserId != cmd.CreatorId && !c.App.SessionHasPermissionToBranch(*c.App.Session(), cmd.BranchId, model.PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS) {
		c.LogAudit("fail - inappropriate permissions")
		c.SetPermissionError(model.PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS)
		return
	}

	rcmd, err := c.App.RegenCommandToken(cmd)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("success")

	resp := make(map[string]string)
	resp["token"] = rcmd.Token

	w.Write([]byte(model.MapToJson(resp)))
}
