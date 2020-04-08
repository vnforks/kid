// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unicode"

	goi18n "github.com/mattermost/go-i18n/i18n"
	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
	"github.com/vnforks/kid/v5/utils"
)

type CommandProvider interface {
	GetTrigger() string
	GetCommand(a *App, T goi18n.TranslateFunc) *model.Command
	DoCommand(a *App, args *model.CommandArgs, message string) *model.CommandResponse
}

var commandProviders = make(map[string]CommandProvider)

func RegisterCommandProvider(newProvider CommandProvider) {
	commandProviders[newProvider.GetTrigger()] = newProvider
}

func GetCommandProvider(name string) CommandProvider {
	provider, ok := commandProviders[name]
	if ok {
		return provider
	}

	return nil
}

// @openTracingParams branchId
// previous ListCommands now ListAutocompleteCommands
func (a *App) ListAutocompleteCommands(branchId string, T goi18n.TranslateFunc) ([]*model.Command, *model.AppError) {
	commands := make([]*model.Command, 0, 32)
	seen := make(map[string]bool)
	for _, value := range commandProviders {
		if cmd := value.GetCommand(a, T); cmd != nil {
			cpy := *cmd
			if cpy.AutoComplete && !seen[cpy.Id] {
				cpy.Sanitize()
				seen[cpy.Trigger] = true
				commands = append(commands, &cpy)
			}
		}
	}

	if *a.Config().ServiceSettings.EnableCommands {
		branchCmds, err := a.Srv().Store.Command().GetByBranch(branchId)
		if err != nil {
			return nil, err
		}

		for _, cmd := range branchCmds {
			if cmd.AutoComplete && !seen[cmd.Id] {
				cmd.Sanitize()
				seen[cmd.Trigger] = true
				commands = append(commands, cmd)
			}
		}
	}

	return commands, nil
}

func (a *App) ListBranchCommands(branchId string) ([]*model.Command, *model.AppError) {
	if !*a.Config().ServiceSettings.EnableCommands {
		return nil, model.NewAppError("ListBranchCommands", "api.command.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	return a.Srv().Store.Command().GetByBranch(branchId)
}

func (a *App) ListAllCommands(branchId string, T goi18n.TranslateFunc) ([]*model.Command, *model.AppError) {
	commands := make([]*model.Command, 0, 32)
	seen := make(map[string]bool)
	for _, value := range commandProviders {
		if cmd := value.GetCommand(a, T); cmd != nil {
			cpy := *cmd
			if cpy.AutoComplete && !seen[cpy.Trigger] {
				cpy.Sanitize()
				seen[cpy.Trigger] = true
				commands = append(commands, &cpy)
			}
		}
	}

	if *a.Config().ServiceSettings.EnableCommands {
		branchCmds, err := a.Srv().Store.Command().GetByBranch(branchId)
		if err != nil {
			return nil, err
		}
		for _, cmd := range branchCmds {
			if !seen[cmd.Trigger] {
				cmd.Sanitize()
				seen[cmd.Trigger] = true
				commands = append(commands, cmd)
			}
		}
	}

	return commands, nil
}

// @openTracingParams args
func (a *App) ExecuteCommand(args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	trigger := ""
	message := ""
	index := strings.IndexFunc(args.Command, unicode.IsSpace)
	if index != -1 {
		trigger = args.Command[:index]
		message = args.Command[index+1:]
	} else {
		trigger = args.Command
	}
	trigger = strings.ToLower(trigger)
	if !strings.HasPrefix(trigger, "/") {
		return nil, model.NewAppError("command", "api.command.execute_command.format.app_error", map[string]interface{}{"Trigger": trigger}, "", http.StatusBadRequest)
	}
	trigger = strings.TrimPrefix(trigger, "/")

	clientTriggerId, triggerId, appErr := model.GenerateTriggerId(args.UserId, a.AsymmetricSigningKey())
	if appErr != nil {
		mlog.Error("error occurred in generating trigger Id for a user ", mlog.Err(appErr))
	}

	args.TriggerId = triggerId

	cmd, response := a.tryExecuteBuiltInCommand(args, trigger, message)
	if cmd != nil && response != nil {
		return a.HandleCommandResponse(cmd, args, response, true)
	}

	if cmd != nil && response != nil {
		response.TriggerId = clientTriggerId
		return a.HandleCommandResponse(cmd, args, response, true)
	}

	cmd, response, appErr = a.tryExecuteCustomCommand(args, trigger, message)
	if appErr != nil {
		return nil, appErr
	} else if cmd != nil && response != nil {
		response.TriggerId = clientTriggerId
		return a.HandleCommandResponse(cmd, args, response, false)
	}

	return nil, model.NewAppError("command", "api.command.execute_command.not_found.app_error", map[string]interface{}{"Trigger": trigger}, "", http.StatusNotFound)
}

// mentionsToBranchMembers returns all the @ mentions found in message that
// belong to users in the specified branch, linking them to their users
func (a *App) mentionsToBranchMembers(message, branchId string) model.UserMentionMap {
	type mentionMapItem struct {
		Name string
		Id   string
	}

	possibleMentions := model.PossibleAtMentions(message)
	mentionChan := make(chan *mentionMapItem, len(possibleMentions))

	var wg sync.WaitGroup
	for _, mention := range possibleMentions {
		wg.Add(1)
		go func(mention string) {
			defer wg.Done()
			user, err := a.Srv().Store.User().GetByUsername(mention)

			if err != nil && err.StatusCode != http.StatusNotFound {
				mlog.Warn("Failed to retrieve user @"+mention, mlog.Err(err))
				return
			}

			// If it's a http.StatusNotFound error, check for usernames in substrings
			// without trailing punctuation
			if err != nil {
				trimmed, ok := model.TrimUsernameSpecialChar(mention)
				for ; ok; trimmed, ok = model.TrimUsernameSpecialChar(trimmed) {
					userFromTrimmed, userErr := a.Srv().Store.User().GetByUsername(trimmed)
					if userErr != nil && err.StatusCode != http.StatusNotFound {
						return
					}

					if userErr != nil {
						continue
					}

					_, err = a.GetBranchMember(branchId, userFromTrimmed.Id)
					if err != nil {
						// The user is not in the branch, so we should ignore it
						return
					}

					mentionChan <- &mentionMapItem{trimmed, userFromTrimmed.Id}
					return
				}

				return
			}

			_, err = a.GetBranchMember(branchId, user.Id)
			if err != nil {
				// The user is not in the branch, so we should ignore it
				return
			}

			mentionChan <- &mentionMapItem{mention, user.Id}
		}(mention)
	}

	wg.Wait()
	close(mentionChan)

	atMentionMap := make(model.UserMentionMap)
	for mention := range mentionChan {
		atMentionMap[mention.Name] = mention.Id
	}

	return atMentionMap
}

// tryExecuteBuiltInCommand attempts to run a built in command based on the given arguments. If no such command can be
// found, returns nil for all arguments.
func (a *App) tryExecuteBuiltInCommand(args *model.CommandArgs, trigger string, message string) (*model.Command, *model.CommandResponse) {
	provider := GetCommandProvider(trigger)
	if provider == nil {
		return nil, nil
	}

	cmd := provider.GetCommand(a, args.T)
	if cmd == nil {
		return nil, nil
	}

	return cmd, provider.DoCommand(a, args, message)
}

// tryExecuteCustomCommand attempts to run a custom command based on the given arguments. If no such command can be
// found, returns nil for all arguments.
func (a *App) tryExecuteCustomCommand(args *model.CommandArgs, trigger string, message string) (*model.Command, *model.CommandResponse, *model.AppError) {
	// Handle custom commands
	if !*a.Config().ServiceSettings.EnableCommands {
		return nil, nil, model.NewAppError("ExecuteCommand", "api.command.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	chanChan := make(chan store.StoreResult, 1)
	go func() {
		class, err := a.Srv().Store.Class().Get(args.ClassId, true)
		chanChan <- store.StoreResult{Data: class, Err: err}
		close(chanChan)
	}()

	branchChan := make(chan store.StoreResult, 1)
	go func() {
		branch, err := a.Srv().Store.Branch().Get(args.BranchId)
		branchChan <- store.StoreResult{Data: branch, Err: err}
		close(branchChan)
	}()

	userChan := make(chan store.StoreResult, 1)
	go func() {
		user, err := a.Srv().Store.User().Get(args.UserId)
		userChan <- store.StoreResult{Data: user, Err: err}
		close(userChan)
	}()

	branchCmds, err := a.Srv().Store.Command().GetByBranch(args.BranchId)
	if err != nil {
		return nil, nil, err
	}

	tr := <-branchChan
	if tr.Err != nil {
		return nil, nil, tr.Err
	}
	branch := tr.Data.(*model.Branch)

	ur := <-userChan
	if ur.Err != nil {
		return nil, nil, ur.Err
	}
	user := ur.Data.(*model.User)

	cr := <-chanChan
	if cr.Err != nil {
		return nil, nil, cr.Err
	}
	class := cr.Data.(*model.Class)

	var cmd *model.Command

	for _, branchCmd := range branchCmds {
		if trigger == branchCmd.Trigger {
			cmd = branchCmd
		}
	}

	if cmd == nil {
		return nil, nil, nil
	}

	mlog.Debug("Executing command", mlog.String("command", trigger), mlog.String("user_id", args.UserId))

	p := url.Values{}
	p.Set("token", cmd.Token)

	p.Set("branch_id", cmd.BranchId)
	p.Set("branch_domain", branch.Name)

	p.Set("class_id", args.ClassId)
	p.Set("class_name", class.Name)

	p.Set("user_id", args.UserId)
	p.Set("user_name", user.Username)

	p.Set("command", "/"+trigger)
	p.Set("text", message)

	p.Set("trigger_id", args.TriggerId)

	userMentionMap := a.mentionsToBranchMembers(message, branch.Id)
	for key, values := range userMentionMap.ToURLValues() {
		p[key] = values
	}

	return a.doCommandRequest(cmd, p)
}

func (a *App) doCommandRequest(cmd *model.Command, p url.Values) (*model.Command, *model.CommandResponse, *model.AppError) {
	// Prepare the request
	var req *http.Request
	var err error
	if cmd.Method == model.COMMAND_METHOD_GET {
		req, err = http.NewRequest(http.MethodGet, cmd.URL, nil)
	} else {
		req, err = http.NewRequest(http.MethodPost, cmd.URL, strings.NewReader(p.Encode()))
	}

	if err != nil {
		return cmd, nil, model.NewAppError("command", "api.command.execute_command.failed.app_error", map[string]interface{}{"Trigger": cmd.Trigger}, err.Error(), http.StatusInternalServerError)
	}

	if cmd.Method == model.COMMAND_METHOD_GET {
		if req.URL.RawQuery != "" {
			req.URL.RawQuery += "&"
		}
		req.URL.RawQuery += p.Encode()
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Token "+cmd.Token)
	if cmd.Method == model.COMMAND_METHOD_POST {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Send the request
	resp, err := a.HTTPService().MakeClient(false).Do(req)
	if err != nil {
		return cmd, nil, model.NewAppError("command", "api.command.execute_command.failed.app_error", map[string]interface{}{"Trigger": cmd.Trigger}, err.Error(), http.StatusInternalServerError)
	}

	defer resp.Body.Close()

	// Handle the response
	body := io.LimitReader(resp.Body, 1024*1024)

	if resp.StatusCode != http.StatusOK {
		// Ignore the error below because the resulting string will just be the empty string if bodyBytes is nil
		bodyBytes, _ := ioutil.ReadAll(body)

		return cmd, nil, model.NewAppError("command", "api.command.execute_command.failed_resp.app_error", map[string]interface{}{"Trigger": cmd.Trigger, "Status": resp.Status}, string(bodyBytes), http.StatusInternalServerError)
	}

	response, err := model.CommandResponseFromHTTPBody(resp.Header.Get("Content-Type"), body)
	if err != nil {
		return cmd, nil, model.NewAppError("command", "api.command.execute_command.failed.app_error", map[string]interface{}{"Trigger": cmd.Trigger}, err.Error(), http.StatusInternalServerError)
	} else if response == nil {
		return cmd, nil, model.NewAppError("command", "api.command.execute_command.failed_empty.app_error", map[string]interface{}{"Trigger": cmd.Trigger}, "", http.StatusInternalServerError)
	}

	return cmd, response, nil
}

func (a *App) HandleCommandResponse(command *model.Command, args *model.CommandArgs, response *model.CommandResponse, builtIn bool) (*model.CommandResponse, *model.AppError) {
	trigger := ""
	if len(args.Command) != 0 {
		parts := strings.Split(args.Command, " ")
		trigger = parts[0][1:]
		trigger = strings.ToLower(trigger)
	}

	return response, nil
}

func (a *App) CreateCommand(cmd *model.Command) (*model.Command, *model.AppError) {
	if !*a.Config().ServiceSettings.EnableCommands {
		return nil, model.NewAppError("CreateCommand", "api.command.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	cmd.Trigger = strings.ToLower(cmd.Trigger)

	branchCmds, err := a.Srv().Store.Command().GetByBranch(cmd.BranchId)
	if err != nil {
		return nil, err
	}

	for _, existingCommand := range branchCmds {
		if cmd.Trigger == existingCommand.Trigger {
			return nil, model.NewAppError("CreateCommand", "api.command.duplicate_trigger.app_error", nil, "", http.StatusBadRequest)
		}
	}

	for _, builtInProvider := range commandProviders {
		builtInCommand := builtInProvider.GetCommand(a, utils.T)
		if builtInCommand != nil && cmd.Trigger == builtInCommand.Trigger {
			return nil, model.NewAppError("CreateCommand", "api.command.duplicate_trigger.app_error", nil, "", http.StatusBadRequest)
		}
	}

	return a.Srv().Store.Command().Save(cmd)
}

func (a *App) GetCommand(commandId string) (*model.Command, *model.AppError) {
	if !*a.Config().ServiceSettings.EnableCommands {
		return nil, model.NewAppError("GetCommand", "api.command.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	cmd, err := a.Srv().Store.Command().Get(commandId)
	if err != nil {
		err.StatusCode = http.StatusNotFound
		return nil, err
	}

	return cmd, nil
}

func (a *App) UpdateCommand(oldCmd, updatedCmd *model.Command) (*model.Command, *model.AppError) {
	if !*a.Config().ServiceSettings.EnableCommands {
		return nil, model.NewAppError("UpdateCommand", "api.command.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	updatedCmd.Trigger = strings.ToLower(updatedCmd.Trigger)
	updatedCmd.Id = oldCmd.Id
	updatedCmd.Token = oldCmd.Token
	updatedCmd.CreateAt = oldCmd.CreateAt
	updatedCmd.UpdateAt = model.GetMillis()
	updatedCmd.DeleteAt = oldCmd.DeleteAt
	updatedCmd.CreatorId = oldCmd.CreatorId
	updatedCmd.BranchId = oldCmd.BranchId

	return a.Srv().Store.Command().Update(updatedCmd)
}

func (a *App) MoveCommand(branch *model.Branch, command *model.Command) *model.AppError {
	command.BranchId = branch.Id

	_, err := a.Srv().Store.Command().Update(command)
	if err != nil {
		return err
	}

	return nil
}

func (a *App) RegenCommandToken(cmd *model.Command) (*model.Command, *model.AppError) {
	if !*a.Config().ServiceSettings.EnableCommands {
		return nil, model.NewAppError("RegenCommandToken", "api.command.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	cmd.Token = model.NewId()

	return a.Srv().Store.Command().Update(cmd)
}

func (a *App) DeleteCommand(commandId string) *model.AppError {
	if !*a.Config().ServiceSettings.EnableCommands {
		return model.NewAppError("DeleteCommand", "api.command.disabled.app_error", nil, "", http.StatusNotImplemented)
	}

	return a.Srv().Store.Command().Delete(commandId, model.GetMillis())
}
