// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/disintegration/imaging"
	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

func (a *App) CreateBranch(branch *model.Branch) (*model.Branch, *model.AppError) {
	rbranch, err := a.Srv().Store.Branch().Save(branch)
	if err != nil {
		return nil, err
	}

	if _, err := a.CreateDefaultClasses(rbranch.Id); err != nil {
		return nil, err
	}

	return rbranch, nil
}

func (a *App) CreateBranchWithUser(branch *model.Branch, userId string) (*model.Branch, *model.AppError) {
	user, err := a.GetUser(userId)
	if err != nil {
		return nil, err
	}
	branch.Email = user.Email

	rbranch, err := a.CreateBranch(branch)
	if err != nil {
		return nil, err
	}

	if err = a.JoinUserToBranch(rbranch, user, ""); err != nil {
		return nil, err
	}

	return rbranch, nil
}

func (a *App) UpdateBranch(branch *model.Branch) (*model.Branch, *model.AppError) {
	oldBranch, err := a.GetBranch(branch.Id)
	if err != nil {
		return nil, err
	}

	oldBranch.DisplayName = branch.DisplayName
	oldBranch.Description = branch.Description
	oldBranch.LastBranchIconUpdate = branch.LastBranchIconUpdate

	oldBranch, err = a.updateBranchUnsanitized(oldBranch)
	if err != nil {
		return branch, err
	}

	a.sendBranchEvent(oldBranch, model.WEBSOCKET_EVENT_UPDATE_BRANCH)

	return oldBranch, nil
}

func (a *App) updateBranchUnsanitized(branch *model.Branch) (*model.Branch, *model.AppError) {
	return a.Srv().Store.Branch().Update(branch)
}

// RenameBranch is used to rename the branch Name and the DisplayName fields
func (a *App) RenameBranch(branch *model.Branch, newBranchName string, newDisplayName string) (*model.Branch, *model.AppError) {

	// check if name is occupied
	_, errnf := a.GetBranchByName(newBranchName)

	// "-" can be used as a newBranchName if only DisplayName change is wanted
	if errnf == nil && newBranchName != "-" {
		errbody := fmt.Sprintf("branch with name %s already exists", newBranchName)
		return nil, model.NewAppError("RenameBranch", "app.branch.rename_branch.name_occupied", nil, errbody, http.StatusBadRequest)
	}

	if newBranchName != "-" {
		branch.Name = newBranchName
	}

	if newDisplayName != "" {
		branch.DisplayName = newDisplayName
	}

	newBranch, err := a.updateBranchUnsanitized(branch)
	if err != nil {
		return nil, err
	}

	return newBranch, nil
}

func (a *App) UpdateBranchScheme(branch *model.Branch) (*model.Branch, *model.AppError) {
	oldBranch, err := a.GetBranch(branch.Id)
	if err != nil {
		return nil, err
	}

	oldBranch.SchemeId = branch.SchemeId

	if oldBranch, err = a.Srv().Store.Branch().Update(oldBranch); err != nil {
		return nil, err
	}

	a.sendBranchEvent(oldBranch, model.WEBSOCKET_EVENT_UPDATE_BRANCH)

	return oldBranch, nil
}

func (a *App) PatchBranch(branchId string, patch *model.BranchPatch) (*model.Branch, *model.AppError) {
	branch, err := a.GetBranch(branchId)
	if err != nil {
		return nil, err
	}

	branch.Patch(patch)

	updatedBranch, err := a.UpdateBranch(branch)
	if err != nil {
		return nil, err
	}

	a.sendBranchEvent(updatedBranch, model.WEBSOCKET_EVENT_UPDATE_BRANCH)

	return updatedBranch, nil
}

func (a *App) sendBranchEvent(branch *model.Branch, event string) {
	sanitizedBranch := &model.Branch{}
	*sanitizedBranch = *branch
	sanitizedBranch.Sanitize()

	branchId := "" // no filtering by branchId by default
	if event == model.WEBSOCKET_EVENT_UPDATE_BRANCH {
		// in case of update_branch event - we send the message only to members of that branch
		branchId = branch.Id
	}
	message := model.NewWebSocketEvent(event, branchId, "", "", nil)
	message.Add("branch", sanitizedBranch.ToJson())
	a.Publish(message)
}

func (a *App) GetSchemeRolesForBranch(branchId string) (string, string, *model.AppError) {
	branch, err := a.GetBranch(branchId)
	if err != nil {
		return "", "", err
	}

	if branch.SchemeId != nil && len(*branch.SchemeId) != 0 {
		scheme, err := a.GetScheme(*branch.SchemeId)
		if err != nil {
			return "", "", err
		}
		return scheme.DefaultBranchUserRole, scheme.DefaultBranchAdminRole, nil
	}

	return model.BRANCH_USER_ROLE_ID, model.BRANCH_ADMIN_ROLE_ID, nil
}

func (a *App) UpdateBranchMemberRoles(branchId string, userId string, newRoles string) (*model.BranchMember, *model.AppError) {
	member, err := a.Srv().Store.Branch().GetMember(branchId, userId)
	if err != nil {
		return nil, err
	}

	if member == nil {
		err = model.NewAppError("UpdateBranchMemberRoles", "api.branch.update_member_roles.not_a_member", nil, "userId="+userId+" branchId="+branchId, http.StatusBadRequest)
		return nil, err
	}

	schemeUserRole, schemeAdminRole, err := a.GetSchemeRolesForBranch(branchId)
	if err != nil {
		return nil, err
	}

	var newExplicitRoles []string
	member.SchemeUser = false
	member.SchemeAdmin = false

	for _, roleName := range strings.Fields(newRoles) {
		var role *model.Role
		role, err = a.GetRoleByName(roleName)
		if err != nil {
			err.StatusCode = http.StatusBadRequest
			return nil, err
		}
		if !role.SchemeManaged {
			// The role is not scheme-managed, so it's OK to apply it to the explicit roles field.
			newExplicitRoles = append(newExplicitRoles, roleName)
		} else {
			// The role is scheme-managed, so need to check if it is part of the scheme for this class or not.
			switch roleName {
			case schemeAdminRole:
				member.SchemeAdmin = true
			case schemeUserRole:
				member.SchemeUser = true
			default:
				// If not part of the scheme for this branch, then it is not allowed to apply it as an explicit role.
				return nil, model.NewAppError("UpdateBranchMemberRoles", "api.class.update_branch_member_roles.scheme_role.app_error", nil, "role_name="+roleName, http.StatusBadRequest)
			}
		}
	}

	member.ExplicitRoles = strings.Join(newExplicitRoles, " ")

	member, err = a.Srv().Store.Branch().UpdateMember(member)
	if err != nil {
		return nil, err
	}

	a.ClearSessionCacheForUser(userId)

	a.sendUpdatedMemberRoleEvent(userId, member)

	return member, nil
}

func (a *App) UpdateBranchMemberSchemeRoles(branchId string, userId string, isSchemeUser bool, isSchemeAdmin bool) (*model.BranchMember, *model.AppError) {
	member, err := a.GetBranchMember(branchId, userId)
	if err != nil {
		return nil, err
	}

	member.SchemeAdmin = isSchemeAdmin
	member.SchemeUser = isSchemeUser

	// If the migration is not completed, we also need to check the default branch_admin/branch_user roles are not present in the roles field.
	if err = a.IsPhase2MigrationCompleted(); err != nil {
		member.ExplicitRoles = RemoveRoles([]string{model.BRANCH_USER_ROLE_ID, model.BRANCH_ADMIN_ROLE_ID}, member.ExplicitRoles)
	}

	member, err = a.Srv().Store.Branch().UpdateMember(member)
	if err != nil {
		return nil, err
	}

	a.ClearSessionCacheForUser(userId)

	a.sendUpdatedMemberRoleEvent(userId, member)

	return member, nil
}

func (a *App) sendUpdatedMemberRoleEvent(userId string, member *model.BranchMember) {
	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_MEMBERROLE_UPDATED, "", "", userId, nil)
	message.Add("member", member.ToJson())
	a.Publish(message)
}

func (a *App) AddUserToBranch(branchId string, userId string, userRequestorId string) (*model.Branch, *model.AppError) {
	tchan := make(chan store.StoreResult, 1)
	go func() {
		branch, err := a.Srv().Store.Branch().Get(branchId)
		tchan <- store.StoreResult{Data: branch, Err: err}
		close(tchan)
	}()

	uchan := make(chan store.StoreResult, 1)
	go func() {
		user, err := a.Srv().Store.User().Get(userId)
		uchan <- store.StoreResult{Data: user, Err: err}
		close(uchan)
	}()

	result := <-tchan
	if result.Err != nil {
		return nil, result.Err
	}
	branch := result.Data.(*model.Branch)

	result = <-uchan
	if result.Err != nil {
		return nil, result.Err
	}
	user := result.Data.(*model.User)

	if err := a.JoinUserToBranch(branch, user, userRequestorId); err != nil {
		return nil, err
	}

	return branch, nil
}

func (a *App) AddUserToBranchByBranchId(branchId string, user *model.User) *model.AppError {
	branch, err := a.Srv().Store.Branch().Get(branchId)
	if err != nil {
		return err
	}

	return a.JoinUserToBranch(branch, user, "")
}

func (a *App) AddUserToBranchByToken(userId string, tokenId string) (*model.Branch, *model.AppError) {
	token, err := a.Srv().Store.Token().GetByToken(tokenId)
	if err != nil {
		return nil, model.NewAppError("AddUserToBranchByToken", "api.user.create_user.signup_link_invalid.app_error", nil, err.Error(), http.StatusBadRequest)
	}

	if token.Type != TOKEN_TYPE_BRANCH_INVITATION && token.Type != TOKEN_TYPE_GUEST_INVITATION {
		return nil, model.NewAppError("AddUserToBranchByToken", "api.user.create_user.signup_link_invalid.app_error", nil, "", http.StatusBadRequest)
	}

	if model.GetMillis()-token.CreateAt >= INVITATION_EXPIRY_TIME {
		a.DeleteToken(token)
		return nil, model.NewAppError("AddUserToBranchByToken", "api.user.create_user.signup_link_expired.app_error", nil, "", http.StatusBadRequest)
	}

	tokenData := model.MapFromJson(strings.NewReader(token.Extra))

	tchan := make(chan store.StoreResult, 1)
	go func() {
		branch, err := a.Srv().Store.Branch().Get(tokenData["branchId"])
		tchan <- store.StoreResult{Data: branch, Err: err}
		close(tchan)
	}()

	uchan := make(chan store.StoreResult, 1)
	go func() {
		user, err := a.Srv().Store.User().Get(userId)
		uchan <- store.StoreResult{Data: user, Err: err}
		close(uchan)
	}()

	result := <-tchan
	if result.Err != nil {
		return nil, result.Err
	}
	branch := result.Data.(*model.Branch)

	result = <-uchan
	if result.Err != nil {
		return nil, result.Err
	}
	user := result.Data.(*model.User)

	if user.IsGuest() && token.Type == TOKEN_TYPE_BRANCH_INVITATION {
		return nil, model.NewAppError("AddUserToBranchByToken", "api.user.create_user.invalid_invitation_type.app_error", nil, "", http.StatusBadRequest)
	}
	if !user.IsGuest() && token.Type == TOKEN_TYPE_GUEST_INVITATION {
		return nil, model.NewAppError("AddUserToBranchByToken", "api.user.create_user.invalid_invitation_type.app_error", nil, "", http.StatusBadRequest)
	}

	if err := a.JoinUserToBranch(branch, user, ""); err != nil {
		return nil, err
	}

	if token.Type == TOKEN_TYPE_GUEST_INVITATION {
		classes, err := a.Srv().Store.Class().GetClassesByIds(strings.Split(tokenData["classes"], " "), false)
		if err != nil {
			return nil, err
		}

		for _, class := range classes {
			_, err := a.AddUserToClass(user, class)
			if err != nil {
				mlog.Error("error adding user to class", mlog.Err(err))
			}
		}
	}

	if err := a.DeleteToken(token); err != nil {
		return nil, err
	}

	return branch, nil
}

// Returns three values:
// 1. a pointer to the branch member, if successful
// 2. a boolean: true if the user has a non-deleted branch member for that branch already, otherwise false.
// 3. a pointer to an AppError if something went wrong.
func (a *App) joinUserToBranch(branch *model.Branch, user *model.User) (*model.BranchMember, bool, *model.AppError) {
	tm := &model.BranchMember{
		BranchId:   branch.Id,
		UserId:     user.Id,
		SchemeUser: true,
	}

	if branch.Email == user.Email {
		tm.SchemeAdmin = true
	}

	rtm, err := a.Srv().Store.Branch().GetMember(branch.Id, user.Id)
	if err != nil {
		// Membership appears to be missing. Lets try to add.
		var tmr *model.BranchMember
		tmr, err = a.Srv().Store.Branch().SaveMember(tm, *a.Config().BranchSettings.MaxUsersPerBranch)
		if err != nil {
			return nil, false, err
		}
		return tmr, false, nil
	}

	// Membership already exists.  Check if deleted and update, otherwise do nothing
	// Do nothing if already added
	if rtm.DeleteAt == 0 {
		return rtm, true, nil
	}

	membersCount, err := a.Srv().Store.Branch().GetActiveMemberCount(tm.BranchId, nil)
	if err != nil {
		return nil, false, err
	}

	if membersCount >= int64(*a.Config().BranchSettings.MaxUsersPerBranch) {
		return nil, false, model.NewAppError("joinUserToBranch", "app.branch.join_user_to_branch.max_accounts.app_error", nil, "branchId="+tm.BranchId, http.StatusBadRequest)
	}

	member, err := a.Srv().Store.Branch().UpdateMember(tm)
	if err != nil {
		return nil, false, err
	}

	return member, false, nil
}

func (a *App) JoinUserToBranch(branch *model.Branch, user *model.User, userRequestorId string) *model.AppError {
	_, alreadyAdded, err := a.joinUserToBranch(branch, user)
	if err != nil {
		return err
	}
	if alreadyAdded {
		return nil
	}

	if _, err := a.Srv().Store.User().UpdateUpdateAt(user.Id); err != nil {
		return err
	}

	shouldBeAdmin := branch.Email == user.Email

	if !user.IsGuest() {
		// Soft error if there is an issue joining the default classes
		if err := a.JoinDefaultClasses(branch.Id, user, shouldBeAdmin, userRequestorId); err != nil {
			mlog.Error(
				"Encountered an issue joining default classes.",
				mlog.String("user_id", user.Id),
				mlog.String("branch_id", branch.Id),
				mlog.Err(err),
			)
		}
	}

	a.ClearSessionCacheForUser(user.Id)
	a.InvalidateCacheForUser(user.Id)
	a.invalidateCacheForUserBranches(user.Id)

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_ADDED_TO_BRANCH, "", "", user.Id, nil)
	message.Add("branch_id", branch.Id)
	message.Add("user_id", user.Id)
	a.Publish(message)

	return nil
}

func (a *App) GetBranch(branchId string) (*model.Branch, *model.AppError) {
	return a.Srv().Store.Branch().Get(branchId)
}

func (a *App) GetBranchByName(name string) (*model.Branch, *model.AppError) {
	return a.Srv().Store.Branch().GetByName(name)
}

func (a *App) GetAllBranches() ([]*model.Branch, *model.AppError) {
	return a.Srv().Store.Branch().GetAll()
}

func (a *App) GetAllBranchesPage(offset int, limit int) ([]*model.Branch, *model.AppError) {
	return a.Srv().Store.Branch().GetAllPage(offset, limit)
}

func (a *App) GetAllBranchesPageWithCount(offset int, limit int) (*model.BranchesWithCount, *model.AppError) {
	totalCount, err := a.Srv().Store.Branch().AnalyticsBranchCount(true)
	if err != nil {
		return nil, err
	}
	branches, err := a.Srv().Store.Branch().GetAllPage(offset, limit)
	if err != nil {
		return nil, err
	}
	return &model.BranchesWithCount{Branches: branches, TotalCount: totalCount}, nil
}

func (a *App) GetBranchesForUser(userId string) ([]*model.Branch, *model.AppError) {
	return a.Srv().Store.Branch().GetBranchesByUserId(userId)
}

func (a *App) GetBranchMember(branchId, userId string) (*model.BranchMember, *model.AppError) {
	return a.Srv().Store.Branch().GetMember(branchId, userId)
}

func (a *App) GetBranchMembersForUser(userId string) ([]*model.BranchMember, *model.AppError) {
	return a.Srv().Store.Branch().GetBranchesForUser(userId)
}

func (a *App) GetBranchMembersForUserWithPagination(userId string, page, perPage int) ([]*model.BranchMember, *model.AppError) {
	return a.Srv().Store.Branch().GetBranchesForUserWithPagination(userId, page, perPage)
}

func (a *App) GetBranchMembers(branchId string, offset int, limit int, branchMembersGetOptions *model.BranchMembersGetOptions) ([]*model.BranchMember, *model.AppError) {
	return a.Srv().Store.Branch().GetMembers(branchId, offset, limit, branchMembersGetOptions)
}

func (a *App) GetBranchMembersByIds(branchId string, userIds []string, restrictions *model.ViewUsersRestrictions) ([]*model.BranchMember, *model.AppError) {
	return a.Srv().Store.Branch().GetMembersByIds(branchId, userIds, restrictions)
}

func (a *App) AddBranchMember(branchId, userId string) (*model.BranchMember, *model.AppError) {
	if _, err := a.AddUserToBranch(branchId, userId, ""); err != nil {
		return nil, err
	}

	branchMember, err := a.GetBranchMember(branchId, userId)
	if err != nil {
		return nil, err
	}

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_ADDED_TO_BRANCH, "", "", userId, nil)
	message.Add("branch_id", branchId)
	message.Add("user_id", userId)
	a.Publish(message)

	return branchMember, nil
}

func (a *App) AddBranchMembers(branchId string, userIds []string, userRequestorId string, graceful bool) ([]*model.BranchMemberWithError, *model.AppError) {
	var membersWithErrors []*model.BranchMemberWithError

	for _, userId := range userIds {
		if _, err := a.AddUserToBranch(branchId, userId, userRequestorId); err != nil {
			if graceful {
				membersWithErrors = append(membersWithErrors, &model.BranchMemberWithError{
					UserId: userId,
					Error:  err,
				})
				continue
			}
			return nil, err
		}

		branchMember, err := a.GetBranchMember(branchId, userId)
		if err != nil {
			return nil, err
		}
		membersWithErrors = append(membersWithErrors, &model.BranchMemberWithError{
			UserId: userId,
			Member: branchMember,
		})

		message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_ADDED_TO_BRANCH, "", "", userId, nil)
		message.Add("branch_id", branchId)
		message.Add("user_id", userId)
		a.Publish(message)
	}

	return membersWithErrors, nil
}

func (a *App) AddBranchMemberByToken(userId, tokenId string) (*model.BranchMember, *model.AppError) {
	branch, err := a.AddUserToBranchByToken(userId, tokenId)
	if err != nil {
		return nil, err
	}

	branchMember, err := a.GetBranchMember(branch.Id, userId)
	if err != nil {
		return nil, err
	}

	return branchMember, nil
}

func (a *App) RemoveUserFromBranch(branchId string, userId string, requestorId string) *model.AppError {
	tchan := make(chan store.StoreResult, 1)
	go func() {
		branch, err := a.Srv().Store.Branch().Get(branchId)
		tchan <- store.StoreResult{Data: branch, Err: err}
		close(tchan)
	}()

	uchan := make(chan store.StoreResult, 1)
	go func() {
		user, err := a.Srv().Store.User().Get(userId)
		uchan <- store.StoreResult{Data: user, Err: err}
		close(uchan)
	}()

	result := <-tchan
	if result.Err != nil {
		return result.Err
	}
	branch := result.Data.(*model.Branch)

	result = <-uchan
	if result.Err != nil {
		return result.Err
	}
	user := result.Data.(*model.User)

	if err := a.LeaveBranch(branch, user, requestorId); err != nil {
		return err
	}

	return nil
}

func (a *App) RemoveBranchMemberFromBranch(branchMember *model.BranchMember, requestorId string) *model.AppError {
	// Send the websocket message before we actually do the remove so the user being removed gets it.
	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_LEAVE_BRANCH, branchMember.BranchId, "", "", nil)
	message.Add("user_id", branchMember.UserId)
	message.Add("branch_id", branchMember.BranchId)
	a.Publish(message)

	user, err := a.Srv().Store.User().Get(branchMember.UserId)
	if err != nil {
		return err
	}

	branchMember.Roles = ""
	branchMember.DeleteAt = model.GetMillis()

	if _, err := a.Srv().Store.Branch().UpdateMember(branchMember); err != nil {
		return err
	}

	if _, err := a.Srv().Store.User().UpdateUpdateAt(user.Id); err != nil {
		return err
	}

	// delete the preferences that set the last class used in the branch and other branch specific preferences
	if err := a.Srv().Store.Preference().DeleteCategory(user.Id, branchMember.BranchId); err != nil {
		return err
	}

	a.ClearSessionCacheForUser(user.Id)
	a.InvalidateCacheForUser(user.Id)
	a.invalidateCacheForUserBranches(user.Id)

	return nil
}

func (a *App) LeaveBranch(branch *model.Branch, user *model.User, requestorId string) *model.AppError {
	branchMember, err := a.GetBranchMember(branch.Id, user.Id)
	if err != nil {
		return model.NewAppError("LeaveBranch", "api.branch.remove_user_from_branch.missing.app_error", nil, err.Error(), http.StatusBadRequest)
	}

	var classList *model.ClassList

	if classList, err = a.Srv().Store.Class().GetClasses(branch.Id, user.Id, true); err != nil {
		if err.Id == "store.sql_class.get_classes.not_found.app_error" {
			classList = &model.ClassList{}
		} else {
			return err
		}
	}

	for _, class := range *classList {
		a.invalidateCacheForClassMembers(class.Id)
		if err = a.Srv().Store.Class().RemoveMember(class.Id, user.Id); err != nil {
			return err
		}
	}

	_, err = a.Srv().Store.Class().GetByName(branch.Id, model.DEFAULT_CLASS, false)
	if err != nil {
		return err
	}

	err = a.RemoveBranchMemberFromBranch(branchMember, requestorId)
	if err != nil {
		return err
	}

	return nil
}
func (a *App) FindBranchByName(name string) bool {
	if _, err := a.Srv().Store.Branch().GetByName(name); err != nil {
		return false
	}
	return true
}

func (a *App) PermanentDeleteBranchId(branchId string) *model.AppError {
	branch, err := a.GetBranch(branchId)
	if err != nil {
		return err
	}

	return a.PermanentDeleteBranch(branch)
}

func (a *App) PermanentDeleteBranch(branch *model.Branch) *model.AppError {
	branch.DeleteAt = model.GetMillis()
	if _, err := a.Srv().Store.Branch().Update(branch); err != nil {
		return err
	}

	if classes, err := a.Srv().Store.Class().GetBranchClasses(branch.Id); err != nil {
		if err.Id != "store.sql_class.get_classes.not_found.app_error" {
			return err
		}
	} else {
		for _, c := range *classes {
			a.PermanentDeleteClass(c)
		}
	}

	if err := a.Srv().Store.Branch().RemoveAllMembersByBranch(branch.Id); err != nil {
		return err
	}

	if err := a.Srv().Store.Command().PermanentDeleteByBranch(branch.Id); err != nil {
		return err
	}

	if err := a.Srv().Store.Branch().PermanentDelete(branch.Id); err != nil {
		return err
	}

	a.sendBranchEvent(branch, model.WEBSOCKET_EVENT_DELETE_BRANCH)

	return nil
}

func (a *App) SoftDeleteBranch(branchId string) *model.AppError {
	branch, err := a.GetBranch(branchId)
	if err != nil {
		return err
	}

	branch.DeleteAt = model.GetMillis()
	if branch, err = a.Srv().Store.Branch().Update(branch); err != nil {
		return err
	}

	a.sendBranchEvent(branch, model.WEBSOCKET_EVENT_DELETE_BRANCH)

	return nil
}

func (a *App) RestoreBranch(branchId string) *model.AppError {
	branch, err := a.GetBranch(branchId)
	if err != nil {
		return err
	}

	branch.DeleteAt = 0
	if branch, err = a.Srv().Store.Branch().Update(branch); err != nil {
		return err
	}

	a.sendBranchEvent(branch, model.WEBSOCKET_EVENT_RESTORE_BRANCH)
	return nil
}

func (a *App) GetBranchStats(branchId string, restrictions *model.ViewUsersRestrictions) (*model.BranchStats, *model.AppError) {
	tchan := make(chan store.StoreResult, 1)
	go func() {
		totalMemberCount, err := a.Srv().Store.Branch().GetTotalMemberCount(branchId, restrictions)
		tchan <- store.StoreResult{Data: totalMemberCount, Err: err}
		close(tchan)
	}()
	achan := make(chan store.StoreResult, 1)
	go func() {
		memberCount, err := a.Srv().Store.Branch().GetActiveMemberCount(branchId, restrictions)
		achan <- store.StoreResult{Data: memberCount, Err: err}
		close(achan)
	}()

	stats := &model.BranchStats{}
	stats.BranchId = branchId

	result := <-tchan
	if result.Err != nil {
		return nil, result.Err
	}
	stats.TotalMemberCount = result.Data.(int64)

	result = <-achan
	if result.Err != nil {
		return nil, result.Err
	}
	stats.ActiveMemberCount = result.Data.(int64)

	return stats, nil
}

func (a *App) GetBranchIdFromQuery(query url.Values) (string, *model.AppError) {
	tokenId := query.Get("t")

	if len(tokenId) > 0 {
		token, err := a.Srv().Store.Token().GetByToken(tokenId)
		if err != nil {
			return "", model.NewAppError("GetBranchIdFromQuery", "api.oauth.singup_with_oauth.invalid_link.app_error", nil, "", http.StatusBadRequest)
		}

		if token.Type != TOKEN_TYPE_BRANCH_INVITATION {
			return "", model.NewAppError("GetBranchIdFromQuery", "api.oauth.singup_with_oauth.invalid_link.app_error", nil, "", http.StatusBadRequest)
		}

		if model.GetMillis()-token.CreateAt >= INVITATION_EXPIRY_TIME {
			a.DeleteToken(token)
			return "", model.NewAppError("GetBranchIdFromQuery", "api.oauth.singup_with_oauth.expired_link.app_error", nil, "", http.StatusBadRequest)
		}

		tokenData := model.MapFromJson(strings.NewReader(token.Extra))

		return tokenData["branchId"], nil
	}

	return "", nil
}

func (a *App) SanitizeBranch(session model.Session, branch *model.Branch) *model.Branch {
	if a.SessionHasPermissionToBranch(session, branch.Id, model.PERMISSION_MANAGE_BRANCH) {
		return branch
	}

	branch.Sanitize()

	return branch
}

func (a *App) SanitizeBranches(session model.Session, branches []*model.Branch) []*model.Branch {
	for _, branch := range branches {
		a.SanitizeBranch(session, branch)
	}

	return branches
}

func (a *App) GetBranchIcon(branch *model.Branch) ([]byte, *model.AppError) {
	if len(*a.Config().FileSettings.DriverName) == 0 {
		return nil, model.NewAppError("GetBranchIcon", "api.branch.get_branch_icon.filesettings_no_driver.app_error", nil, "", http.StatusNotImplemented)
	}

	path := "branches/" + branch.Id + "/branchIcon.png"
	data, err := a.ReadFile(path)
	if err != nil {
		return nil, model.NewAppError("GetBranchIcon", "api.branch.get_branch_icon.read_file.app_error", nil, err.Error(), http.StatusNotFound)
	}

	return data, nil
}

func (a *App) SetBranchIcon(branchId string, imageData *multipart.FileHeader) *model.AppError {
	file, err := imageData.Open()
	if err != nil {
		return model.NewAppError("SetBranchIcon", "api.branch.set_branch_icon.open.app_error", nil, err.Error(), http.StatusBadRequest)
	}
	defer file.Close()
	return a.SetBranchIconFromMultiPartFile(branchId, file)
}

func (a *App) SetBranchIconFromMultiPartFile(branchId string, file multipart.File) *model.AppError {
	branch, getBranchErr := a.GetBranch(branchId)

	if getBranchErr != nil {
		return model.NewAppError("SetBranchIcon", "api.branch.set_branch_icon.get_branch.app_error", nil, getBranchErr.Error(), http.StatusBadRequest)
	}

	if len(*a.Config().FileSettings.DriverName) == 0 {
		return model.NewAppError("setBranchIcon", "api.branch.set_branch_icon.storage.app_error", nil, "", http.StatusNotImplemented)
	}

	// Decode image config first to check dimensions before loading the whole thing into memory later on
	config, _, err := image.DecodeConfig(file)
	if err != nil {
		return model.NewAppError("SetBranchIcon", "api.branch.set_branch_icon.decode_config.app_error", nil, err.Error(), http.StatusBadRequest)
	}
	if config.Width*config.Height > model.MaxImageSize {
		return model.NewAppError("SetBranchIcon", "api.branch.set_branch_icon.too_large.app_error", nil, "", http.StatusBadRequest)
	}

	file.Seek(0, 0)

	return a.SetBranchIconFromFile(branch, file)
}

func (a *App) SetBranchIconFromFile(branch *model.Branch, file io.Reader) *model.AppError {
	// Decode image into Image object
	img, _, err := image.Decode(file)
	if err != nil {
		return model.NewAppError("SetBranchIcon", "api.branch.set_branch_icon.decode.app_error", nil, err.Error(), http.StatusBadRequest)
	}

	orientation, _ := getImageOrientation(file)
	img = makeImageUpright(img, orientation)

	// Scale branch icon
	branchIconWidthAndHeight := 128
	img = imaging.Fill(img, branchIconWidthAndHeight, branchIconWidthAndHeight, imaging.Center, imaging.Lanczos)

	buf := new(bytes.Buffer)
	err = png.Encode(buf, img)
	if err != nil {
		return model.NewAppError("SetBranchIcon", "api.branch.set_branch_icon.encode.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	path := "branches/" + branch.Id + "/branchIcon.png"

	if _, err := a.WriteFile(buf, path); err != nil {
		return model.NewAppError("SetBranchIcon", "api.branch.set_branch_icon.write_file.app_error", nil, "", http.StatusInternalServerError)
	}

	curTime := model.GetMillis()

	if err := a.Srv().Store.Branch().UpdateLastBranchIconUpdate(branch.Id, curTime); err != nil {
		return model.NewAppError("SetBranchIcon", "api.branch.branch_icon.update.app_error", nil, err.Error(), http.StatusBadRequest)
	}

	// manually set time to avoid possible cluster inconsistencies
	branch.LastBranchIconUpdate = curTime

	a.sendBranchEvent(branch, model.WEBSOCKET_EVENT_UPDATE_BRANCH)

	return nil
}

func (a *App) RemoveBranchIcon(branchId string) *model.AppError {
	branch, err := a.GetBranch(branchId)
	if err != nil {
		return model.NewAppError("RemoveBranchIcon", "api.branch.remove_branch_icon.get_branch.app_error", nil, err.Error(), http.StatusBadRequest)
	}

	if err := a.Srv().Store.Branch().UpdateLastBranchIconUpdate(branchId, 0); err != nil {
		return model.NewAppError("RemoveBranchIcon", "api.branch.branch_icon.update.app_error", nil, err.Error(), http.StatusBadRequest)
	}

	branch.LastBranchIconUpdate = 0

	a.sendBranchEvent(branch, model.WEBSOCKET_EVENT_UPDATE_BRANCH)

	return nil
}

func (a *App) ClearBranchMembersCache(branchID string) {
	perPage := 100
	page := 0

	for {
		branchMembers, err := a.Srv().Store.Branch().GetMembers(branchID, page, perPage, nil)
		if err != nil {
			a.Log().Warn("error clearing cache for branch members", mlog.String("branch_id", branchID), mlog.String("err", err.Error()))
			break
		}

		for _, branchMember := range branchMembers {
			a.ClearSessionCacheForUser(branchMember.UserId)

			message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_MEMBERROLE_UPDATED, "", "", branchMember.UserId, nil)
			message.Add("member", branchMember.ToJson())
			a.Publish(message)
		}

		length := len(branchMembers)
		if length < perPage {
			break
		}

		page++
	}
}
