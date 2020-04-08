// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"net/http"
	"strings"

	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
)

func (a *App) MakePermissionError(permission *model.Permission) *model.AppError {
	return model.NewAppError("Permissions", "api.context.permissions.app_error", nil, "userId="+a.Session().UserId+", "+"permission="+permission.Id, http.StatusForbidden)
}

func (a *App) SessionHasPermissionTo(session model.Session, permission *model.Permission) bool {
	return a.RolesGrantPermission(session.GetUserRoles(), permission.Id)
}

func (a *App) SessionHasPermissionToBranch(session model.Session, branchId string, permission *model.Permission) bool {
	if branchId == "" {
		return false
	}

	branchMember := session.GetBranchByBranchId(branchId)
	if branchMember != nil {
		if a.RolesGrantPermission(branchMember.GetRoles(), permission.Id) {
			return true
		}
	}

	return a.RolesGrantPermission(session.GetUserRoles(), permission.Id)
}

func (a *App) SessionHasPermissionToClass(session model.Session, classId string, permission *model.Permission) bool {
	if classId == "" {
		return false
	}

	ids, err := a.Srv().Store.Class().GetAllClassMembersForUser(session.UserId, true, true)

	var classRoles []string
	if err == nil {
		if roles, ok := ids[classId]; ok {
			classRoles = strings.Fields(roles)
			if a.RolesGrantPermission(classRoles, permission.Id) {
				return true
			}
		}
	}

	class, err := a.GetClass(classId)
	if err == nil && class.BranchId != "" {
		return a.SessionHasPermissionToBranch(session, class.BranchId, permission)
	}

	if err != nil && err.StatusCode == http.StatusNotFound {
		return false
	}

	return a.SessionHasPermissionTo(session, permission)
}

func (a *App) SessionHasPermissionToClassByPost(session model.Session, postId string, permission *model.Permission) bool {
	if classMember, err := a.Srv().Store.Class().GetMemberForPost(postId, session.UserId); err == nil {

		if a.RolesGrantPermission(classMember.GetRoles(), permission.Id) {
			return true
		}
	}

	if class, err := a.Srv().Store.Class().GetForPost(postId); err == nil {
		if class.BranchId != "" {
			return a.SessionHasPermissionToBranch(session, class.BranchId, permission)
		}
	}

	return a.SessionHasPermissionTo(session, permission)
}

func (a *App) SessionHasPermissionToUser(session model.Session, userId string) bool {
	if userId == "" {
		return false
	}

	if session.UserId == userId {
		return true
	}

	if a.SessionHasPermissionTo(session, model.PERMISSION_EDIT_OTHER_USERS) {
		return true
	}

	return false
}

func (a *App) HasPermissionTo(askingUserId string, permission *model.Permission) bool {
	user, err := a.GetUser(askingUserId)
	if err != nil {
		return false
	}

	roles := user.GetRoles()

	return a.RolesGrantPermission(roles, permission.Id)
}

func (a *App) HasPermissionToBranch(askingUserId string, branchId string, permission *model.Permission) bool {
	if branchId == "" || askingUserId == "" {
		return false
	}

	branchMember, err := a.GetBranchMember(branchId, askingUserId)
	if err != nil {
		return false
	}

	roles := branchMember.GetRoles()

	if a.RolesGrantPermission(roles, permission.Id) {
		return true
	}

	return a.HasPermissionTo(askingUserId, permission)
}

func (a *App) HasPermissionToClass(askingUserId string, classId string, permission *model.Permission) bool {
	if classId == "" || askingUserId == "" {
		return false
	}

	classMember, err := a.GetClassMember(classId, askingUserId)
	if err == nil {
		roles := classMember.GetRoles()
		if a.RolesGrantPermission(roles, permission.Id) {
			return true
		}
	}

	var class *model.Class
	class, err = a.GetClass(classId)
	if err == nil {
		return a.HasPermissionToBranch(askingUserId, class.BranchId, permission)
	}

	return a.HasPermissionTo(askingUserId, permission)
}

func (a *App) HasPermissionToUser(askingUserId string, userId string) bool {
	if askingUserId == userId {
		return true
	}

	if a.HasPermissionTo(askingUserId, model.PERMISSION_EDIT_OTHER_USERS) {
		return true
	}

	return false
}

func (a *App) RolesGrantPermission(roleNames []string, permissionId string) bool {
	roles, err := a.GetRolesByNames(roleNames)
	if err != nil {
		// This should only happen if something is very broken. We can't realistically
		// recover the situation, so deny permission and log an error.
		mlog.Error("Failed to get roles from database with role names: "+strings.Join(roleNames, ",")+" ", mlog.Err(err))
		return false
	}

	for _, role := range roles {
		if role.DeleteAt != 0 {
			continue
		}

		permissions := role.Permissions
		for _, permission := range permissions {
			if permission == permissionId {
				return true
			}
		}
	}

	return false
}
