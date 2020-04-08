// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package api4

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/vnforks/kid/v5/audit"
	"github.com/vnforks/kid/v5/model"
)

const (
	MAX_ADD_MEMBERS_BATCH    = 20
	MAXIMUM_BULK_IMPORT_SIZE = 10 * 1024 * 1024
	groupIDsParamPattern     = "[^a-zA-Z0-9,]*"
)

var groupIDsQueryParamRegex *regexp.Regexp

func init() {
	groupIDsQueryParamRegex = regexp.MustCompile(groupIDsParamPattern)
}

func (api *API) InitBranch() {
	api.BaseRoutes.Branches.Handle("", api.ApiSessionRequired(createBranch)).Methods("POST")
	api.BaseRoutes.Branches.Handle("", api.ApiSessionRequired(getAllBranches)).Methods("GET")
	api.BaseRoutes.Branches.Handle("/{branch_id:[A-Za-z0-9]+}/scheme", api.ApiSessionRequired(updateBranchScheme)).Methods("PUT")
	api.BaseRoutes.BranchesForUser.Handle("", api.ApiSessionRequired(getBranchesForUser)).Methods("GET")

	api.BaseRoutes.Branch.Handle("", api.ApiSessionRequired(getBranch)).Methods("GET")
	api.BaseRoutes.Branch.Handle("", api.ApiSessionRequired(updateBranch)).Methods("PUT")
	api.BaseRoutes.Branch.Handle("", api.ApiSessionRequired(deleteBranch)).Methods("DELETE")
	api.BaseRoutes.Branch.Handle("/patch", api.ApiSessionRequired(patchBranch)).Methods("PUT")
	api.BaseRoutes.Branch.Handle("/stats", api.ApiSessionRequired(getBranchStats)).Methods("GET")

	api.BaseRoutes.Branch.Handle("/image", api.ApiSessionRequiredTrustRequester(getBranchIcon)).Methods("GET")
	api.BaseRoutes.Branch.Handle("/image", api.ApiSessionRequired(setBranchIcon)).Methods("POST")
	api.BaseRoutes.Branch.Handle("/image", api.ApiSessionRequired(removeBranchIcon)).Methods("DELETE")

	api.BaseRoutes.BranchMembers.Handle("", api.ApiSessionRequired(getBranchMembers)).Methods("GET")
	api.BaseRoutes.BranchMembers.Handle("/ids", api.ApiSessionRequired(getBranchMembersByIds)).Methods("POST")
	api.BaseRoutes.BranchMembersForUser.Handle("", api.ApiSessionRequired(getBranchMembersForUser)).Methods("GET")
	api.BaseRoutes.BranchMembers.Handle("", api.ApiSessionRequired(addBranchMember)).Methods("POST")
	api.BaseRoutes.BranchMembers.Handle("/batch", api.ApiSessionRequired(addBranchMembers)).Methods("POST")
	api.BaseRoutes.BranchMember.Handle("", api.ApiSessionRequired(removeBranchMember)).Methods("DELETE")

	api.BaseRoutes.BranchByName.Handle("", api.ApiSessionRequired(getBranchByName)).Methods("GET")
	api.BaseRoutes.BranchMember.Handle("", api.ApiSessionRequired(getBranchMember)).Methods("GET")
	api.BaseRoutes.BranchByName.Handle("/exists", api.ApiSessionRequired(branchExists)).Methods("GET")
	api.BaseRoutes.BranchMember.Handle("/roles", api.ApiSessionRequired(updateBranchMemberRoles)).Methods("PUT")
	api.BaseRoutes.BranchMember.Handle("/schemeRoles", api.ApiSessionRequired(updateBranchMemberSchemeRoles)).Methods("PUT")
}

func createBranch(c *Context, w http.ResponseWriter, r *http.Request) {
	branch := model.BranchFromJson(r.Body)
	if branch == nil {
		c.SetInvalidParam("branch")
		return
	}
	branch.Email = strings.ToLower(branch.Email)

	auditRec := c.MakeAuditRecord("createBranch", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_name", branch.Name)
	auditRec.AddMeta("branch_display", branch.DisplayName)

	if !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_CREATE_BRANCH) {
		c.Err = model.NewAppError("createBranch", "api.branch.is_branch_creation_allowed.disabled.app_error", nil, "", http.StatusForbidden)
		return
	}

	rbranch, err := c.App.CreateBranchWithUser(branch, c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	// Don't sanitize the branch here since the user will be a branch admin and their session won't reflect that yet

	auditRec.Success()
	auditRec.AddMeta("branch_id", rbranch.Id)

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(rbranch.ToJson()))
}

func getBranch(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	branch, err := c.App.GetBranch(c.Params.BranchId)
	if err != nil {
		c.Err = err
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), branch.Id, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	c.App.SanitizeBranch(*c.App.Session(), branch)
	w.Write([]byte(branch.ToJson()))
}

func getBranchByName(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchName()
	if c.Err != nil {
		return
	}

	branch, err := c.App.GetBranchByName(c.Params.BranchName)
	if err != nil {
		c.Err = err
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), branch.Id, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	c.App.SanitizeBranch(*c.App.Session(), branch)
	w.Write([]byte(branch.ToJson()))
}

func updateBranch(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	branch := model.BranchFromJson(r.Body)

	if branch == nil {
		c.SetInvalidParam("branch")
		return
	}
	branch.Email = strings.ToLower(branch.Email)

	// The branch being updated in the payload must be the same one as indicated in the URL.
	if branch.Id != c.Params.BranchId {
		c.SetInvalidParam("id")
		return
	}

	auditRec := c.MakeAuditRecord("updateBranch", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)
	auditRec.AddMeta("branch_name", branch.Name)
	auditRec.AddMeta("branch_display", branch.DisplayName)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_BRANCH) {
		c.SetPermissionError(model.PERMISSION_MANAGE_BRANCH)
		return
	}

	updatedBranch, err := c.App.UpdateBranch(branch)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()

	c.App.SanitizeBranch(*c.App.Session(), updatedBranch)
	w.Write([]byte(updatedBranch.ToJson()))
}

func patchBranch(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	branch := model.BranchPatchFromJson(r.Body)

	if branch == nil {
		c.SetInvalidParam("branch")
		return
	}

	auditRec := c.MakeAuditRecord("patchBranch", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_BRANCH) {
		c.SetPermissionError(model.PERMISSION_MANAGE_BRANCH)
		return
	}

	patchedBranch, err := c.App.PatchBranch(c.Params.BranchId, branch)

	if err != nil {
		c.Err = err
		return
	}

	c.App.SanitizeBranch(*c.App.Session(), patchedBranch)

	auditRec.Success()
	auditRec.AddMeta("branch_name", patchedBranch.Name)
	auditRec.AddMeta("branch_display", patchedBranch.DisplayName)
	c.LogAudit("")

	w.Write([]byte(patchedBranch.ToJson()))
}

func deleteBranch(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_BRANCH) {
		c.SetPermissionError(model.PERMISSION_MANAGE_BRANCH)
		return
	}

	auditRec := c.MakeAuditRecord("deleteBranch", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)

	var err *model.AppError
	if c.Params.Permanent && *c.App.Config().ServiceSettings.EnableAPIBranchDeletion {
		err = c.App.PermanentDeleteBranchId(c.Params.BranchId)
	} else {
		err = c.App.SoftDeleteBranch(c.Params.BranchId)
	}

	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	ReturnStatusOK(w)
}

func getBranchesForUser(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId()
	if c.Err != nil {
		return
	}

	if c.App.Session().UserId != c.Params.UserId && !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	branches, err := c.App.GetBranchesForUser(c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	c.App.SanitizeBranches(*c.App.Session(), branches)
	w.Write([]byte(model.BranchListToJson(branches)))
}
func getBranchMember(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId().RequireUserId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	canSee, err := c.App.UserCanSeeOtherUser(c.App.Session().UserId, c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	if !canSee {
		c.SetPermissionError(model.PERMISSION_VIEW_MEMBERS)
		return
	}

	branch, err := c.App.GetBranchMember(c.Params.BranchId, c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(branch.ToJson()))
}

func getBranchMembers(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	sort := r.URL.Query().Get("sort")
	excludeDeletedUsers := r.URL.Query().Get("exclude_deleted_users")
	excludeDeletedUsersBool, _ := strconv.ParseBool(excludeDeletedUsers)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	restrictions, err := c.App.GetViewUsersRestrictions(c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	branchMembersGetOptions := &model.BranchMembersGetOptions{
		Sort:                sort,
		ExcludeDeletedUsers: excludeDeletedUsersBool,
		ViewRestrictions:    restrictions,
	}

	members, err := c.App.GetBranchMembers(c.Params.BranchId, c.Params.Page*c.Params.PerPage, c.Params.PerPage, branchMembersGetOptions)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(model.BranchMembersToJson(members)))
}

func getBranchMembersForUser(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToUser(*c.App.Session(), c.Params.UserId) {
		c.SetPermissionError(model.PERMISSION_EDIT_OTHER_USERS)
		return
	}

	canSee, err := c.App.UserCanSeeOtherUser(c.App.Session().UserId, c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	if !canSee {
		c.SetPermissionError(model.PERMISSION_VIEW_MEMBERS)
		return
	}

	members, err := c.App.GetBranchMembersForUser(c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(model.BranchMembersToJson(members)))
}

func getBranchMembersByIds(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	userIds := model.ArrayFromJson(r.Body)

	if len(userIds) == 0 {
		c.SetInvalidParam("user_ids")
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	restrictions, err := c.App.GetViewUsersRestrictions(c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	members, err := c.App.GetBranchMembersByIds(c.Params.BranchId, userIds, restrictions)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(model.BranchMembersToJson(members)))
}

func addBranchMember(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	var err *model.AppError
	member := model.BranchMemberFromJson(r.Body)
	if member.BranchId != c.Params.BranchId {
		c.SetInvalidParam("branch_id")
		return
	}

	if len(member.UserId) != 26 {
		c.SetInvalidParam("user_id")
		return
	}

	auditRec := c.MakeAuditRecord("addBranchMember", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)
	auditRec.AddMeta("add_user_id", member.UserId)

	if member.UserId == c.App.Session().UserId {
		_, err = c.App.GetBranch(member.BranchId)
		if err != nil {
			c.Err = err
			return
		}

	} else {
		if !c.App.SessionHasPermissionToBranch(*c.App.Session(), member.BranchId, model.PERMISSION_ADD_USER_TO_BRANCH) {
			c.SetPermissionError(model.PERMISSION_ADD_USER_TO_BRANCH)
			return
		}
	}

	branch, err := c.App.GetBranch(member.BranchId)
	if err != nil {
		c.Err = err
		return
	}
	auditRec.AddMeta("branch_name", branch.Name)
	auditRec.AddMeta("branch_display", branch.DisplayName)

	member, err = c.App.AddBranchMember(member.BranchId, member.UserId)

	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(member.ToJson()))
}

func addBranchMembers(c *Context, w http.ResponseWriter, r *http.Request) {
	graceful := r.URL.Query().Get("graceful") != ""

	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	var err *model.AppError
	members := model.BranchMembersFromJson(r.Body)

	if len(members) > MAX_ADD_MEMBERS_BATCH {
		c.SetInvalidParam("too many members in batch")
		return
	}

	if len(members) == 0 {
		c.SetInvalidParam("no members in batch")
		return
	}

	auditRec := c.MakeAuditRecord("addBranchMembers", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)
	auditRec.AddMeta("count", len(members))

	var memberIDs []string
	for _, member := range members {
		memberIDs = append(memberIDs, member.UserId)
	}
	auditRec.AddMeta("user_ids", memberIDs)

	branch, err := c.App.GetBranch(c.Params.BranchId)
	if err != nil {
		c.Err = err
		return
	}
	auditRec.AddMeta("branch_name", branch.Name)
	auditRec.AddMeta("branch_display", branch.DisplayName)

	var userIds []string
	for _, member := range members {
		if member.BranchId != c.Params.BranchId {
			c.SetInvalidParam("branch_id for member with user_id=" + member.UserId)
			return
		}

		if len(member.UserId) != 26 {
			c.SetInvalidParam("user_id")
			return
		}

		userIds = append(userIds, member.UserId)
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_ADD_USER_TO_BRANCH) {
		c.SetPermissionError(model.PERMISSION_ADD_USER_TO_BRANCH)
		return
	}

	membersWithErrors, err := c.App.AddBranchMembers(c.Params.BranchId, userIds, c.App.Session().UserId, graceful)

	if membersWithErrors != nil {
		errList := make([]string, 0, len(membersWithErrors))
		for _, m := range membersWithErrors {
			if m.Error != nil {
				errList = append(errList, model.BranchMemberWithErrorToString(m))
			}
		}
		auditRec.AddMeta("errors", errList)
	}
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()

	w.WriteHeader(http.StatusCreated)

	if graceful {
		// in 'graceful' mode we allow a different return value, notifying the client which users were not added
		w.Write([]byte(model.BranchMembersWithErrorToJson(membersWithErrors)))
	} else {
		w.Write([]byte(model.BranchMembersToJson(model.BranchMembersWithErrorToBranchMembers(membersWithErrors))))
	}

}

func removeBranchMember(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId().RequireUserId()
	if c.Err != nil {
		return
	}

	auditRec := c.MakeAuditRecord("removeBranchMember", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)

	if c.App.Session().UserId != c.Params.UserId {
		if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_REMOVE_USER_FROM_BRANCH) {
			c.SetPermissionError(model.PERMISSION_REMOVE_USER_FROM_BRANCH)
			return
		}
	}

	branch, err := c.App.GetBranch(c.Params.BranchId)
	if err != nil {
		c.Err = err
		return
	}
	auditRec.AddMeta("branch_name", branch.Name)
	auditRec.AddMeta("branch_display", branch.DisplayName)

	user, err := c.App.GetUser(c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}
	auditRec.AddMeta("remove_user_id", user.Id)

	if c.Params.UserId != c.App.Session().UserId {
		c.Err = model.NewAppError("removeBranchMember", "api.branch.remove_member.group_constrained.app_error", nil, "", http.StatusBadRequest)
		return
	}

	if err := c.App.RemoveUserFromBranch(c.Params.BranchId, c.Params.UserId, c.App.Session().UserId); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	ReturnStatusOK(w)
}

func getBranchStats(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	restrictions, err := c.App.GetViewUsersRestrictions(c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	stats, err := c.App.GetBranchStats(c.Params.BranchId, restrictions)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(stats.ToJson()))
}

func updateBranchMemberRoles(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId().RequireUserId()
	if c.Err != nil {
		return
	}

	props := model.MapFromJson(r.Body)

	newRoles := props["roles"]
	if !model.IsValidUserRoles(newRoles) {
		c.SetInvalidParam("branch_member_roles")
		return
	}

	auditRec := c.MakeAuditRecord("updateBranchMemberRoles", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)
	auditRec.AddMeta("update_user_id", c.Params.UserId)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_BRANCH_ROLES) {
		c.SetPermissionError(model.PERMISSION_MANAGE_BRANCH_ROLES)
		return
	}

	if _, err := c.App.UpdateBranchMemberRoles(c.Params.BranchId, c.Params.UserId, newRoles); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	ReturnStatusOK(w)
}

func updateBranchMemberSchemeRoles(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId().RequireUserId()
	if c.Err != nil {
		return
	}

	schemeRoles := model.SchemeRolesFromJson(r.Body)
	if schemeRoles == nil {
		c.SetInvalidParam("scheme_roles")
		return
	}

	auditRec := c.MakeAuditRecord("updateBranchMemberSchemeRoles", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)
	auditRec.AddMeta("update_user_id", c.Params.UserId)
	auditRec.AddMeta("new_scheme_admin", schemeRoles.SchemeAdmin)
	auditRec.AddMeta("new_scheme_user", schemeRoles.SchemeUser)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_BRANCH_ROLES) {
		c.SetPermissionError(model.PERMISSION_MANAGE_BRANCH_ROLES)
		return
	}

	if _, err := c.App.UpdateBranchMemberSchemeRoles(c.Params.BranchId, c.Params.UserId, schemeRoles.SchemeUser, schemeRoles.SchemeAdmin); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	ReturnStatusOK(w)
}

func getAllBranches(c *Context, w http.ResponseWriter, r *http.Request) {
	branches := []*model.Branch{}
	var err *model.AppError
	var branchesWithCount *model.BranchesWithCount

	// list := c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_LIST_BRANCHES)
	if c.Params.IncludeTotalCount {
		branchesWithCount, err = c.App.GetAllBranchesPageWithCount(c.Params.Page*c.Params.PerPage, c.Params.PerPage)
	} else {
		branches, err = c.App.GetAllBranchesPage(c.Params.Page*c.Params.PerPage, c.Params.PerPage)
	}

	if err != nil {
		c.Err = err
		return
	}

	c.App.SanitizeBranches(*c.App.Session(), branches)

	var resBody []byte

	if c.Params.IncludeTotalCount {
		resBody = model.BranchesWithCountToJson(branchesWithCount)
	} else {
		resBody = []byte(model.BranchListToJson(branches))
	}

	w.Write(resBody)
}

func branchExists(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchName()
	if c.Err != nil {
		return
	}

	branch, err := c.App.GetBranchByName(c.Params.BranchName)
	if err != nil && err.StatusCode != http.StatusNotFound {
		c.Err = err
		return
	}

	exists := false

	if branch != nil {
		var branchMember *model.BranchMember
		branchMember, err = c.App.GetBranchMember(branch.Id, c.App.Session().UserId)
		if err != nil && err.StatusCode != http.StatusNotFound {
			c.Err = err
			return
		}

		// Verify that the user can see the branch (be a member or have the permission to list the branch)
		if branchMember != nil && branchMember.DeleteAt == 0 {
			exists = true
		}
	}

	resp := map[string]bool{"exists": exists}
	w.Write([]byte(model.MapBoolToJson(resp)))
}

func getBranchIcon(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	branch, err := c.App.GetBranch(c.Params.BranchId)

	if err != nil {
		c.Err = err
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	etag := strconv.FormatInt(branch.LastBranchIconUpdate, 10)

	if c.HandleEtag(etag, "Get Branch Icon", w, r) {
		return
	}

	img, err := c.App.GetBranchIcon(branch)
	if err != nil {
		c.Err = err
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%v, public", 24*60*60)) // 24 hrs
	w.Header().Set(model.HEADER_ETAG_SERVER, etag)
	w.Write(img)
}

func setBranchIcon(c *Context, w http.ResponseWriter, r *http.Request) {
	defer io.Copy(ioutil.Discard, r.Body)

	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	auditRec := c.MakeAuditRecord("setBranchIcon", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_BRANCH) {
		c.SetPermissionError(model.PERMISSION_MANAGE_BRANCH)
		return
	}

	if r.ContentLength > *c.App.Config().FileSettings.MaxFileSize {
		c.Err = model.NewAppError("setBranchIcon", "api.branch.set_branch_icon.too_large.app_error", nil, "", http.StatusBadRequest)
		return
	}

	if err := r.ParseMultipartForm(*c.App.Config().FileSettings.MaxFileSize); err != nil {
		c.Err = model.NewAppError("setBranchIcon", "api.branch.set_branch_icon.parse.app_error", nil, err.Error(), http.StatusBadRequest)
		return
	}

	m := r.MultipartForm

	imageArray, ok := m.File["image"]
	if !ok {
		c.Err = model.NewAppError("setBranchIcon", "api.branch.set_branch_icon.no_file.app_error", nil, "", http.StatusBadRequest)
		return
	}

	if len(imageArray) <= 0 {
		c.Err = model.NewAppError("setBranchIcon", "api.branch.set_branch_icon.array.app_error", nil, "", http.StatusBadRequest)
		return
	}

	imageData := imageArray[0]

	if err := c.App.SetBranchIcon(c.Params.BranchId, imageData); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("")

	ReturnStatusOK(w)
}

func removeBranchIcon(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	auditRec := c.MakeAuditRecord("removeBranchIcon", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_BRANCH) {
		c.SetPermissionError(model.PERMISSION_MANAGE_BRANCH)
		return
	}

	if err := c.App.RemoveBranchIcon(c.Params.BranchId); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("")

	ReturnStatusOK(w)
}

func updateBranchScheme(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	schemeID := model.SchemeIDFromJson(r.Body)
	if schemeID == nil || (len(*schemeID) != 26 && *schemeID != "") {
		c.SetInvalidParam("scheme_id")
		return
	}

	auditRec := c.MakeAuditRecord("updateBranchScheme", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("branch_id", c.Params.BranchId)

	if c.App.License() == nil {
		c.Err = model.NewAppError("Api4.UpdateBranchScheme", "api.branch.update_branch_scheme.license.error", nil, "", http.StatusNotImplemented)
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	if *schemeID != "" {
		scheme, err := c.App.GetScheme(*schemeID)
		if err != nil {
			c.Err = err
			return
		}
		auditRec.AddMeta("scheme_id", scheme.Id)
		auditRec.AddMeta("scheme_name", scheme.Name)
		auditRec.AddMeta("scheme_display", scheme.DisplayName)

		if scheme.Scope != model.SCHEME_SCOPE_BRANCH {
			c.Err = model.NewAppError("Api4.UpdateBranchScheme", "api.branch.update_branch_scheme.scheme_scope.error", nil, "", http.StatusBadRequest)
			return
		}
	}

	branch, err := c.App.GetBranch(c.Params.BranchId)
	if err != nil {
		c.Err = err
		return
	}
	auditRec.AddMeta("branch_name", branch.Name)
	auditRec.AddMeta("branch_display", branch.DisplayName)

	branch.SchemeId = schemeID

	_, err = c.App.UpdateBranchScheme(branch)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	ReturnStatusOK(w)
}
