// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package api4

import (
	"encoding/json"
	"net/http"

	"github.com/vnforks/kid/v5/audit"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

func (api *API) InitClass() {
	api.BaseRoutes.Classes.Handle("", api.ApiSessionRequired(getAllClasses)).Methods("GET")
	api.BaseRoutes.Classes.Handle("", api.ApiSessionRequired(createClass)).Methods("POST")
	api.BaseRoutes.Classes.Handle("/{class_id:[A-Za-z0-9]+}/scheme", api.ApiSessionRequired(updateClassScheme)).Methods("PUT")

	api.BaseRoutes.ClassesForBranch.Handle("/deleted", api.ApiSessionRequired(getDeletedClassesForBranch)).Methods("GET")
	api.BaseRoutes.User.Handle("/branches/{branch_id:[A-Za-z0-9]+}/classes", api.ApiSessionRequired(getClassesForBranchForUser)).Methods("GET")

	api.BaseRoutes.Class.Handle("", api.ApiSessionRequired(getClass)).Methods("GET")
	api.BaseRoutes.Class.Handle("", api.ApiSessionRequired(updateClass)).Methods("PUT")
	api.BaseRoutes.Class.Handle("/patch", api.ApiSessionRequired(patchClass)).Methods("PUT")
	api.BaseRoutes.Class.Handle("/restore", api.ApiSessionRequired(restoreClass)).Methods("POST")
	api.BaseRoutes.Class.Handle("", api.ApiSessionRequired(deleteClass)).Methods("DELETE")
	api.BaseRoutes.Class.Handle("/timezones", api.ApiSessionRequired(getClassMembersTimezones)).Methods("GET")

	api.BaseRoutes.ClassByName.Handle("", api.ApiSessionRequired(getClassByName)).Methods("GET")
	api.BaseRoutes.ClassByNameForBranchName.Handle("", api.ApiSessionRequired(getClassByNameForBranchName)).Methods("GET")

	api.BaseRoutes.ClassMembers.Handle("", api.ApiSessionRequired(getClassMembers)).Methods("GET")
	api.BaseRoutes.ClassMembers.Handle("/ids", api.ApiSessionRequired(getClassMembersByIds)).Methods("POST")
	api.BaseRoutes.ClassMembers.Handle("", api.ApiSessionRequired(addClassMember)).Methods("POST")
	api.BaseRoutes.ClassMembersForUser.Handle("", api.ApiSessionRequired(getClassMembersForUser)).Methods("GET")
	api.BaseRoutes.ClassMember.Handle("", api.ApiSessionRequired(getClassMember)).Methods("GET")
	api.BaseRoutes.ClassMember.Handle("", api.ApiSessionRequired(removeClassMember)).Methods("DELETE")
	api.BaseRoutes.ClassMember.Handle("/roles", api.ApiSessionRequired(updateClassMemberRoles)).Methods("PUT")
	api.BaseRoutes.ClassMember.Handle("/schemeRoles", api.ApiSessionRequired(updateClassMemberSchemeRoles)).Methods("PUT")
	api.BaseRoutes.ClassMember.Handle("/notify_props", api.ApiSessionRequired(updateClassMemberNotifyProps)).Methods("PUT")

	api.BaseRoutes.ClassModerations.Handle("", api.ApiSessionRequired(getClassModerations)).Methods("GET")
	api.BaseRoutes.ClassModerations.Handle("/patch", api.ApiSessionRequired(patchClassModerations)).Methods("PUT")
}

func createClass(c *Context, w http.ResponseWriter, r *http.Request) {
	class := model.ClassFromJson(r.Body)
	if class == nil {
		c.SetInvalidParam("class")
		return
	}

	auditRec := c.MakeAuditRecord("createClass", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_name", class.Name)

	sc, err := c.App.CreateClassWithUser(class, c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	auditRec.AddMeta("class_id", sc.Id)
	c.LogAudit("name=" + class.Name)

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(sc.ToJson()))
}

func updateClass(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	class := model.ClassFromJson(r.Body)

	if class == nil {
		c.SetInvalidParam("class")
		return
	}

	// The class being updated in the payload must be the same one as indicated in the URL.
	if class.Id != c.Params.ClassId {
		c.SetInvalidParam("class_id")
		return
	}

	auditRec := c.MakeAuditRecord("updateClass", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", class.Id)

	originalOldClass, err := c.App.GetClass(class.Id)
	if err != nil {
		c.Err = err
		return
	}
	oldClass := originalOldClass.DeepCopy()

	auditRec.AddMeta("class_name", oldClass.Name)

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_MANAGE_CLASS) {
		c.SetPermissionError(model.PERMISSION_MANAGE_CLASS)
		return
	}

	if oldClass.DeleteAt > 0 {
		c.Err = model.NewAppError("updateClass", "api.class.update_class.deleted.app_error", nil, "", http.StatusBadRequest)
		return
	}

	if oldClass.Name == model.DEFAULT_CLASS {
		if len(class.Name) > 0 && class.Name != oldClass.Name {
			c.Err = model.NewAppError("updateClass", "api.class.update_class.tried.app_error", map[string]interface{}{"Class": model.DEFAULT_CLASS}, "", http.StatusBadRequest)
			return
		}
	}

	oldClass.Header = class.Header
	oldClass.Purpose = class.Purpose

	if len(class.DisplayName) > 0 {
		oldClass.DisplayName = class.DisplayName
	}

	if len(class.Name) > 0 {
		oldClass.Name = class.Name
		auditRec.AddMeta("new_class_name", oldClass.Name)
	}

	if _, err := c.App.UpdateClass(oldClass); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("name=" + class.Name)

	w.Write([]byte(oldClass.ToJson()))
}

func patchClass(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	patch := model.ClassPatchFromJson(r.Body)
	if patch == nil {
		c.SetInvalidParam("class")
		return
	}

	originalOldClass, err := c.App.GetClass(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}
	oldClass := originalOldClass.DeepCopy()

	auditRec := c.MakeAuditRecord("patchClass", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", oldClass.Id)
	auditRec.AddMeta("class_name", oldClass.Name)

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_MANAGE_CLASS) {
		c.SetPermissionError(model.PERMISSION_MANAGE_CLASS)
		return
	}

	rclass, err := c.App.PatchClass(oldClass, patch, c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("")

	w.Write([]byte(rclass.ToJson()))
}

func restoreClass(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	class, err := c.App.GetClass(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}
	branchId := class.BranchId

	auditRec := c.MakeAuditRecord("restoreClass", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", class.Id)
	auditRec.AddMeta("class_name", class.Name)

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), branchId, model.PERMISSION_MANAGE_BRANCH) {
		c.SetPermissionError(model.PERMISSION_MANAGE_BRANCH)
		return
	}

	class, err = c.App.RestoreClass(class, c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("name=" + class.Name)

	w.Write([]byte(class.ToJson()))
}

func getClass(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	class, err := c.App.GetClass(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_READ_CLASS) {
		c.SetPermissionError(model.PERMISSION_READ_CLASS)
		return
	}

	w.Write([]byte(class.ToJson()))
}

func getAllClasses(c *Context, w http.ResponseWriter, r *http.Request) {
	if !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	opts := model.ClassSearchOpts{
		NotAssociatedToGroup:  c.Params.NotAssociatedToGroup,
		ExcludeDefaultClasses: c.Params.ExcludeDefaultClasses,
	}

	classes, err := c.App.GetAllClasses(c.Params.Page, c.Params.PerPage, opts)
	if err != nil {
		c.Err = err
		return
	}

	var payload []byte
	if c.Params.IncludeTotalCount {
		totalCount, err := c.App.GetAllClassesCount(opts)
		if err != nil {
			c.Err = err
			return
		}
		cwc := &model.ClassesWithCount{
			Classes:    classes,
			TotalCount: totalCount,
		}
		payload = cwc.ToJson()
	} else {
		payload = []byte(classes.ToJson())
	}

	w.Write(payload)
}

func getDeletedClassesForBranch(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId()
	if c.Err != nil {
		return
	}

	classes, err := c.App.GetDeletedClasses(c.Params.BranchId, c.Params.Page*c.Params.PerPage, c.Params.PerPage, c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(classes.ToJson()))
}

func getClassesForBranchForUser(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId().RequireBranchId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToUser(*c.App.Session(), c.Params.UserId) {
		c.SetPermissionError(model.PERMISSION_EDIT_OTHER_USERS)
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	classes, err := c.App.GetClassesForUser(c.Params.BranchId, c.Params.UserId, c.Params.IncludeDeleted)
	if err != nil {
		c.Err = err
		return
	}

	if c.HandleEtag(classes.Etag(), "Get Classes", w, r) {
		return
	}
	w.Header().Set(model.HEADER_ETAG_SERVER, classes.Etag())
	w.Write([]byte(classes.ToJson()))
}

func deleteClass(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	class, err := c.App.GetClass(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec := c.MakeAuditRecord("deleteClass", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", class.Id)
	auditRec.AddMeta("class_name", class.Name)

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), class.Id, model.PERMISSION_DELETE_CLASS) {
		c.SetPermissionError(model.PERMISSION_DELETE_CLASS)
		return
	}

	err = c.App.DeleteClass(class, c.App.Session().UserId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("name=" + class.Name)

	ReturnStatusOK(w)
}

func getClassByName(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchId().RequireClassName()
	if c.Err != nil {
		return
	}

	includeDeleted := r.URL.Query().Get("include_deleted") == "true"

	class, err := c.App.GetClassByName(c.Params.ClassName, c.Params.BranchId, includeDeleted)
	if err != nil {
		c.Err = err
		return
	}

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), class.Id, model.PERMISSION_READ_CLASS) {
		c.Err = model.NewAppError("getClassByName", store.MISSING_CLASS_ERROR, nil, "branchId="+class.BranchId+", "+"name="+class.Name+"", http.StatusNotFound)
		return
	}

	w.Write([]byte(class.ToJson()))
}

func getClassByNameForBranchName(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireBranchName().RequireClassName()
	if c.Err != nil {
		return
	}

	includeDeleted := r.URL.Query().Get("include_deleted") == "true"

	class, err := c.App.GetClassByNameForBranchName(c.Params.ClassName, c.Params.BranchName, includeDeleted)
	if err != nil {
		c.Err = err
		return
	}

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), class.Id, model.PERMISSION_READ_CLASS) {
		c.Err = model.NewAppError("getClassByNameForBranchName", store.MISSING_CLASS_ERROR, nil, "branchId="+class.BranchId+", "+"name="+class.Name+"", http.StatusNotFound)
		return
	}

	w.Write([]byte(class.ToJson()))
}

func getClassMembers(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_READ_CLASS) {
		c.SetPermissionError(model.PERMISSION_READ_CLASS)
		return
	}

	members, err := c.App.GetClassMembersPage(c.Params.ClassId, c.Params.Page, c.Params.PerPage)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(members.ToJson()))
}

func getClassMembersTimezones(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_READ_CLASS) {
		c.SetPermissionError(model.PERMISSION_READ_CLASS)
		return
	}

	membersTimezones, err := c.App.GetClassMembersTimezones(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(model.ArrayToJson(membersTimezones)))
}

func getClassMembersByIds(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	userIds := model.ArrayFromJson(r.Body)
	if len(userIds) == 0 {
		c.SetInvalidParam("user_ids")
		return
	}

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_READ_CLASS) {
		c.SetPermissionError(model.PERMISSION_READ_CLASS)
		return
	}

	members, err := c.App.GetClassMembersByIds(c.Params.ClassId, userIds)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(members.ToJson()))
}

func getClassMember(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId().RequireUserId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_READ_CLASS) {
		c.SetPermissionError(model.PERMISSION_READ_CLASS)
		return
	}

	member, err := c.App.GetClassMember(c.Params.ClassId, c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(member.ToJson()))
}

func getClassMembersForUser(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireUserId().RequireBranchId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_VIEW_BRANCH) {
		c.SetPermissionError(model.PERMISSION_VIEW_BRANCH)
		return
	}

	if c.App.Session().UserId != c.Params.UserId && !c.App.SessionHasPermissionToBranch(*c.App.Session(), c.Params.BranchId, model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	members, err := c.App.GetClassMembersForUser(c.Params.BranchId, c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(members.ToJson()))
}

func updateClassMemberRoles(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId().RequireUserId()
	if c.Err != nil {
		return
	}

	props := model.MapFromJson(r.Body)

	newRoles := props["roles"]
	if !(model.IsValidUserRoles(newRoles)) {
		c.SetInvalidParam("roles")
		return
	}

	auditRec := c.MakeAuditRecord("updateClassMemberRoles", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", c.Params.ClassId)
	auditRec.AddMeta("roles", newRoles)

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_MANAGE_CLASS_ROLES) {
		c.SetPermissionError(model.PERMISSION_MANAGE_CLASS_ROLES)
		return
	}

	if _, err := c.App.UpdateClassMemberRoles(c.Params.ClassId, c.Params.UserId, newRoles); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()

	ReturnStatusOK(w)
}

func updateClassMemberSchemeRoles(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId().RequireUserId()
	if c.Err != nil {
		return
	}

	schemeRoles := model.SchemeRolesFromJson(r.Body)
	if schemeRoles == nil {
		c.SetInvalidParam("scheme_roles")
		return
	}

	auditRec := c.MakeAuditRecord("updateClassMemberSchemeRoles", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", c.Params.ClassId)
	auditRec.AddMeta("roles", schemeRoles)

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), c.Params.ClassId, model.PERMISSION_MANAGE_CLASS_ROLES) {
		c.SetPermissionError(model.PERMISSION_MANAGE_CLASS_ROLES)
		return
	}

	if _, err := c.App.UpdateClassMemberSchemeRoles(c.Params.ClassId, c.Params.UserId, schemeRoles.SchemeUser, schemeRoles.SchemeAdmin); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()

	ReturnStatusOK(w)
}

func updateClassMemberNotifyProps(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId().RequireUserId()
	if c.Err != nil {
		return
	}

	props := model.MapFromJson(r.Body)
	if props == nil {
		c.SetInvalidParam("notify_props")
		return
	}

	auditRec := c.MakeAuditRecord("updateClassMemberNotifyProps", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", c.Params.ClassId)
	auditRec.AddMeta("props", props)

	if !c.App.SessionHasPermissionToUser(*c.App.Session(), c.Params.UserId) {
		c.SetPermissionError(model.PERMISSION_EDIT_OTHER_USERS)
		return
	}

	_, err := c.App.UpdateClassMemberNotifyProps(props, c.Params.ClassId, c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()

	ReturnStatusOK(w)
}

func addClassMember(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	props := model.StringInterfaceFromJson(r.Body)
	userId, ok := props["user_id"].(string)
	if !ok || len(userId) != 26 {
		c.SetInvalidParam("user_id")
		return
	}

	member := &model.ClassMember{
		ClassId: c.Params.ClassId,
		UserId:  userId,
	}

	postRootId, ok := props["post_root_id"].(string)
	if ok && len(postRootId) != 0 && len(postRootId) != 26 {
		c.SetInvalidParam("post_root_id")
		return
	}

	if ok && len(postRootId) == 26 {
		rootPost, err := c.App.GetSinglePost(postRootId)
		if err != nil {
			c.Err = err
			return
		}
		if rootPost.ClassId != member.ClassId {
			c.SetInvalidParam("post_root_id")
			return
		}
	}

	class, err := c.App.GetClass(member.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec := c.MakeAuditRecord("addClassMember", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", class.Id)
	auditRec.AddMeta("class_name", class.Name)

	// isNewMembership := false
	// if _, err = c.App.GetClassMember(member.ClassId, member.UserId); err != nil {
	// 	if err.Id == store.MISSING_CLASS_MEMBER_ERROR {
	// 		isNewMembership = true
	// 	} else {
	// 		c.Err = err
	// 		return
	// 	}
	// }

	// isSelfAdd := member.UserId == c.App.Session().UserId

	if !c.App.SessionHasPermissionToClass(*c.App.Session(), class.Id, model.PERMISSION_MANAGE_CLASS_MEMBERS) {
		c.SetPermissionError(model.PERMISSION_MANAGE_CLASS_MEMBERS)
		return
	}

	cm, err := c.App.AddClassMember(member.UserId, class, c.App.Session().UserId, postRootId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	auditRec.AddMeta("add_user_id", cm.UserId)
	c.LogAudit("name=" + class.Name + " user_id=" + cm.UserId)

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(cm.ToJson()))
}

func removeClassMember(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId().RequireUserId()
	if c.Err != nil {
		return
	}

	class, err := c.App.GetClass(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	user, err := c.App.GetUser(c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec := c.MakeAuditRecord("removeClassMember", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("class_id", class.Id)
	auditRec.AddMeta("class_name", class.Name)
	auditRec.AddMeta("remove_user_id", user.Id)

	if c.Params.UserId != c.App.Session().UserId {
		if !c.App.SessionHasPermissionToClass(*c.App.Session(), class.Id, model.PERMISSION_MANAGE_CLASS_MEMBERS) {
			c.SetPermissionError(model.PERMISSION_MANAGE_CLASS_MEMBERS)
			return
		}

	}

	if err = c.App.RemoveUserFromClass(c.Params.UserId, c.App.Session().UserId, class); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("name=" + class.Name + " user_id=" + c.Params.UserId)

	ReturnStatusOK(w)
}

func updateClassScheme(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireClassId()
	if c.Err != nil {
		return
	}

	schemeID := model.SchemeIDFromJson(r.Body)
	if schemeID == nil || len(*schemeID) != 26 {
		c.SetInvalidParam("scheme_id")
		return
	}

	auditRec := c.MakeAuditRecord("updateClassScheme", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("new_scheme_id", schemeID)

	if c.App.License() == nil {
		c.Err = model.NewAppError("Api4.UpdateClassScheme", "api.class.update_class_scheme.license.error", nil, "", http.StatusNotImplemented)
		return
	}

	if !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	scheme, err := c.App.GetScheme(*schemeID)
	if err != nil {
		c.Err = err
		return
	}

	if scheme.Scope != model.SCHEME_SCOPE_CLASS {
		c.Err = model.NewAppError("Api4.UpdateClassScheme", "api.class.update_class_scheme.scheme_scope.error", nil, "", http.StatusBadRequest)
		return
	}

	class, err := c.App.GetClass(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.AddMeta("class_id", class.Id)
	auditRec.AddMeta("class_name", class.Name)
	auditRec.AddMeta("old_scheme_id", class.SchemeId)

	class.SchemeId = &scheme.Id

	_, err = c.App.UpdateClassScheme(class)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()

	ReturnStatusOK(w)
}
func getClassModerations(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App.License() == nil {
		c.Err = model.NewAppError("Api4.GetClassModerations", "api.class.get_class_moderations.license.error", nil, "", http.StatusNotImplemented)
		return
	}

	c.RequireClassId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	class, err := c.App.GetClass(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	classModerations, err := c.App.GetClassModerationsForClass(class)
	if err != nil {
		c.Err = err
		return
	}

	b, marshalErr := json.Marshal(classModerations)
	if marshalErr != nil {
		c.Err = model.NewAppError("Api4.getClassModerations", "api.marshal_error", nil, marshalErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func patchClassModerations(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App.License() == nil {
		c.Err = model.NewAppError("Api4.patchClassModerations", "api.class.patch_class_moderations.license.error", nil, "", http.StatusNotImplemented)
		return
	}

	c.RequireClassId()
	if c.Err != nil {
		return
	}

	if !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	class, err := c.App.GetClass(c.Params.ClassId)
	if err != nil {
		c.Err = err
		return
	}

	classModerationsPatch := model.ClassModerationsPatchFromJson(r.Body)
	classModerations, err := c.App.PatchClassModerationsForClass(class, classModerationsPatch)
	if err != nil {
		c.Err = err
		return
	}

	b, marshalErr := json.Marshal(classModerations)
	if marshalErr != nil {
		c.Err = model.NewAppError("Api4.patchClassModerations", "api.marshal_error", nil, marshalErr.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(b)
}
