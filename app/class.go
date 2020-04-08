// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"net/http"
	"strings"
	"time"

	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
	"github.com/vnforks/kid/v5/utils"
)

// CreateDefaultClasses creates classes in the given branch for each class returned by (*App).DefaultClassNames.
//
func (a *App) CreateDefaultClasses(branchID string) ([]*model.Class, *model.AppError) {
	displayNames := map[string]string{
		"town-square": utils.T("api.class.create_default_classes.town_square"),
		"off-topic":   utils.T("api.class.create_default_classes.off_topic"),
	}
	classes := []*model.Class{}
	defaultClassNames := a.DefaultClassNames()
	for _, name := range defaultClassNames {
		displayName := utils.TDefault(displayNames[name], name)
		class := &model.Class{DisplayName: displayName, Name: name, BranchId: branchID}
		if _, err := a.CreateClass(class, false); err != nil {
			return nil, err
		}
		classes = append(classes, class)
	}
	return classes, nil
}

// DefaultClassNames returns the list of system-wide default class names.
//
// By default the list will be (not necessarily in this order):
//	['town-square', 'off-topic']
// However, if BranchSettings.ExperimentalDefaultClasses contains a list of classes then that list will replace
// 'off-topic' and be included in the return results in addition to 'town-square'. For example:
//	['town-square', 'game-of-thrones', 'wow']
//
func (a *App) DefaultClassNames() []string {
	names := []string{"town-square"}

	if len(a.Config().BranchSettings.ExperimentalDefaultClasses) == 0 {
		names = append(names, "off-topic")
	} else {
		seenClasses := map[string]bool{"town-square": true}
		for _, className := range a.Config().BranchSettings.ExperimentalDefaultClasses {
			if !seenClasses[className] {
				names = append(names, className)
				seenClasses[className] = true
			}
		}
	}

	return names
}

func (a *App) JoinDefaultClasses(branchId string, user *model.User, shouldBeAdmin bool, userRequestorId string) *model.AppError {
	if userRequestorId != "" {
		var err *model.AppError
		_, err = a.Srv().Store.User().Get(userRequestorId)
		if err != nil {
			return err
		}
	}

	var err *model.AppError
	for _, className := range a.DefaultClassNames() {
		class, classErr := a.Srv().Store.Class().GetByName(branchId, className, true)
		if classErr != nil {
			err = classErr
			continue
		}

		cm := &model.ClassMember{
			ClassId:     class.Id,
			UserId:      user.Id,
			SchemeUser:  !shouldBeAdmin,
			SchemeAdmin: shouldBeAdmin,
			NotifyProps: model.GetDefaultClassNotifyProps(),
		}

		_, err = a.Srv().Store.Class().SaveMember(cm)

		a.invalidateCacheForClassMembers(class.Id)

		message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_USER_ADDED, "", class.Id, "", nil)
		message.Add("user_id", user.Id)
		message.Add("branch_id", class.BranchId)
		a.Publish(message)

	}

	return err
}

func (a *App) CreateClassWithUser(class *model.Class, userId string) (*model.Class, *model.AppError) {

	if strings.Index(class.Name, "__") > 0 {
		return nil, model.NewAppError("CreateClassWithUser", "api.class.create_class.invalid_character.app_error", nil, "", http.StatusBadRequest)
	}

	if len(class.BranchId) == 0 {
		return nil, model.NewAppError("CreateClassWithUser", "app.class.create_class.no_branch_id.app_error", nil, "", http.StatusBadRequest)
	}

	// Get total number of classes on current branch
	count, err := a.GetNumberOfClassesOnBranch(class.BranchId)
	if err != nil {
		return nil, err
	}

	if int64(count+1) > *a.Config().BranchSettings.MaxClassesPerBranch {
		return nil, model.NewAppError("CreateClassWithUser", "api.class.create_class.max_class_limit.app_error", map[string]interface{}{"MaxClassesPerBranch": *a.Config().BranchSettings.MaxClassesPerBranch}, "", http.StatusBadRequest)
	}

	class.CreatorId = userId

	rclass, err := a.CreateClass(class, true)
	if err != nil {
		return nil, err
	}

	if _, err = a.GetUser(userId); err != nil {
		return nil, err
	}

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_CREATED, "", "", userId, nil)
	message.Add("class_id", class.Id)
	message.Add("branch_id", class.BranchId)
	a.Publish(message)

	return rclass, nil
}

// RenameClass is used to rename the class Name and the DisplayName fields
func (a *App) RenameClass(class *model.Class, newClassName string, newDisplayName string) (*model.Class, *model.AppError) {

	class.Name = newClassName
	if newDisplayName != "" {
		class.DisplayName = newDisplayName
	}

	newClass, err := a.UpdateClass(class)
	if err != nil {
		return nil, err
	}

	return newClass, nil
}

func (a *App) CreateClass(class *model.Class, addMember bool) (*model.Class, *model.AppError) {
	class.DisplayName = strings.TrimSpace(class.DisplayName)

	sc, err := a.Srv().Store.Class().Save(class, *a.Config().BranchSettings.MaxClassesPerBranch)
	if err != nil {
		return nil, err
	}

	if addMember {
		user, err := a.Srv().Store.User().Get(class.CreatorId)
		if err != nil {
			return nil, err
		}

		cm := &model.ClassMember{
			ClassId:     sc.Id,
			UserId:      user.Id,
			SchemeUser:  true,
			SchemeAdmin: true,
			NotifyProps: model.GetDefaultClassNotifyProps(),
		}

		if _, err := a.Srv().Store.Class().SaveMember(cm); err != nil {
			return nil, err
		}

		a.InvalidateCacheForUser(class.CreatorId)
	}

	return sc, nil
}

func (a *App) WaitForClassMembership(classId string, userId string) {
	if len(a.Config().SqlSettings.DataSourceReplicas) == 0 {
		return
	}

	now := model.GetMillis()

	for model.GetMillis()-now < 12000 {

		time.Sleep(100 * time.Millisecond)

		_, err := a.Srv().Store.Class().GetMember(classId, userId)

		// If the membership was found then return
		if err == nil {
			return
		}

		// If we received an error, but it wasn't a missing class member then return
		if err.Id != store.MISSING_CLASS_MEMBER_ERROR {
			return
		}
	}

	mlog.Error("WaitForClassMembership giving up", mlog.String("class_id", classId), mlog.String("user_id", userId))
}

// UpdateClass updates a given class by its Id. It also publishes the CLASS_UPDATED event.
func (a *App) UpdateClass(class *model.Class) (*model.Class, *model.AppError) {
	// userIds := strings.Split(class.Name, "__")

	_, err := a.Srv().Store.Class().Update(class)
	if err != nil {
		return nil, err
	}

	a.invalidateCacheForClass(class)

	messageWs := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_UPDATED, "", class.Id, "", nil)
	messageWs.Add("class", class.ToJson())
	a.Publish(messageWs)

	return class, nil
}

// CreateClassScheme creates a new Scheme of scope class and assigns it to the class.
func (a *App) CreateClassScheme(class *model.Class) (*model.Scheme, *model.AppError) {
	scheme, err := a.CreateScheme(&model.Scheme{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Scope:       model.SCHEME_SCOPE_CLASS,
	})
	if err != nil {
		return nil, err
	}

	class.SchemeId = &scheme.Id
	if _, err := a.UpdateClassScheme(class); err != nil {
		return nil, err
	}
	return scheme, nil
}

// DeleteClassScheme deletes a classes scheme and sets its SchemeId to nil.
func (a *App) DeleteClassScheme(class *model.Class) (*model.Class, *model.AppError) {
	if _, err := a.DeleteScheme(*class.SchemeId); err != nil {
		return nil, err
	}
	class.SchemeId = nil
	return a.UpdateClassScheme(class)
}

// UpdateClassScheme saves the new SchemeId of the class passed.
func (a *App) UpdateClassScheme(class *model.Class) (*model.Class, *model.AppError) {
	var oldClass *model.Class
	var err *model.AppError
	if oldClass, err = a.GetClass(class.Id); err != nil {
		return nil, err
	}

	oldClass.SchemeId = class.SchemeId
	return a.UpdateClass(oldClass)
}

func (a *App) UpdateClassPrivacy(oldClass *model.Class, user *model.User) (*model.Class, *model.AppError) {
	class, err := a.UpdateClass(oldClass)
	if err != nil {
		return class, err
	}

	a.invalidateCacheForClass(class)

	messageWs := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_CONVERTED, class.BranchId, "", "", nil)
	messageWs.Add("class_id", class.Id)
	a.Publish(messageWs)

	return class, nil
}

func (a *App) RestoreClass(class *model.Class, userId string) (*model.Class, *model.AppError) {
	if class.DeleteAt == 0 {
		return nil, model.NewAppError("restoreClass", "api.class.restore_class.restored.app_error", nil, "", http.StatusBadRequest)
	}

	if err := a.Srv().Store.Class().Restore(class.Id, model.GetMillis()); err != nil {
		return nil, err
	}
	class.DeleteAt = 0
	a.invalidateCacheForClass(class)

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_RESTORED, class.BranchId, "", "", nil)
	message.Add("class_id", class.Id)
	a.Publish(message)

	_, err := a.Srv().Store.User().Get(userId)
	if err != nil {
		return nil, err
	}

	return class, nil
}

func (a *App) PatchClass(class *model.Class, patch *model.ClassPatch, userId string) (*model.Class, *model.AppError) {

	class.Patch(patch)
	class, err := a.UpdateClass(class)
	if err != nil {
		return nil, err
	}

	return class, nil
}

// GetSchemeRolesForClass Checks if a class or its branch has an override scheme for class roles and returns the scheme roles or default class roles.
func (a *App) GetSchemeRolesForClass(classId string) (userRoleName string, adminRoleName string, err *model.AppError) {
	class, err := a.GetClass(classId)
	if err != nil {
		return
	}

	if class.SchemeId != nil && len(*class.SchemeId) != 0 {
		var scheme *model.Scheme
		scheme, err = a.GetScheme(*class.SchemeId)
		if err != nil {
			return
		}

		userRoleName = scheme.DefaultClassUserRole
		adminRoleName = scheme.DefaultClassAdminRole

		return
	}

	return a.GetBranchSchemeClassRoles(class.BranchId)
}

// GetBranchSchemeClassRoles Checks if a branch has an override scheme and returns the scheme class role names or default class role names.
func (a *App) GetBranchSchemeClassRoles(branchId string) (userRoleName string, adminRoleName string, err *model.AppError) {
	branch, err := a.GetBranch(branchId)
	if err != nil {
		return
	}

	if branch.SchemeId != nil && len(*branch.SchemeId) != 0 {
		var scheme *model.Scheme
		scheme, err = a.GetScheme(*branch.SchemeId)
		if err != nil {
			return
		}

		userRoleName = scheme.DefaultClassUserRole
		adminRoleName = scheme.DefaultClassAdminRole
	} else {
		userRoleName = model.CLASS_USER_ROLE_ID
		adminRoleName = model.CLASS_ADMIN_ROLE_ID
	}

	return
}

// GetClassModerationsForClass Gets a classes ClassModerations from either the higherScoped roles or from the class scheme roles.
func (a *App) GetClassModerationsForClass(class *model.Class) ([]*model.ClassModeration, *model.AppError) {
	memberRoleName, _, err := a.GetSchemeRolesForClass(class.Id)
	if err != nil {
		return nil, err
	}

	memberRole, err := a.GetRoleByName(memberRoleName)
	if err != nil {
		return nil, err
	}

	higherScopedMemberRoleName, _, err := a.GetBranchSchemeClassRoles(class.BranchId)
	if err != nil {
		return nil, err
	}
	higherScopedMemberRole, err := a.GetRoleByName(higherScopedMemberRoleName)
	if err != nil {
		return nil, err
	}

	return buildClassModerations(memberRole, higherScopedMemberRole), nil
}

// PatchClassModerationsForClass Updates a classes scheme roles based on a given ClassModerationPatch, if the permissions match the higher scoped role the scheme is deleted.
func (a *App) PatchClassModerationsForClass(class *model.Class, classModerationsPatch []*model.ClassModerationPatch) ([]*model.ClassModeration, *model.AppError) {
	higherScopedMemberRoleName, _, _ := a.GetBranchSchemeClassRoles(class.BranchId)
	higherScopedMemberRole, err := a.GetRoleByName(higherScopedMemberRoleName)
	if err != nil {
		return nil, err
	}

	higherScopedMemberPermissions := higherScopedMemberRole.GetClassModeratedPermissions()

	for _, moderationPatch := range classModerationsPatch {
		if moderationPatch.Roles.Members != nil && *moderationPatch.Roles.Members && !higherScopedMemberPermissions[*moderationPatch.Name] {
			return nil, &model.AppError{Message: "Cannot add a permission that is restricted by the branch or system permission scheme"}
		}
	}

	// Class has no scheme so create one
	if class.SchemeId == nil || len(*class.SchemeId) == 0 {
		if _, err = a.CreateClassScheme(class); err != nil {
			return nil, err
		}

		message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_SCHEME_UPDATED, "", class.Id, "", nil)
		a.Publish(message)
		mlog.Info("Permission scheme created.", mlog.String("class_id", class.Id), mlog.String("class_name", class.Name))
	}

	memberRoleName, _, _ := a.GetSchemeRolesForClass(class.Id)
	memberRole, err := a.GetRoleByName(memberRoleName)
	if err != nil {
		return nil, err
	}

	memberRolePatch := memberRole.RolePatchFromClassModerationsPatch(classModerationsPatch, "members")

	for _, classModerationPatch := range classModerationsPatch {
		permissionModified := *classModerationPatch.Name

		if classModerationPatch.Roles.Members != nil && utils.StringInSlice(permissionModified, model.ClassModeratedPermissionsChangedByPatch(memberRole, memberRolePatch)) {
			if *classModerationPatch.Roles.Members {
				mlog.Info("Permission enabled for members.", mlog.String("permission", permissionModified), mlog.String("class_id", class.Id), mlog.String("class_name", class.Name))
			} else {
				mlog.Info("Permission disabled for members.", mlog.String("permission", permissionModified), mlog.String("class_id", class.Id), mlog.String("class_name", class.Name))
			}
		}
	}

	memberRolePermissionsUnmodified := len(model.ClassModeratedPermissionsChangedByPatch(higherScopedMemberRole, memberRolePatch)) == 0
	if memberRolePermissionsUnmodified {
		// The class scheme matches the permissions of its higherScoped scheme so delete the scheme
		if _, err = a.DeleteClassScheme(class); err != nil {
			return nil, err
		}

		message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_SCHEME_UPDATED, "", class.Id, "", nil)
		a.Publish(message)

		memberRole = higherScopedMemberRole
		mlog.Info("Permission scheme deleted.", mlog.String("class_id", class.Id), mlog.String("class_name", class.Name))
	} else {
		memberRole, err = a.PatchRole(memberRole, memberRolePatch)
		if err != nil {
			return nil, err
		}
		if err != nil {
			return nil, err
		}
	}

	return buildClassModerations(memberRole, higherScopedMemberRole), nil
}

func buildClassModerations(memberRole *model.Role, higherScopedMemberRole *model.Role) []*model.ClassModeration {
	var memberPermissions, higherScopedMemberPermissions map[string]bool
	if memberRole != nil {
		memberPermissions = memberRole.GetClassModeratedPermissions()
	}
	if higherScopedMemberRole != nil {
		higherScopedMemberPermissions = higherScopedMemberRole.GetClassModeratedPermissions()
	}

	var classModerations []*model.ClassModeration
	for _, permissionKey := range model.CLASS_MODERATED_PERMISSIONS {
		roles := &model.ClassModeratedRoles{}

		roles.Members = &model.ClassModeratedRole{
			Value:   memberPermissions[permissionKey],
			Enabled: higherScopedMemberPermissions[permissionKey],
		}

		moderation := &model.ClassModeration{
			Name:  permissionKey,
			Roles: roles,
		}

		classModerations = append(classModerations, moderation)
	}

	return classModerations
}

func (a *App) UpdateClassMemberRoles(classId string, userId string, newRoles string) (*model.ClassMember, *model.AppError) {
	var member *model.ClassMember
	var err *model.AppError
	if member, err = a.GetClassMember(classId, userId); err != nil {
		return nil, err
	}

	schemeUserRole, schemeAdminRole, err := a.GetSchemeRolesForClass(classId)
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
				// If not part of the scheme for this class, then it is not allowed to apply it as an explicit role.
				return nil, model.NewAppError("UpdateClassMemberRoles", "api.class.update_class_member_roles.scheme_role.app_error", nil, "role_name="+roleName, http.StatusBadRequest)
			}
		}
	}

	member.ExplicitRoles = strings.Join(newExplicitRoles, " ")

	member, err = a.Srv().Store.Class().UpdateMember(member)
	if err != nil {
		return nil, err
	}

	a.InvalidateCacheForUser(userId)
	return member, nil
}

func (a *App) UpdateClassMemberSchemeRoles(classId string, userId string, isSchemeUser bool, isSchemeAdmin bool) (*model.ClassMember, *model.AppError) {
	member, err := a.GetClassMember(classId, userId)
	if err != nil {
		return nil, err
	}

	member.SchemeAdmin = isSchemeAdmin
	member.SchemeUser = isSchemeUser

	// If the migration is not completed, we also need to check the default class_admin/class_user roles are not present in the roles field.
	if err = a.IsPhase2MigrationCompleted(); err != nil {
		member.ExplicitRoles = RemoveRoles([]string{model.CLASS_USER_ROLE_ID, model.CLASS_ADMIN_ROLE_ID}, member.ExplicitRoles)
	}

	member, err = a.Srv().Store.Class().UpdateMember(member)
	if err != nil {
		return nil, err
	}

	// Notify the clients that the member notify props changed
	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_MEMBER_UPDATED, "", "", userId, nil)
	message.Add("classMember", member.ToJson())
	a.Publish(message)

	a.InvalidateCacheForUser(userId)
	return member, nil
}

func (a *App) UpdateClassMemberNotifyProps(data map[string]string, classId string, userId string) (*model.ClassMember, *model.AppError) {
	var member *model.ClassMember
	var err *model.AppError
	if member, err = a.GetClassMember(classId, userId); err != nil {
		return nil, err
	}

	// update whichever notify properties have been provided, but don't change the others
	if markUnread, exists := data[model.MARK_UNREAD_NOTIFY_PROP]; exists {
		member.NotifyProps[model.MARK_UNREAD_NOTIFY_PROP] = markUnread
	}

	if desktop, exists := data[model.DESKTOP_NOTIFY_PROP]; exists {
		member.NotifyProps[model.DESKTOP_NOTIFY_PROP] = desktop
	}

	if email, exists := data[model.EMAIL_NOTIFY_PROP]; exists {
		member.NotifyProps[model.EMAIL_NOTIFY_PROP] = email
	}

	if push, exists := data[model.PUSH_NOTIFY_PROP]; exists {
		member.NotifyProps[model.PUSH_NOTIFY_PROP] = push
	}

	if ignoreClassMentions, exists := data[model.IGNORE_CLASS_MENTIONS_NOTIFY_PROP]; exists {
		member.NotifyProps[model.IGNORE_CLASS_MENTIONS_NOTIFY_PROP] = ignoreClassMentions
	}

	member, err = a.Srv().Store.Class().UpdateMember(member)
	if err != nil {
		return nil, err
	}

	a.InvalidateCacheForUser(userId)
	a.invalidateCacheForClassMembersNotifyProps(classId)
	// Notify the clients that the member notify props changed
	evt := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_MEMBER_UPDATED, "", "", userId, nil)
	evt.Add("classMember", member.ToJson())
	a.Publish(evt)
	return member, nil
}

func (a *App) DeleteClass(class *model.Class, userId string) *model.AppError {
	ihc := make(chan store.StoreResult, 1)
	ohc := make(chan store.StoreResult, 1)

	go func() {
		webhooks, err := a.Srv().Store.Webhook().GetIncomingByClass(class.Id)
		ihc <- store.StoreResult{Data: webhooks, Err: err}
		close(ihc)
	}()

	go func() {
		outgoingHooks, err := a.Srv().Store.Webhook().GetOutgoingByClass(class.Id, -1, -1)
		ohc <- store.StoreResult{Data: outgoingHooks, Err: err}
		close(ohc)
	}()

	if userId != "" {
		_, err := a.Srv().Store.User().Get(userId)
		if err != nil {
			return err
		}
	}

	ihcresult := <-ihc
	if ihcresult.Err != nil {
		return ihcresult.Err
	}

	ohcresult := <-ohc
	if ohcresult.Err != nil {
		return ohcresult.Err
	}

	incomingHooks := ihcresult.Data.([]*model.IncomingWebhook)
	outgoingHooks := ohcresult.Data.([]*model.OutgoingWebhook)

	if class.DeleteAt > 0 {
		err := model.NewAppError("deleteClass", "api.class.delete_class.deleted.app_error", nil, "", http.StatusBadRequest)
		return err
	}

	if class.Name == model.DEFAULT_CLASS {
		err := model.NewAppError("deleteClass", "api.class.delete_class.cannot.app_error", map[string]interface{}{"Class": model.DEFAULT_CLASS}, "", http.StatusBadRequest)
		return err
	}

	now := model.GetMillis()
	for _, hook := range incomingHooks {
		if err := a.Srv().Store.Webhook().DeleteIncoming(hook.Id, now); err != nil {
			mlog.Error("Encountered error deleting incoming webhook", mlog.String("hook_id", hook.Id), mlog.Err(err))
		}
		a.invalidateCacheForWebhook(hook.Id)
	}

	for _, hook := range outgoingHooks {
		if err := a.Srv().Store.Webhook().DeleteOutgoing(hook.Id, now); err != nil {
			mlog.Error("Encountered error deleting outgoing webhook", mlog.String("hook_id", hook.Id), mlog.Err(err))
		}
	}

	deleteAt := model.GetMillis()

	if err := a.Srv().Store.Class().Delete(class.Id, deleteAt); err != nil {
		return err
	}
	a.invalidateCacheForClass(class)

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_DELETED, class.BranchId, "", "", nil)
	message.Add("class_id", class.Id)
	message.Add("delete_at", deleteAt)
	a.Publish(message)

	return nil
}

func (a *App) addUserToClass(user *model.User, class *model.Class, branchMember *model.BranchMember) (*model.ClassMember, *model.AppError) {

	classMember, err := a.Srv().Store.Class().GetMember(class.Id, user.Id)
	if err != nil {
		if err.Id != store.MISSING_CLASS_MEMBER_ERROR {
			return nil, err
		}
	} else {
		return classMember, nil
	}

	newMember := &model.ClassMember{
		ClassId:     class.Id,
		UserId:      user.Id,
		NotifyProps: model.GetDefaultClassNotifyProps(),
		SchemeUser:  true,
	}

	newMember, err = a.Srv().Store.Class().SaveMember(newMember)
	if err != nil {
		mlog.Error("Failed to add member", mlog.String("user_id", user.Id), mlog.String("class_id", class.Id), mlog.Err(err))
		return nil, model.NewAppError("AddUserToClass", "api.class.add_user.to.class.failed.app_error", nil, "", http.StatusInternalServerError)
	}
	a.WaitForClassMembership(class.Id, user.Id)

	a.InvalidateCacheForUser(user.Id)
	a.invalidateCacheForClassMembers(class.Id)

	return newMember, nil
}

func (a *App) AddUserToClass(user *model.User, class *model.Class) (*model.ClassMember, *model.AppError) {
	branchMember, err := a.Srv().Store.Branch().GetMember(class.BranchId, user.Id)

	if err != nil {
		return nil, err
	}
	if branchMember.DeleteAt > 0 {
		return nil, model.NewAppError("AddUserToClass", "api.class.add_user.to.class.failed.deleted.app_error", nil, "", http.StatusBadRequest)
	}

	newMember, err := a.addUserToClass(user, class, branchMember)
	if err != nil {
		return nil, err
	}

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_USER_ADDED, "", class.Id, "", nil)
	message.Add("user_id", user.Id)
	message.Add("branch_id", class.BranchId)
	a.Publish(message)

	return newMember, nil
}

func (a *App) AddClassMember(userId string, class *model.Class, userRequestorId string, postRootId string) (*model.ClassMember, *model.AppError) {
	if member, err := a.Srv().Store.Class().GetMember(class.Id, userId); err != nil {
		if err.Id != store.MISSING_CLASS_MEMBER_ERROR {
			return nil, err
		}
	} else {
		return member, nil
	}

	var user *model.User
	var err *model.AppError

	if user, err = a.GetUser(userId); err != nil {
		return nil, err
	}

	if userRequestorId != "" {
		if _, err = a.GetUser(userRequestorId); err != nil {
			return nil, err
		}
	}

	cm, err := a.AddUserToClass(user, class)
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (a *App) AddDirectClasses(branchId string, user *model.User) *model.AppError {
	var profiles []*model.User
	options := &model.UserGetOptions{InBranchId: branchId, Page: 0, PerPage: 100}
	profiles, err := a.Srv().Store.User().GetProfiles(options)
	if err != nil {
		return model.NewAppError("AddDirectClasses", "api.user.add_direct_classes_and_forget.failed.error", map[string]interface{}{"UserId": user.Id, "BranchId": branchId, "Error": err.Error()}, "", http.StatusInternalServerError)
	}

	var preferences model.Preferences

	for _, profile := range profiles {
		if profile.Id == user.Id {
			continue
		}

		preference := model.Preference{
			UserId:   user.Id,
			Category: model.PREFERENCE_CATEGORY_DIRECT_CLASS_SHOW,
			Name:     profile.Id,
			Value:    "true",
		}

		preferences = append(preferences, preference)

		if len(preferences) >= 10 {
			break
		}
	}

	if err := a.Srv().Store.Preference().Save(&preferences); err != nil {
		return model.NewAppError("AddDirectClasses", "api.user.add_direct_classes_and_forget.failed.error", map[string]interface{}{"UserId": user.Id, "BranchId": branchId, "Error": err.Error()}, "", http.StatusInternalServerError)
	}

	return nil
}

func (a *App) GetClass(classId string) (*model.Class, *model.AppError) {
	class, errCh := a.Srv().Store.Class().Get(classId, true)
	if errCh != nil {
		if errCh.Id == "store.sql_class.get.existing.app_error" {
			errCh.StatusCode = http.StatusNotFound
			return nil, errCh
		}
		errCh.StatusCode = http.StatusBadRequest
		return nil, errCh
	}
	return class, nil
}

func (a *App) GetClassByName(className, branchId string, includeDeleted bool) (*model.Class, *model.AppError) {
	var class *model.Class
	var err *model.AppError

	if includeDeleted {
		class, err = a.Srv().Store.Class().GetByNameIncludeDeleted(branchId, className, false)
	} else {
		class, err = a.Srv().Store.Class().GetByName(branchId, className, false)
	}

	if err != nil && err.Id == "store.sql_class.get_by_name.missing.app_error" {
		err.StatusCode = http.StatusNotFound
		return nil, err
	}

	if err != nil {
		err.StatusCode = http.StatusBadRequest
		return nil, err
	}

	return class, nil
}

func (a *App) GetClassesByNames(classNames []string, branchId string) ([]*model.Class, *model.AppError) {
	classes, err := a.Srv().Store.Class().GetByNames(branchId, classNames, true)
	if err != nil {
		if err.Id == "store.sql_class.get_by_name.missing.app_error" {
			err.StatusCode = http.StatusNotFound
			return nil, err
		}
		err.StatusCode = http.StatusBadRequest
		return nil, err
	}
	return classes, nil
}

func (a *App) GetClassByNameForBranchName(className, branchName string, includeDeleted bool) (*model.Class, *model.AppError) {
	var branch *model.Branch

	branch, err := a.Srv().Store.Branch().GetByName(branchName)
	if err != nil {
		err.StatusCode = http.StatusNotFound
		return nil, err
	}

	var result *model.Class

	if includeDeleted {
		result, err = a.Srv().Store.Class().GetByNameIncludeDeleted(branch.Id, className, false)
	} else {
		result, err = a.Srv().Store.Class().GetByName(branch.Id, className, false)
	}

	if err != nil && err.Id == "store.sql_class.get_by_name.missing.app_error" {
		err.StatusCode = http.StatusNotFound
		return nil, err
	}

	if err != nil {
		err.StatusCode = http.StatusBadRequest
		return nil, err
	}

	return result, nil
}

func (a *App) GetClassesForUser(branchId string, userId string, includeDeleted bool) (*model.ClassList, *model.AppError) {
	return a.Srv().Store.Class().GetClasses(branchId, userId, includeDeleted)
}

func (a *App) GetAllClasses(page, perPage int, opts model.ClassSearchOpts) (*model.ClassListWithBranchData, *model.AppError) {
	if opts.ExcludeDefaultClasses {
		opts.ExcludeClassNames = a.DefaultClassNames()
	}
	storeOpts := store.ClassSearchOpts{
		ExcludeClassNames: opts.ExcludeClassNames,
		IncludeDeleted:    opts.IncludeDeleted,
	}
	return a.Srv().Store.Class().GetAllClasses(page*perPage, perPage, storeOpts)
}

func (a *App) GetAllClassesCount(opts model.ClassSearchOpts) (int64, *model.AppError) {
	if opts.ExcludeDefaultClasses {
		opts.ExcludeClassNames = a.DefaultClassNames()
	}
	storeOpts := store.ClassSearchOpts{
		ExcludeClassNames: opts.ExcludeClassNames,
		IncludeDeleted:    opts.IncludeDeleted,
	}
	return a.Srv().Store.Class().GetAllClassesCount(storeOpts)
}

func (a *App) GetDeletedClasses(branchId string, offset int, limit int, userId string) (*model.ClassList, *model.AppError) {
	return a.Srv().Store.Class().GetDeleted(branchId, offset, limit, userId)
}

func (a *App) GetClassesUserNotIn(branchId string, userId string, offset int, limit int) (*model.ClassList, *model.AppError) {
	return a.Srv().Store.Class().GetMoreClasses(branchId, userId, offset, limit)
}

func (a *App) GetClassMember(classId string, userId string) (*model.ClassMember, *model.AppError) {
	return a.Srv().Store.Class().GetMember(classId, userId)
}

func (a *App) GetClassMembersPage(classId string, page, perPage int) (*model.ClassMembers, *model.AppError) {
	return a.Srv().Store.Class().GetMembers(classId, page*perPage, perPage)
}

func (a *App) GetClassMembersTimezones(classId string) ([]string, *model.AppError) {
	membersTimezones, err := a.Srv().Store.Class().GetClassMembersTimezones(classId)
	if err != nil {
		return nil, err
	}

	var timezones []string
	for _, membersTimezone := range membersTimezones {
		if membersTimezone["automaticTimezone"] == "" && membersTimezone["manualTimezone"] == "" {
			continue
		}
		timezones = append(timezones, model.GetPreferredTimezone(membersTimezone))
	}

	return model.RemoveDuplicateStrings(timezones), nil
}

func (a *App) GetClassMembersByIds(classId string, userIds []string) (*model.ClassMembers, *model.AppError) {
	return a.Srv().Store.Class().GetMembersByIds(classId, userIds)
}

func (a *App) GetClassMembersForUser(branchId string, userId string) (*model.ClassMembers, *model.AppError) {
	return a.Srv().Store.Class().GetMembersForUser(branchId, userId)
}

func (a *App) GetClassMembersForUserWithPagination(branchId, userId string, page, perPage int) ([]*model.ClassMember, *model.AppError) {
	m, err := a.Srv().Store.Class().GetMembersForUserWithPagination(branchId, userId, page, perPage)
	if err != nil {
		return nil, err
	}

	members := make([]*model.ClassMember, 0)
	if m != nil {
		for _, member := range *m {
			member := member
			members = append(members, &member)
		}
	}
	return members, nil
}

func (a *App) GetClassMemberCount(classId string) (int64, *model.AppError) {
	return a.Srv().Store.Class().GetMemberCount(classId, true)
}

func (a *App) JoinClass(class *model.Class, userId string) *model.AppError {
	userChan := make(chan store.StoreResult, 1)
	memberChan := make(chan store.StoreResult, 1)
	go func() {
		user, err := a.Srv().Store.User().Get(userId)
		userChan <- store.StoreResult{Data: user, Err: err}
		close(userChan)
	}()
	go func() {
		member, err := a.Srv().Store.Class().GetMember(class.Id, userId)
		memberChan <- store.StoreResult{Data: member, Err: err}
		close(memberChan)
	}()

	uresult := <-userChan
	if uresult.Err != nil {
		return uresult.Err
	}

	mresult := <-memberChan
	if mresult.Err == nil && mresult.Data != nil {
		// user is already in the class
		return nil
	}

	user := uresult.Data.(*model.User)

	_, err := a.AddUserToClass(user, class)
	if err != nil {
		return err
	}

	return nil
}

func (a *App) LeaveClass(classId string, userId string) *model.AppError {
	sc := make(chan store.StoreResult, 1)
	go func() {
		class, err := a.Srv().Store.Class().Get(classId, true)
		sc <- store.StoreResult{Data: class, Err: err}
		close(sc)
	}()

	uc := make(chan store.StoreResult, 1)
	go func() {
		user, err := a.Srv().Store.User().Get(userId)
		uc <- store.StoreResult{Data: user, Err: err}
		close(uc)
	}()

	mcc := make(chan store.StoreResult, 1)
	go func() {
		count, err := a.Srv().Store.Class().GetMemberCount(classId, false)
		mcc <- store.StoreResult{Data: count, Err: err}
		close(mcc)
	}()

	cresult := <-sc
	if cresult.Err != nil {
		return cresult.Err
	}
	uresult := <-uc
	if uresult.Err != nil {
		return cresult.Err
	}
	ccresult := <-mcc
	if ccresult.Err != nil {
		return ccresult.Err
	}

	class := cresult.Data.(*model.Class)

	if err := a.removeUserFromClass(userId, userId, class); err != nil {
		return err
	}

	if class.Name == model.DEFAULT_CLASS && !*a.Config().ServiceSettings.ExperimentalEnableDefaultClassLeaveJoinMessages {
		return nil
	}

	return nil
}

func (a *App) removeUserFromClass(userIdToRemove string, removerUserId string, class *model.Class) *model.AppError {
	user, err := a.Srv().Store.User().Get(userIdToRemove)
	if err != nil {
		return err
	}
	isGuest := user.IsGuest()

	if class.Name == model.DEFAULT_CLASS {
		if !isGuest {
			return model.NewAppError("RemoveUserFromClass", "api.class.remove.default.app_error", map[string]interface{}{"Class": model.DEFAULT_CLASS}, "", http.StatusBadRequest)
		}
	}

	_, err = a.GetClassMember(class.Id, userIdToRemove)
	if err != nil {
		return err
	}

	if err := a.Srv().Store.Class().RemoveMember(class.Id, userIdToRemove); err != nil {
		return err
	}

	if isGuest {
		currentMembers, err := a.GetClassMembersForUser(class.BranchId, userIdToRemove)
		if err != nil {
			return err
		}
		if len(*currentMembers) == 0 {
			branchMember, err := a.GetBranchMember(class.BranchId, userIdToRemove)
			if err != nil {
				return model.NewAppError("removeUserFromClass", "api.branch.remove_user_from_branch.missing.app_error", nil, err.Error(), http.StatusBadRequest)
			}

			if err = a.RemoveBranchMemberFromBranch(branchMember, removerUserId); err != nil {
				return err
			}
		}
	}

	a.InvalidateCacheForUser(userIdToRemove)
	a.invalidateCacheForClassMembers(class.Id)

	message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_USER_REMOVED, "", class.Id, "", nil)
	message.Add("user_id", userIdToRemove)
	message.Add("remover_id", removerUserId)
	a.Publish(message)

	// because the removed user no longer belongs to the class we need to send a separate websocket event
	userMsg := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_USER_REMOVED, "", "", userIdToRemove, nil)
	userMsg.Add("class_id", class.Id)
	userMsg.Add("remover_id", removerUserId)
	a.Publish(userMsg)

	return nil
}

func (a *App) RemoveUserFromClass(userIdToRemove string, removerUserId string, class *model.Class) *model.AppError {
	var err *model.AppError

	if err = a.removeUserFromClass(userIdToRemove, removerUserId, class); err != nil {
		return err
	}

	if _, err = a.GetUser(userIdToRemove); err != nil {
		return err
	}

	return nil
}

func (a *App) GetNumberOfClassesOnBranch(branchId string) (int, *model.AppError) {
	// Get total number of classes on current branch
	list, err := a.Srv().Store.Class().GetBranchClasses(branchId)
	if err != nil {
		return 0, err
	}
	return len(*list), nil
}

func (a *App) SetActiveClass(userId string, classId string) *model.AppError {
	status, err := a.GetStatus(userId)

	oldStatus := model.STATUS_OFFLINE

	if err != nil {
		status = &model.Status{UserId: userId, Status: model.STATUS_ONLINE, Manual: false, LastActivityAt: model.GetMillis(), ActiveClass: classId}
	} else {
		oldStatus = status.Status
		status.ActiveClass = classId
		if !status.Manual && classId != "" {
			status.Status = model.STATUS_ONLINE
		}
		status.LastActivityAt = model.GetMillis()
	}

	a.AddStatusCache(status)

	if status.Status != oldStatus {
		a.BroadcastStatus(status)
	}

	return nil
}

// func (a *App) UpdateClassLastViewedAt(classIds []string, userId string) *model.AppError {
// 	if _, err := a.Srv().Store.Class().UpdateLastViewedAt(classIds, userId); err != nil {
// 		return err
// 	}
//
// 	if *a.Config().ServiceSettings.EnableClassViewedMessages {
// 		for _, classId := range classIds {
// 			message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_VIEWED, "", "", userId, nil)
// 			message.Add("class_id", classId)
// 			a.Publish(message)
// 		}
// 	}
//
// 	return nil
// }

// func (a *App) ViewClass(view *model.ClassView, userId string, currentSessionId string) (map[string]int64, *model.AppError) {
// 	if err := a.SetActiveClass(userId, view.ClassId); err != nil {
// 		return nil, err
// 	}
//
// 	classIds := []string{}
//
// 	if len(view.ClassId) > 0 {
// 		classIds = append(classIds, view.ClassId)
// 	}
//
// 	if len(view.PrevClassId) > 0 {
// 		classIds = append(classIds, view.PrevClassId)
// 	}
//
// 	if len(classIds) == 0 {
// 		return map[string]int64{}, nil
// 	}
//
// 	return a.MarkClassesAsViewed(classIds, userId, currentSessionId)
// }

func (a *App) PermanentDeleteClass(class *model.Class) *model.AppError {

	if err := a.Srv().Store.Class().PermanentDeleteMembersByClass(class.Id); err != nil {
		return err
	}

	if err := a.Srv().Store.Webhook().PermanentDeleteIncomingByClass(class.Id); err != nil {
		return err
	}

	if err := a.Srv().Store.Webhook().PermanentDeleteOutgoingByClass(class.Id); err != nil {
		return err
	}

	if err := a.Srv().Store.Class().PermanentDelete(class.Id); err != nil {
		return err
	}

	return nil
}

// This function is intended for use from the CLI. It is not robust against people joining the class while the move
// is in progress, and therefore should not be used from the API without first fixing this potential race condition.
func (a *App) MoveClass(branch *model.Branch, class *model.Class, user *model.User, removeDeactivatedMembers bool) *model.AppError {
	if removeDeactivatedMembers {
		if err := a.Srv().Store.Class().RemoveAllDeactivatedMembers(class.Id); err != nil {
			return err
		}
	}

	// Check that all class members are in the destination branch.
	classMembers, err := a.GetClassMembersPage(class.Id, 0, 10000000)
	if err != nil {
		return err
	}

	classMemberIds := []string{}
	for _, classMember := range *classMembers {
		classMemberIds = append(classMemberIds, classMember.UserId)
	}

	if len(classMemberIds) > 0 {
		branchMembers, err2 := a.GetBranchMembersByIds(branch.Id, classMemberIds, nil)
		if err2 != nil {
			return err2
		}

		if len(branchMembers) != len(*classMembers) {
			return model.NewAppError("MoveClass", "app.class.move_class.members_do_not_match.error", nil, "", http.StatusInternalServerError)
		}
	}

	// keep instance of the previous branch
	_, err = a.Srv().Store.Branch().Get(class.BranchId)
	if err != nil {
		return err
	}

	class.BranchId = branch.Id
	if _, err := a.Srv().Store.Class().Update(class); err != nil {
		return err
	}

	return nil
}

func (a *App) ClearClassMembersCache(classID string) {
	perPage := 100
	page := 0

	for {
		classMembers, err := a.Srv().Store.Class().GetMembers(classID, page, perPage)
		if err != nil {
			a.Log().Warn("error clearing cache for class members", mlog.String("class_id", classID))
			break
		}

		for _, classMember := range *classMembers {
			a.ClearSessionCacheForUser(classMember.UserId)

			message := model.NewWebSocketEvent(model.WEBSOCKET_EVENT_CLASS_MEMBER_UPDATED, "", "", classMember.UserId, nil)
			message.Add("classMember", classMember.ToJson())
			a.Publish(message)
		}

		length := len(*(classMembers))
		if length < perPage {
			break
		}

		page++
	}
}
