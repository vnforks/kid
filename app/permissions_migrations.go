// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"strings"

	"github.com/vnforks/kid/v5/model"
)

type permissionTransformation struct {
	On     func(*model.Role, map[string]map[string]bool) bool
	Add    []string
	Remove []string
}
type permissionsMap []permissionTransformation

const (
	PERMISSION_MANAGE_SYSTEM                   = "manage_system"
	PERMISSION_MANAGE_EMOJIS                   = "manage_emojis"
	PERMISSION_MANAGE_OTHERS_EMOJIS            = "manage_others_emojis"
	PERMISSION_CREATE_EMOJIS                   = "create_emojis"
	PERMISSION_DELETE_EMOJIS                   = "delete_emojis"
	PERMISSION_DELETE_OTHERS_EMOJIS            = "delete_others_emojis"
	PERMISSION_MANAGE_WEBHOOKS                 = "manage_webhooks"
	PERMISSION_MANAGE_OTHERS_WEBHOOKS          = "manage_others_webhooks"
	PERMISSION_MANAGE_INCOMING_WEBHOOKS        = "manage_incoming_webhooks"
	PERMISSION_MANAGE_OTHERS_INCOMING_WEBHOOKS = "manage_others_incoming_webhooks"
	PERMISSION_MANAGE_OUTGOING_WEBHOOKS        = "manage_outgoing_webhooks"
	PERMISSION_MANAGE_OTHERS_OUTGOING_WEBHOOKS = "manage_others_outgoing_webhooks"
	PERMISSION_LIST_BRANCHES                   = "list_branches"
	PERMISSION_PERMANENT_DELETE_USER           = "permanent_delete_user"
	PERMISSION_DELETE_CLASS                    = "delete_class"
	PERMISSION_MANAGE_CLASS                    = "manage_class"
	PERMISSION_VIEW_MEMBERS                    = "view_members"
	PERMISSION_USE_CLASS_MENTIONS              = "use_class_mentions"
	PERMISSION_CREATE_POST                     = "create_post"
	PERMISSION_ADD_REACTION                    = "add_reaction"
	PERMISSION_REMOVE_REACTION                 = "remove_reaction"
	PERMISSION_MANAGE_CLASS_MEMBERS            = "manage_class_members"
)

func isRole(roleName string) func(*model.Role, map[string]map[string]bool) bool {
	return func(role *model.Role, permissionsMap map[string]map[string]bool) bool {
		return role.Name == roleName
	}
}

func isNotRole(roleName string) func(*model.Role, map[string]map[string]bool) bool {
	return func(role *model.Role, permissionsMap map[string]map[string]bool) bool {
		return role.Name != roleName
	}
}

func isNotSchemeRole(roleName string) func(*model.Role, map[string]map[string]bool) bool {
	return func(role *model.Role, permissionsMap map[string]map[string]bool) bool {
		return !strings.Contains(role.DisplayName, roleName)
	}
}

func permissionExists(permission string) func(*model.Role, map[string]map[string]bool) bool {
	return func(role *model.Role, permissionsMap map[string]map[string]bool) bool {
		val, ok := permissionsMap[role.Name][permission]
		return ok && val
	}
}

func permissionNotExists(permission string) func(*model.Role, map[string]map[string]bool) bool {
	return func(role *model.Role, permissionsMap map[string]map[string]bool) bool {
		val, ok := permissionsMap[role.Name][permission]
		return !(ok && val)
	}
}

func onOtherRole(otherRole string, function func(*model.Role, map[string]map[string]bool) bool) func(*model.Role, map[string]map[string]bool) bool {
	return func(role *model.Role, permissionsMap map[string]map[string]bool) bool {
		return function(&model.Role{Name: otherRole}, permissionsMap)
	}
}

func permissionOr(funcs ...func(*model.Role, map[string]map[string]bool) bool) func(*model.Role, map[string]map[string]bool) bool {
	return func(role *model.Role, permissionsMap map[string]map[string]bool) bool {
		for _, f := range funcs {
			if f(role, permissionsMap) {
				return true
			}
		}
		return false
	}
}

func permissionAnd(funcs ...func(*model.Role, map[string]map[string]bool) bool) func(*model.Role, map[string]map[string]bool) bool {
	return func(role *model.Role, permissionsMap map[string]map[string]bool) bool {
		for _, f := range funcs {
			if !f(role, permissionsMap) {
				return false
			}
		}
		return true
	}
}

func applyPermissionsMap(role *model.Role, roleMap map[string]map[string]bool, migrationMap permissionsMap) []string {
	var result []string

	roleName := role.Name
	for _, transformation := range migrationMap {
		if transformation.On(role, roleMap) {
			for _, permission := range transformation.Add {
				roleMap[roleName][permission] = true
			}
			for _, permission := range transformation.Remove {
				roleMap[roleName][permission] = false
			}
		}
	}

	for key, active := range roleMap[roleName] {
		if active {
			result = append(result, key)
		}
	}
	return result
}

func (a *App) doPermissionsMigration(key string, migrationMap permissionsMap) *model.AppError {
	if _, err := a.Srv().Store.System().GetByName(key); err == nil {
		return nil
	}

	roles, err := a.GetAllRoles()
	if err != nil {
		return err
	}

	roleMap := make(map[string]map[string]bool)
	for _, role := range roles {
		roleMap[role.Name] = make(map[string]bool)
		for _, permission := range role.Permissions {
			roleMap[role.Name][permission] = true
		}
	}

	for _, role := range roles {
		role.Permissions = applyPermissionsMap(role, roleMap, migrationMap)
		if _, err := a.Srv().Store.Role().Save(role); err != nil {
			return err
		}
	}

	if err := a.Srv().Store.System().Save(&model.System{Name: key, Value: "true"}); err != nil {
		return err
	}
	return nil
}

func (a *App) getEmojisPermissionsSplitMigration() (permissionsMap, error) {
	return permissionsMap{
		permissionTransformation{
			On:     permissionExists(PERMISSION_MANAGE_EMOJIS),
			Add:    []string{PERMISSION_CREATE_EMOJIS, PERMISSION_DELETE_EMOJIS},
			Remove: []string{PERMISSION_MANAGE_EMOJIS},
		},
		permissionTransformation{
			On:     permissionExists(PERMISSION_MANAGE_OTHERS_EMOJIS),
			Add:    []string{PERMISSION_DELETE_OTHERS_EMOJIS},
			Remove: []string{PERMISSION_MANAGE_OTHERS_EMOJIS},
		},
	}, nil
}

func (a *App) getWebhooksPermissionsSplitMigration() (permissionsMap, error) {
	return permissionsMap{
		permissionTransformation{
			On:     permissionExists(PERMISSION_MANAGE_WEBHOOKS),
			Add:    []string{PERMISSION_MANAGE_INCOMING_WEBHOOKS, PERMISSION_MANAGE_OUTGOING_WEBHOOKS},
			Remove: []string{PERMISSION_MANAGE_WEBHOOKS},
		},
		permissionTransformation{
			On:     permissionExists(PERMISSION_MANAGE_OTHERS_WEBHOOKS),
			Add:    []string{PERMISSION_MANAGE_OTHERS_INCOMING_WEBHOOKS, PERMISSION_MANAGE_OTHERS_OUTGOING_WEBHOOKS},
			Remove: []string{PERMISSION_MANAGE_OTHERS_WEBHOOKS},
		},
	}, nil
}

func (a *App) removePermanentDeleteUserMigration() (permissionsMap, error) {
	return permissionsMap{
		permissionTransformation{
			On:     permissionExists(PERMISSION_PERMANENT_DELETE_USER),
			Remove: []string{PERMISSION_PERMANENT_DELETE_USER},
		},
	}, nil
}

func (a *App) applyClassManageDeleteToClassUser() (permissionsMap, error) {
	return permissionsMap{
		permissionTransformation{
			On:  permissionAnd(isRole(model.CLASS_USER_ROLE_ID), onOtherRole(model.BRANCH_USER_ROLE_ID, permissionExists(PERMISSION_DELETE_CLASS))),
			Add: []string{PERMISSION_DELETE_CLASS},
		},
		permissionTransformation{
			On:  permissionAnd(isRole(model.CLASS_USER_ROLE_ID), onOtherRole(model.BRANCH_USER_ROLE_ID, permissionExists(PERMISSION_MANAGE_CLASS))),
			Add: []string{PERMISSION_MANAGE_CLASS},
		},
	}, nil
}

func (a *App) removeClassManageDeleteFromBranchUser() (permissionsMap, error) {
	return permissionsMap{
		permissionTransformation{
			On:     permissionAnd(isRole(model.BRANCH_USER_ROLE_ID), permissionExists(PERMISSION_MANAGE_CLASS)),
			Remove: []string{PERMISSION_MANAGE_CLASS},
		},
		permissionTransformation{
			On:     permissionAnd(isRole(model.BRANCH_USER_ROLE_ID), permissionExists(PERMISSION_DELETE_CLASS)),
			Remove: []string{model.PERMISSION_DELETE_CLASS.Id},
		},
	}, nil
}

func (a *App) getViewMembersPermissionMigration() (permissionsMap, error) {
	return permissionsMap{
		permissionTransformation{
			On:  isRole(model.SYSTEM_USER_ROLE_ID),
			Add: []string{PERMISSION_VIEW_MEMBERS},
		},
		permissionTransformation{
			On:  isRole(model.SYSTEM_ADMIN_ROLE_ID),
			Add: []string{PERMISSION_VIEW_MEMBERS},
		},
	}, nil
}

func (a *App) classModerationPermissionsMigration() (permissionsMap, error) {
	transformations := permissionsMap{}

	var allBranchSchemes []*model.Scheme
	next := a.SchemesIterator(model.SCHEME_SCOPE_BRANCH, 100)
	var schemeBatch []*model.Scheme
	for schemeBatch = next(); len(schemeBatch) > 0; schemeBatch = next() {
		allBranchSchemes = append(allBranchSchemes, schemeBatch...)
	}

	moderatedPermissionsMinusCreatePost := []string{
		PERMISSION_ADD_REACTION,
		PERMISSION_REMOVE_REACTION,
		PERMISSION_MANAGE_CLASS_MEMBERS,
		PERMISSION_USE_CLASS_MENTIONS,
	}

	branchAndClassAdminConditionalTransformations := func(branchAdminID, classAdminID, classUserID string) []permissionTransformation {
		transformations := []permissionTransformation{}

		for _, perm := range moderatedPermissionsMinusCreatePost {
			// add each moderated permission to the class admin if class user or guest has the permission
			trans := permissionTransformation{
				On: permissionAnd(
					isRole(classAdminID),
					permissionOr(
						onOtherRole(classUserID, permissionExists(perm)),
					),
				),
				Add: []string{perm},
			}
			transformations = append(transformations, trans)

			// add each moderated permission to the branch admin if class admin, user, or guest has the permission
			trans = permissionTransformation{
				On: permissionAnd(
					isRole(branchAdminID),
					permissionOr(
						onOtherRole(classAdminID, permissionExists(perm)),
						onOtherRole(classUserID, permissionExists(perm)),
					),
				),
				Add: []string{perm},
			}
			transformations = append(transformations, trans)
		}

		return transformations
	}

	for _, ts := range allBranchSchemes {
		// ensure all branch scheme class admins have create_post because it's not exposed via the UI
		trans := permissionTransformation{
			On:  isRole(ts.DefaultClassAdminRole),
			Add: []string{PERMISSION_CREATE_POST},
		}
		transformations = append(transformations, trans)

		// ensure all branch scheme branch admins have create_post because it's not exposed via the UI
		trans = permissionTransformation{
			On:  isRole(ts.DefaultBranchAdminRole),
			Add: []string{PERMISSION_CREATE_POST},
		}
		transformations = append(transformations, trans)

		// conditionally add all other moderated permissions to branch and class admins
		transformations = append(transformations, branchAndClassAdminConditionalTransformations(
			ts.DefaultBranchAdminRole,
			ts.DefaultClassAdminRole,
			ts.DefaultClassUserRole,
		)...)
	}

	// ensure branch admins have create_post
	transformations = append(transformations, permissionTransformation{
		On:  isRole(model.BRANCH_ADMIN_ROLE_ID),
		Add: []string{PERMISSION_CREATE_POST},
	})

	// ensure class admins have create_post
	transformations = append(transformations, permissionTransformation{
		On:  isRole(model.CLASS_ADMIN_ROLE_ID),
		Add: []string{PERMISSION_CREATE_POST},
	})

	// conditionally add all other moderated permissions to branch and class admins
	transformations = append(transformations, branchAndClassAdminConditionalTransformations(
		model.BRANCH_ADMIN_ROLE_ID,
		model.CLASS_ADMIN_ROLE_ID,
		model.CLASS_USER_ROLE_ID,
	)...)

	// ensure system admin has all of the moderated permissions
	transformations = append(transformations, permissionTransformation{
		On:  isRole(model.SYSTEM_ADMIN_ROLE_ID),
		Add: append(moderatedPermissionsMinusCreatePost, PERMISSION_CREATE_POST),
	})

	// add the new use_class_mentions permission to everyone who has create_post
	transformations = append(transformations, permissionTransformation{
		On:  permissionOr(permissionExists(PERMISSION_CREATE_POST)),
		Add: []string{PERMISSION_USE_CLASS_MENTIONS},
	})

	return transformations, nil
}

// DoPermissionsMigrations execute all the permissions migrations need by the current version.
func (a *App) DoPermissionsMigrations() error {
	PermissionsMigrations := []struct {
		Key       string
		Migration func() (permissionsMap, error)
	}{
		{Key: model.MIGRATION_KEY_EMOJI_PERMISSIONS_SPLIT, Migration: a.getEmojisPermissionsSplitMigration},
		{Key: model.MIGRATION_KEY_WEBHOOK_PERMISSIONS_SPLIT, Migration: a.getWebhooksPermissionsSplitMigration},
		{Key: model.MIGRATION_KEY_REMOVE_PERMANENT_DELETE_USER, Migration: a.removePermanentDeleteUserMigration},
		{Key: model.MIGRATION_KEY_APPLY_CLASS_MANAGE_DELETE_TO_CLASS_USER, Migration: a.applyClassManageDeleteToClassUser},
		{Key: model.MIGRATION_KEY_REMOVE_CLASS_MANAGE_DELETE_FROM_BRANCH_USER, Migration: a.removeClassManageDeleteFromBranchUser},
		{Key: model.MIGRATION_KEY_VIEW_MEMBERS_NEW_PERMISSION, Migration: a.getViewMembersPermissionMigration},
		{Key: model.MIGRATION_KEY_CLASS_MODERATIONS_PERMISSIONS, Migration: a.classModerationPermissionsMigration},
	}

	for _, migration := range PermissionsMigrations {
		migMap, err := migration.Migration()
		if err != nil {
			return err
		}
		if err := a.doPermissionsMigration(migration.Key, migMap); err != nil {
			return err
		}
	}
	return nil
}
