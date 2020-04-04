// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"io"
	"strings"
)

var BuiltInSchemeManagedRoleIDs []string

func init() {
	BuiltInSchemeManagedRoleIDs = []string{
		SYSTEM_GUEST_ROLE_ID,
		SYSTEM_USER_ROLE_ID,
		SYSTEM_ADMIN_ROLE_ID,
		SYSTEM_POST_ALL_ROLE_ID,
		SYSTEM_POST_ALL_PUBLIC_ROLE_ID,
		SYSTEM_USER_ACCESS_TOKEN_ROLE_ID,

		BRANCH_USER_ROLE_ID,
		BRANCH_ADMIN_ROLE_ID,
		BRANCH_POST_ALL_ROLE_ID,
		BRANCH_POST_ALL_PUBLIC_ROLE_ID,

		CLASS_USER_ROLE_ID,
		CLASS_ADMIN_ROLE_ID,
	}
}

type RoleType string
type RoleScope string

const (
	SYSTEM_GUEST_ROLE_ID             = "system_guest"
	SYSTEM_USER_ROLE_ID              = "system_user"
	SYSTEM_ADMIN_ROLE_ID             = "system_admin"
	SYSTEM_POST_ALL_ROLE_ID          = "system_post_all"
	SYSTEM_POST_ALL_PUBLIC_ROLE_ID   = "system_post_all_public"
	SYSTEM_USER_ACCESS_TOKEN_ROLE_ID = "system_user_access_token"

	BRANCH_POST_ALL_ROLE_ID        = "branch_post_all"
	BRANCH_POST_ALL_PUBLIC_ROLE_ID = "branch_post_all_public"

	BRANCH_USER_ROLE_ID  = "branch_user"
	BRANCH_ADMIN_ROLE_ID = "branch_admin"

	CLASS_USER_ROLE_ID  = "class_user"
	CLASS_ADMIN_ROLE_ID = "class_admin"

	ROLE_NAME_MAX_LENGTH         = 64
	ROLE_DISPLAY_NAME_MAX_LENGTH = 128
	ROLE_DESCRIPTION_MAX_LENGTH  = 1024

	RoleScopeSystem RoleScope = "System"
	RoleScopeBranch RoleScope = "Branch"
	RoleScopeClass  RoleScope = "Class"

	RoleTypeUser  RoleType = "User"
	RoleTypeAdmin RoleType = "Admin"
)

type Role struct {
	Id            string   `json:"id"`
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name"`
	Description   string   `json:"description"`
	CreateAt      int64    `json:"create_at"`
	UpdateAt      int64    `json:"update_at"`
	DeleteAt      int64    `json:"delete_at"`
	Permissions   []string `json:"permissions"`
	SchemeManaged bool     `json:"scheme_managed"`
	BuiltIn       bool     `json:"built_in"`
}

type RolePatch struct {
	Permissions *[]string `json:"permissions"`
}

type RolePermissions struct {
	RoleID      string
	Permissions []string
}

func (r *Role) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func RoleFromJson(data io.Reader) *Role {
	var r *Role
	json.NewDecoder(data).Decode(&r)
	return r
}

func RoleListToJson(r []*Role) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func RoleListFromJson(data io.Reader) []*Role {
	var roles []*Role
	json.NewDecoder(data).Decode(&roles)
	return roles
}

func (r *RolePatch) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func RolePatchFromJson(data io.Reader) *RolePatch {
	var rolePatch *RolePatch
	json.NewDecoder(data).Decode(&rolePatch)
	return rolePatch
}

func (r *Role) Patch(patch *RolePatch) {
	if patch.Permissions != nil {
		r.Permissions = *patch.Permissions
	}
}

// MergeClassHigherScopedPermissions is meant to be invoked on a class scheme's role and merges the higher-scoped
// class role's permissions.
func (r *Role) MergeClassHigherScopedPermissions(higherScopedPermissions *RolePermissions) {
	mergedPermissions := []string{}

	higherScopedPermissionsMap := AsStringBoolMap(higherScopedPermissions.Permissions)
	rolePermissionsMap := AsStringBoolMap(r.Permissions)

	for _, cp := range ALL_PERMISSIONS {
		if cp.Scope != PERMISSION_SCOPE_CLASS {
			continue
		}

		_, presentOnHigherScope := higherScopedPermissionsMap[cp.Id]

		// For the class admin role always look to the higher scope to determine if the role has ther permission.
		// The class admin is a special case because they're not part of the UI to be "class moderated", only
		// class members and class guests are.
		if higherScopedPermissions.RoleID == CLASS_ADMIN_ROLE_ID && presentOnHigherScope {
			mergedPermissions = append(mergedPermissions, cp.Id)
			continue
		}

		_, permissionIsModerated := CLASS_MODERATED_PERMISSIONS_MAP[cp.Id]
		if permissionIsModerated {
			_, presentOnRole := rolePermissionsMap[cp.Id]
			if presentOnRole && presentOnHigherScope {
				mergedPermissions = append(mergedPermissions, cp.Id)
			}
		} else {
			if presentOnHigherScope {
				mergedPermissions = append(mergedPermissions, cp.Id)
			}
		}
	}

	r.Permissions = mergedPermissions
}

// Returns an array of permissions that are in either role.Permissions
// or patch.Permissions, but not both.
func PermissionsChangedByPatch(role *Role, patch *RolePatch) []string {
	var result []string

	if patch.Permissions == nil {
		return result
	}

	roleMap := make(map[string]bool)
	patchMap := make(map[string]bool)

	for _, permission := range role.Permissions {
		roleMap[permission] = true
	}

	for _, permission := range *patch.Permissions {
		patchMap[permission] = true
	}

	for _, permission := range role.Permissions {
		if !patchMap[permission] {
			result = append(result, permission)
		}
	}

	for _, permission := range *patch.Permissions {
		if !roleMap[permission] {
			result = append(result, permission)
		}
	}

	return result
}

func (r *Role) IsValid() bool {
	if len(r.Id) != 26 {
		return false
	}

	return r.IsValidWithoutId()
}

func (r *Role) IsValidWithoutId() bool {
	if !IsValidRoleName(r.Name) {
		return false
	}

	if len(r.DisplayName) == 0 || len(r.DisplayName) > ROLE_DISPLAY_NAME_MAX_LENGTH {
		return false
	}

	if len(r.Description) > ROLE_DESCRIPTION_MAX_LENGTH {
		return false
	}

	for _, permission := range r.Permissions {
		permissionValidated := false
		for _, p := range ALL_PERMISSIONS {
			if permission == p.Id {
				permissionValidated = true
				break
			}
		}

		if !permissionValidated {
			return false
		}
	}

	return true
}

func IsValidRoleName(roleName string) bool {
	if len(roleName) <= 0 || len(roleName) > ROLE_NAME_MAX_LENGTH {
		return false
	}

	if strings.TrimLeft(roleName, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
		return false
	}

	return true
}

func MakeDefaultRoles() map[string]*Role {
	roles := make(map[string]*Role)

	roles[CLASS_USER_ROLE_ID] = &Role{
		Name:        "class_user",
		DisplayName: "authentication.roles.class_user.name",
		Description: "authentication.roles.class_user.description",
		Permissions: []string{
			PERMISSION_READ_CLASS.Id,
			PERMISSION_ADD_REACTION.Id,
			PERMISSION_REMOVE_REACTION.Id,
			PERMISSION_MANAGE_PUBLIC_CLASS_MEMBERS.Id,
			PERMISSION_UPLOAD_FILE.Id,
			PERMISSION_GET_PUBLIC_LINK.Id,
			PERMISSION_CREATE_POST.Id,
			PERMISSION_USE_CLASS_MENTIONS.Id,
			PERMISSION_USE_SLASH_COMMANDS.Id,
		},
		SchemeManaged: true,
		BuiltIn:       true,
	}

	roles[CLASS_ADMIN_ROLE_ID] = &Role{
		Name:        "class_admin",
		DisplayName: "authentication.roles.class_admin.name",
		Description: "authentication.roles.class_admin.description",
		Permissions: []string{
			PERMISSION_MANAGE_CLASS_ROLES.Id,
		},
		SchemeManaged: true,
		BuiltIn:       true,
	}

	roles[BRANCH_USER_ROLE_ID] = &Role{
		Name:        "branch_user",
		DisplayName: "authentication.roles.branch_user.name",
		Description: "authentication.roles.branch_user.description",
		Permissions: []string{
			PERMISSION_LIST_BRANCH_CLASSES.Id,
			PERMISSION_JOIN_PUBLIC_CLASSES.Id,
			PERMISSION_READ_PUBLIC_CLASS.Id,
			PERMISSION_VIEW_BRANCH.Id,
		},
		SchemeManaged: true,
		BuiltIn:       true,
	}

	roles[BRANCH_POST_ALL_ROLE_ID] = &Role{
		Name:        "branch_post_all",
		DisplayName: "authentication.roles.branch_post_all.name",
		Description: "authentication.roles.branch_post_all.description",
		Permissions: []string{
			PERMISSION_CREATE_POST.Id,
			PERMISSION_USE_CLASS_MENTIONS.Id,
		},
		SchemeManaged: false,
		BuiltIn:       true,
	}

	roles[BRANCH_POST_ALL_PUBLIC_ROLE_ID] = &Role{
		Name:        "branch_post_all_public",
		DisplayName: "authentication.roles.branch_post_all_public.name",
		Description: "authentication.roles.branch_post_all_public.description",
		Permissions: []string{
			PERMISSION_CREATE_POST_PUBLIC.Id,
			PERMISSION_USE_CLASS_MENTIONS.Id,
		},
		SchemeManaged: false,
		BuiltIn:       true,
	}

	roles[BRANCH_ADMIN_ROLE_ID] = &Role{
		Name:        "branch_admin",
		DisplayName: "authentication.roles.branch_admin.name",
		Description: "authentication.roles.branch_admin.description",
		Permissions: []string{
			PERMISSION_REMOVE_USER_FROM_BRANCH.Id,
			PERMISSION_MANAGE_BRANCH.Id,
			PERMISSION_IMPORT_BRANCH.Id,
			PERMISSION_MANAGE_BRANCH_ROLES.Id,
			PERMISSION_MANAGE_CLASS_ROLES.Id,
			PERMISSION_MANAGE_OTHERS_INCOMING_WEBHOOKS.Id,
			PERMISSION_MANAGE_OTHERS_OUTGOING_WEBHOOKS.Id,
			PERMISSION_MANAGE_SLASH_COMMANDS.Id,
			PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS.Id,
			PERMISSION_MANAGE_INCOMING_WEBHOOKS.Id,
			PERMISSION_MANAGE_OUTGOING_WEBHOOKS.Id,
		},
		SchemeManaged: true,
		BuiltIn:       true,
	}

	roles[SYSTEM_GUEST_ROLE_ID] = &Role{
		Name:        "system_guest",
		DisplayName: "authentication.roles.global_guest.name",
		Description: "authentication.roles.global_guest.description",
		Permissions: []string{
			PERMISSION_CREATE_DIRECT_CLASS.Id,
			PERMISSION_CREATE_GROUP_CLASS.Id,
		},
		SchemeManaged: true,
		BuiltIn:       true,
	}

	roles[SYSTEM_USER_ROLE_ID] = &Role{
		Name:        "system_user",
		DisplayName: "authentication.roles.global_user.name",
		Description: "authentication.roles.global_user.description",
		Permissions: []string{
			PERMISSION_LIST_PUBLIC_BRANCHES.Id,
			PERMISSION_JOIN_PUBLIC_BRANCHES.Id,
			PERMISSION_CREATE_DIRECT_CLASS.Id,
			PERMISSION_CREATE_GROUP_CLASS.Id,
			PERMISSION_VIEW_MEMBERS.Id,
		},
		SchemeManaged: true,
		BuiltIn:       true,
	}

	roles[SYSTEM_POST_ALL_ROLE_ID] = &Role{
		Name:        "system_post_all",
		DisplayName: "authentication.roles.system_post_all.name",
		Description: "authentication.roles.system_post_all.description",
		Permissions: []string{
			PERMISSION_CREATE_POST.Id,
			PERMISSION_USE_CLASS_MENTIONS.Id,
		},
		SchemeManaged: false,
		BuiltIn:       true,
	}

	roles[SYSTEM_POST_ALL_PUBLIC_ROLE_ID] = &Role{
		Name:        "system_post_all_public",
		DisplayName: "authentication.roles.system_post_all_public.name",
		Description: "authentication.roles.system_post_all_public.description",
		Permissions: []string{
			PERMISSION_CREATE_POST_PUBLIC.Id,
			PERMISSION_USE_CLASS_MENTIONS.Id,
		},
		SchemeManaged: false,
		BuiltIn:       true,
	}

	roles[SYSTEM_USER_ACCESS_TOKEN_ROLE_ID] = &Role{
		Name:        "system_user_access_token",
		DisplayName: "authentication.roles.system_user_access_token.name",
		Description: "authentication.roles.system_user_access_token.description",
		Permissions: []string{
			PERMISSION_CREATE_USER_ACCESS_TOKEN.Id,
			PERMISSION_READ_USER_ACCESS_TOKEN.Id,
			PERMISSION_REVOKE_USER_ACCESS_TOKEN.Id,
		},
		SchemeManaged: false,
		BuiltIn:       true,
	}

	roles[SYSTEM_ADMIN_ROLE_ID] = &Role{
		Name:        "system_admin",
		DisplayName: "authentication.roles.global_admin.name",
		Description: "authentication.roles.global_admin.description",
		// System admins can do anything class and branch admins can do
		// plus everything members of branches and classes can do to all branches
		// and classes on the system
		Permissions: append(
			append(
				append(
					append(
						[]string{
							PERMISSION_ASSIGN_SYSTEM_ADMIN_ROLE.Id,
							PERMISSION_MANAGE_SYSTEM.Id,
							PERMISSION_MANAGE_ROLES.Id,
							PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES.Id,
							PERMISSION_MANAGE_PUBLIC_CLASS_MEMBERS.Id,
							PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS.Id,
							PERMISSION_DELETE_PUBLIC_CLASS.Id,
							PERMISSION_CREATE_PUBLIC_CLASS.Id,
							PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES.Id,
							PERMISSION_DELETE_PRIVATE_CLASS.Id,
							PERMISSION_CREATE_PRIVATE_CLASS.Id,
							PERMISSION_MANAGE_SYSTEM_WIDE_OAUTH.Id,
							PERMISSION_MANAGE_OTHERS_INCOMING_WEBHOOKS.Id,
							PERMISSION_MANAGE_OTHERS_OUTGOING_WEBHOOKS.Id,
							PERMISSION_EDIT_OTHER_USERS.Id,
							PERMISSION_EDIT_OTHERS_POSTS.Id,
							PERMISSION_MANAGE_OAUTH.Id,
							PERMISSION_INVITE_USER.Id,
							PERMISSION_INVITE_GUEST.Id,
							PERMISSION_PROMOTE_GUEST.Id,
							PERMISSION_DEMOTE_TO_GUEST.Id,
							PERMISSION_DELETE_POST.Id,
							PERMISSION_DELETE_OTHERS_POSTS.Id,
							PERMISSION_CREATE_BRANCH.Id,
							PERMISSION_ADD_USER_TO_BRANCH.Id,
							PERMISSION_LIST_USERS_WITHOUT_BRANCH.Id,
							PERMISSION_MANAGE_JOBS.Id,
							PERMISSION_CREATE_POST_PUBLIC.Id,
							PERMISSION_CREATE_POST_EPHEMERAL.Id,
							PERMISSION_CREATE_USER_ACCESS_TOKEN.Id,
							PERMISSION_READ_USER_ACCESS_TOKEN.Id,
							PERMISSION_REVOKE_USER_ACCESS_TOKEN.Id,
							PERMISSION_CREATE_BOT.Id,
							PERMISSION_READ_BOTS.Id,
							PERMISSION_READ_OTHERS_BOTS.Id,
							PERMISSION_MANAGE_BOTS.Id,
							PERMISSION_MANAGE_OTHERS_BOTS.Id,
							PERMISSION_REMOVE_OTHERS_REACTIONS.Id,
							PERMISSION_LIST_PRIVATE_BRANCHES.Id,
							PERMISSION_JOIN_PRIVATE_BRANCHES.Id,
							PERMISSION_VIEW_MEMBERS.Id,
						},
						roles[BRANCH_USER_ROLE_ID].Permissions...,
					),
					roles[CLASS_USER_ROLE_ID].Permissions...,
				),
				roles[BRANCH_ADMIN_ROLE_ID].Permissions...,
			),
			roles[CLASS_ADMIN_ROLE_ID].Permissions...,
		),
		SchemeManaged: true,
		BuiltIn:       true,
	}

	return roles
}
