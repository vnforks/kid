// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package utils

import (
	"github.com/vnforks/kid/v5/model"
)

func SetRolePermissionsFromConfig(roles map[string]*model.Role, cfg *model.Config, isLicensed bool) map[string]*model.Role {
	if isLicensed {
		switch *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictPublicClassCreation {
		case model.PERMISSIONS_ALL:
			roles[model.BRANCH_USER_ROLE_ID].Permissions = append(
				roles[model.BRANCH_USER_ROLE_ID].Permissions,
				model.PERMISSION_CREATE_PUBLIC_CLASS.Id,
			)
		case model.PERMISSIONS_BRANCH_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_CREATE_PUBLIC_CLASS.Id,
			)
		}
	} else {
		roles[model.BRANCH_USER_ROLE_ID].Permissions = append(
			roles[model.BRANCH_USER_ROLE_ID].Permissions,
			model.PERMISSION_CREATE_PUBLIC_CLASS.Id,
		)
	}

	if isLicensed {
		switch *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictPublicClassManagement {
		case model.PERMISSIONS_ALL:
			roles[model.CLASS_USER_ROLE_ID].Permissions = append(
				roles[model.CLASS_USER_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES.Id,
			)
		case model.PERMISSIONS_CLASS_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES.Id,
			)
			roles[model.CLASS_ADMIN_ROLE_ID].Permissions = append(
				roles[model.CLASS_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES.Id,
			)
		case model.PERMISSIONS_BRANCH_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES.Id,
			)
		}
	} else {
		roles[model.CLASS_USER_ROLE_ID].Permissions = append(
			roles[model.CLASS_USER_ROLE_ID].Permissions,
			model.PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES.Id,
		)
	}

	if isLicensed {
		switch *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictPublicClassDeletion {
		case model.PERMISSIONS_ALL:
			roles[model.CLASS_USER_ROLE_ID].Permissions = append(
				roles[model.CLASS_USER_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_PUBLIC_CLASS.Id,
			)
		case model.PERMISSIONS_CLASS_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_PUBLIC_CLASS.Id,
			)
			roles[model.CLASS_ADMIN_ROLE_ID].Permissions = append(
				roles[model.CLASS_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_PUBLIC_CLASS.Id,
			)
		case model.PERMISSIONS_BRANCH_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_PUBLIC_CLASS.Id,
			)
		}
	} else {
		roles[model.CLASS_USER_ROLE_ID].Permissions = append(
			roles[model.CLASS_USER_ROLE_ID].Permissions,
			model.PERMISSION_DELETE_PUBLIC_CLASS.Id,
		)
	}

	if isLicensed {
		switch *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictPrivateClassCreation {
		case model.PERMISSIONS_ALL:
			roles[model.BRANCH_USER_ROLE_ID].Permissions = append(
				roles[model.BRANCH_USER_ROLE_ID].Permissions,
				model.PERMISSION_CREATE_PRIVATE_CLASS.Id,
			)
		case model.PERMISSIONS_BRANCH_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_CREATE_PRIVATE_CLASS.Id,
			)
		}
	} else {
		roles[model.BRANCH_USER_ROLE_ID].Permissions = append(
			roles[model.BRANCH_USER_ROLE_ID].Permissions,
			model.PERMISSION_CREATE_PRIVATE_CLASS.Id,
		)
	}

	if isLicensed {
		switch *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictPrivateClassManagement {
		case model.PERMISSIONS_ALL:
			roles[model.CLASS_USER_ROLE_ID].Permissions = append(
				roles[model.CLASS_USER_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES.Id,
			)
		case model.PERMISSIONS_CLASS_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES.Id,
			)
			roles[model.CLASS_ADMIN_ROLE_ID].Permissions = append(
				roles[model.CLASS_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES.Id,
			)
		case model.PERMISSIONS_BRANCH_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES.Id,
			)
		}
	} else {
		roles[model.CLASS_USER_ROLE_ID].Permissions = append(
			roles[model.CLASS_USER_ROLE_ID].Permissions,
			model.PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES.Id,
		)
	}

	if isLicensed {
		switch *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictPrivateClassDeletion {
		case model.PERMISSIONS_ALL:
			roles[model.CLASS_USER_ROLE_ID].Permissions = append(
				roles[model.CLASS_USER_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_PRIVATE_CLASS.Id,
			)
		case model.PERMISSIONS_CLASS_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_PRIVATE_CLASS.Id,
			)
			roles[model.CLASS_ADMIN_ROLE_ID].Permissions = append(
				roles[model.CLASS_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_PRIVATE_CLASS.Id,
			)
		case model.PERMISSIONS_BRANCH_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_PRIVATE_CLASS.Id,
			)
		}
	} else {
		roles[model.CLASS_USER_ROLE_ID].Permissions = append(
			roles[model.CLASS_USER_ROLE_ID].Permissions,
			model.PERMISSION_DELETE_PRIVATE_CLASS.Id,
		)
	}

	// Restrict permissions for Private Class Manage Members
	if isLicensed {
		switch *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictPrivateClassManageMembers {
		case model.PERMISSIONS_ALL:
			roles[model.CLASS_USER_ROLE_ID].Permissions = append(
				roles[model.CLASS_USER_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS.Id,
			)
		case model.PERMISSIONS_CLASS_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS.Id,
			)
			roles[model.CLASS_ADMIN_ROLE_ID].Permissions = append(
				roles[model.CLASS_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS.Id,
			)
		case model.PERMISSIONS_BRANCH_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS.Id,
			)
		}
	} else {
		roles[model.CLASS_USER_ROLE_ID].Permissions = append(
			roles[model.CLASS_USER_ROLE_ID].Permissions,
			model.PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS.Id,
		)
	}

	if !*cfg.ServiceSettings.DEPRECATED_DO_NOT_USE_EnableOnlyAdminIntegrations {
		roles[model.BRANCH_USER_ROLE_ID].Permissions = append(
			roles[model.BRANCH_USER_ROLE_ID].Permissions,
			model.PERMISSION_MANAGE_INCOMING_WEBHOOKS.Id,
			model.PERMISSION_MANAGE_OUTGOING_WEBHOOKS.Id,
			model.PERMISSION_MANAGE_SLASH_COMMANDS.Id,
		)
		roles[model.SYSTEM_USER_ROLE_ID].Permissions = append(
			roles[model.SYSTEM_USER_ROLE_ID].Permissions,
			model.PERMISSION_MANAGE_OAUTH.Id,
		)
	}

	// Grant permissions for inviting and adding users to a branch.
	if isLicensed {
		if *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictBranchInvite == model.PERMISSIONS_BRANCH_ADMIN {
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_INVITE_USER.Id,
				model.PERMISSION_ADD_USER_TO_BRANCH.Id,
			)
		} else if *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_RestrictBranchInvite == model.PERMISSIONS_ALL {
			roles[model.BRANCH_USER_ROLE_ID].Permissions = append(
				roles[model.BRANCH_USER_ROLE_ID].Permissions,
				model.PERMISSION_INVITE_USER.Id,
				model.PERMISSION_ADD_USER_TO_BRANCH.Id,
			)
		}
	} else {
		roles[model.BRANCH_USER_ROLE_ID].Permissions = append(
			roles[model.BRANCH_USER_ROLE_ID].Permissions,
			model.PERMISSION_INVITE_USER.Id,
			model.PERMISSION_ADD_USER_TO_BRANCH.Id,
		)
	}

	if isLicensed {
		switch *cfg.ServiceSettings.DEPRECATED_DO_NOT_USE_RestrictPostDelete {
		case model.PERMISSIONS_DELETE_POST_ALL:
			roles[model.CLASS_USER_ROLE_ID].Permissions = append(
				roles[model.CLASS_USER_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_POST.Id,
			)
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_POST.Id,
				model.PERMISSION_DELETE_OTHERS_POSTS.Id,
			)
		case model.PERMISSIONS_DELETE_POST_BRANCH_ADMIN:
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
				roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_DELETE_POST.Id,
				model.PERMISSION_DELETE_OTHERS_POSTS.Id,
			)
		}
	} else {
		roles[model.CLASS_USER_ROLE_ID].Permissions = append(
			roles[model.CLASS_USER_ROLE_ID].Permissions,
			model.PERMISSION_DELETE_POST.Id,
		)
		roles[model.BRANCH_ADMIN_ROLE_ID].Permissions = append(
			roles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
			model.PERMISSION_DELETE_POST.Id,
			model.PERMISSION_DELETE_OTHERS_POSTS.Id,
		)
	}

	if *cfg.BranchSettings.DEPRECATED_DO_NOT_USE_EnableBranchCreation {
		roles[model.SYSTEM_USER_ROLE_ID].Permissions = append(
			roles[model.SYSTEM_USER_ROLE_ID].Permissions,
			model.PERMISSION_CREATE_BRANCH.Id,
		)
	}

	if isLicensed {
		switch *cfg.ServiceSettings.DEPRECATED_DO_NOT_USE_AllowEditPost {
		case model.ALLOW_EDIT_POST_ALWAYS, model.ALLOW_EDIT_POST_TIME_LIMIT:
			roles[model.CLASS_USER_ROLE_ID].Permissions = append(
				roles[model.CLASS_USER_ROLE_ID].Permissions,
				model.PERMISSION_EDIT_POST.Id,
			)
			roles[model.SYSTEM_ADMIN_ROLE_ID].Permissions = append(
				roles[model.SYSTEM_ADMIN_ROLE_ID].Permissions,
				model.PERMISSION_EDIT_POST.Id,
			)
		}
	} else {
		roles[model.CLASS_USER_ROLE_ID].Permissions = append(
			roles[model.CLASS_USER_ROLE_ID].Permissions,
			model.PERMISSION_EDIT_POST.Id,
		)
		roles[model.SYSTEM_ADMIN_ROLE_ID].Permissions = append(
			roles[model.SYSTEM_ADMIN_ROLE_ID].Permissions,
			model.PERMISSION_EDIT_POST.Id,
		)
	}

	return roles
}
