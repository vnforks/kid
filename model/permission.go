// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

const (
	PERMISSION_SCOPE_SYSTEM = "system_scope"
	PERMISSION_SCOPE_BRANCH = "branch_scope"
	PERMISSION_SCOPE_CLASS  = "class_scope"
)

type Permission struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Scope       string `json:"scope"`
}

var PERMISSION_INVITE_USER *Permission
var PERMISSION_ADD_USER_TO_BRANCH *Permission
var PERMISSION_USE_SLASH_COMMANDS *Permission
var PERMISSION_MANAGE_SLASH_COMMANDS *Permission
var PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS *Permission
var PERMISSION_CREATE_PUBLIC_CLASS *Permission
var PERMISSION_CREATE_PRIVATE_CLASS *Permission
var PERMISSION_MANAGE_PUBLIC_CLASS_MEMBERS *Permission
var PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS *Permission
var PERMISSION_ASSIGN_SYSTEM_ADMIN_ROLE *Permission
var PERMISSION_MANAGE_ROLES *Permission
var PERMISSION_MANAGE_BRANCH_ROLES *Permission
var PERMISSION_MANAGE_CLASS_ROLES *Permission
var PERMISSION_CREATE_DIRECT_CLASS *Permission
var PERMISSION_CREATE_GROUP_CLASS *Permission
var PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES *Permission
var PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES *Permission
var PERMISSION_LIST_PUBLIC_BRANCHES *Permission
var PERMISSION_JOIN_PUBLIC_BRANCHES *Permission
var PERMISSION_LIST_PRIVATE_BRANCHES *Permission
var PERMISSION_JOIN_PRIVATE_BRANCHES *Permission
var PERMISSION_LIST_BRANCH_CLASSES *Permission
var PERMISSION_JOIN_PUBLIC_CLASSES *Permission
var PERMISSION_DELETE_PUBLIC_CLASS *Permission
var PERMISSION_DELETE_PRIVATE_CLASS *Permission
var PERMISSION_EDIT_OTHER_USERS *Permission
var PERMISSION_READ_CLASS *Permission
var PERMISSION_READ_PUBLIC_CLASS *Permission
var PERMISSION_ADD_REACTION *Permission
var PERMISSION_REMOVE_REACTION *Permission
var PERMISSION_REMOVE_OTHERS_REACTIONS *Permission
var PERMISSION_PERMANENT_DELETE_USER *Permission
var PERMISSION_UPLOAD_FILE *Permission
var PERMISSION_GET_PUBLIC_LINK *Permission
var PERMISSION_MANAGE_WEBHOOKS *Permission
var PERMISSION_MANAGE_OTHERS_WEBHOOKS *Permission
var PERMISSION_MANAGE_INCOMING_WEBHOOKS *Permission
var PERMISSION_MANAGE_OUTGOING_WEBHOOKS *Permission
var PERMISSION_MANAGE_OTHERS_INCOMING_WEBHOOKS *Permission
var PERMISSION_MANAGE_OTHERS_OUTGOING_WEBHOOKS *Permission
var PERMISSION_MANAGE_OAUTH *Permission
var PERMISSION_MANAGE_SYSTEM_WIDE_OAUTH *Permission
var PERMISSION_MANAGE_EMOJIS *Permission
var PERMISSION_MANAGE_OTHERS_EMOJIS *Permission
var PERMISSION_CREATE_EMOJIS *Permission
var PERMISSION_DELETE_EMOJIS *Permission
var PERMISSION_DELETE_OTHERS_EMOJIS *Permission
var PERMISSION_CREATE_POST *Permission
var PERMISSION_CREATE_POST_PUBLIC *Permission
var PERMISSION_CREATE_POST_EPHEMERAL *Permission
var PERMISSION_EDIT_POST *Permission
var PERMISSION_EDIT_OTHERS_POSTS *Permission
var PERMISSION_DELETE_POST *Permission
var PERMISSION_DELETE_OTHERS_POSTS *Permission
var PERMISSION_REMOVE_USER_FROM_BRANCH *Permission
var PERMISSION_CREATE_BRANCH *Permission
var PERMISSION_MANAGE_BRANCH *Permission
var PERMISSION_IMPORT_BRANCH *Permission
var PERMISSION_VIEW_BRANCH *Permission
var PERMISSION_LIST_USERS_WITHOUT_BRANCH *Permission
var PERMISSION_MANAGE_JOBS *Permission
var PERMISSION_CREATE_USER_ACCESS_TOKEN *Permission
var PERMISSION_READ_USER_ACCESS_TOKEN *Permission
var PERMISSION_REVOKE_USER_ACCESS_TOKEN *Permission
var PERMISSION_CREATE_BOT *Permission
var PERMISSION_ASSIGN_BOT *Permission
var PERMISSION_READ_BOTS *Permission
var PERMISSION_READ_OTHERS_BOTS *Permission
var PERMISSION_MANAGE_BOTS *Permission
var PERMISSION_MANAGE_OTHERS_BOTS *Permission
var PERMISSION_VIEW_MEMBERS *Permission
var PERMISSION_INVITE_GUEST *Permission
var PERMISSION_PROMOTE_GUEST *Permission
var PERMISSION_DEMOTE_TO_GUEST *Permission
var PERMISSION_USE_CLASS_MENTIONS *Permission
var PERMISSION_USE_GROUP_MENTIONS *Permission

// General permission that encompasses all system admin functions
// in the future this could be broken up to allow access to some
// admin functions but not others
var PERMISSION_MANAGE_SYSTEM *Permission

var ALL_PERMISSIONS []*Permission

var CLASS_MODERATED_PERMISSIONS []string
var CLASS_MODERATED_PERMISSIONS_MAP map[string]string

func initializePermissions() {
	PERMISSION_INVITE_USER = &Permission{
		"invite_user",
		"authentication.permissions.branch_invite_user.name",
		"authentication.permissions.branch_invite_user.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_ADD_USER_TO_BRANCH = &Permission{
		"add_user_to_branch",
		"authentication.permissions.add_user_to_branch.name",
		"authentication.permissions.add_user_to_branch.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_USE_SLASH_COMMANDS = &Permission{
		"use_slash_commands",
		"authentication.permissions.branch_use_slash_commands.name",
		"authentication.permissions.branch_use_slash_commands.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_MANAGE_SLASH_COMMANDS = &Permission{
		"manage_slash_commands",
		"authentication.permissions.manage_slash_commands.name",
		"authentication.permissions.manage_slash_commands.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS = &Permission{
		"manage_others_slash_commands",
		"authentication.permissions.manage_others_slash_commands.name",
		"authentication.permissions.manage_others_slash_commands.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_CREATE_PUBLIC_CLASS = &Permission{
		"create_public_class",
		"authentication.permissions.create_public_class.name",
		"authentication.permissions.create_public_class.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_CREATE_PRIVATE_CLASS = &Permission{
		"create_private_class",
		"authentication.permissions.create_private_class.name",
		"authentication.permissions.create_private_class.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_MANAGE_PUBLIC_CLASS_MEMBERS = &Permission{
		"manage_public_class_members",
		"authentication.permissions.manage_public_class_members.name",
		"authentication.permissions.manage_public_class_members.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS = &Permission{
		"manage_private_class_members",
		"authentication.permissions.manage_private_class_members.name",
		"authentication.permissions.manage_private_class_members.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_ASSIGN_SYSTEM_ADMIN_ROLE = &Permission{
		"assign_system_admin_role",
		"authentication.permissions.assign_system_admin_role.name",
		"authentication.permissions.assign_system_admin_role.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_MANAGE_ROLES = &Permission{
		"manage_roles",
		"authentication.permissions.manage_roles.name",
		"authentication.permissions.manage_roles.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_MANAGE_BRANCH_ROLES = &Permission{
		"manage_branch_roles",
		"authentication.permissions.manage_branch_roles.name",
		"authentication.permissions.manage_branch_roles.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_MANAGE_CLASS_ROLES = &Permission{
		"manage_class_roles",
		"authentication.permissions.manage_class_roles.name",
		"authentication.permissions.manage_class_roles.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_MANAGE_SYSTEM = &Permission{
		"manage_system",
		"authentication.permissions.manage_system.name",
		"authentication.permissions.manage_system.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_CREATE_DIRECT_CLASS = &Permission{
		"create_direct_class",
		"authentication.permissions.create_direct_class.name",
		"authentication.permissions.create_direct_class.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_CREATE_GROUP_CLASS = &Permission{
		"create_group_class",
		"authentication.permissions.create_group_class.name",
		"authentication.permissions.create_group_class.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES = &Permission{
		"manage_public_class_properties",
		"authentication.permissions.manage_public_class_properties.name",
		"authentication.permissions.manage_public_class_properties.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES = &Permission{
		"manage_private_class_properties",
		"authentication.permissions.manage_private_class_properties.name",
		"authentication.permissions.manage_private_class_properties.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_LIST_PUBLIC_BRANCHES = &Permission{
		"list_public_branches",
		"authentication.permissions.list_public_branches.name",
		"authentication.permissions.list_public_branches.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_JOIN_PUBLIC_BRANCHES = &Permission{
		"join_public_branches",
		"authentication.permissions.join_public_branches.name",
		"authentication.permissions.join_public_branches.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_LIST_PRIVATE_BRANCHES = &Permission{
		"list_private_branches",
		"authentication.permissions.list_private_branches.name",
		"authentication.permissions.list_private_branches.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_JOIN_PRIVATE_BRANCHES = &Permission{
		"join_private_branches",
		"authentication.permissions.join_private_branches.name",
		"authentication.permissions.join_private_branches.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_LIST_BRANCH_CLASSES = &Permission{
		"list_branch_classes",
		"authentication.permissions.list_branch_classes.name",
		"authentication.permissions.list_branch_classes.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_JOIN_PUBLIC_CLASSES = &Permission{
		"join_public_classes",
		"authentication.permissions.join_public_classes.name",
		"authentication.permissions.join_public_classes.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_DELETE_PUBLIC_CLASS = &Permission{
		"delete_public_class",
		"authentication.permissions.delete_public_class.name",
		"authentication.permissions.delete_public_class.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_DELETE_PRIVATE_CLASS = &Permission{
		"delete_private_class",
		"authentication.permissions.delete_private_class.name",
		"authentication.permissions.delete_private_class.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_EDIT_OTHER_USERS = &Permission{
		"edit_other_users",
		"authentication.permissions.edit_other_users.name",
		"authentication.permissions.edit_other_users.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_READ_CLASS = &Permission{
		"read_class",
		"authentication.permissions.read_class.name",
		"authentication.permissions.read_class.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_READ_PUBLIC_CLASS = &Permission{
		"read_public_class",
		"authentication.permissions.read_public_class.name",
		"authentication.permissions.read_public_class.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_ADD_REACTION = &Permission{
		"add_reaction",
		"authentication.permissions.add_reaction.name",
		"authentication.permissions.add_reaction.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_REMOVE_REACTION = &Permission{
		"remove_reaction",
		"authentication.permissions.remove_reaction.name",
		"authentication.permissions.remove_reaction.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_REMOVE_OTHERS_REACTIONS = &Permission{
		"remove_others_reactions",
		"authentication.permissions.remove_others_reactions.name",
		"authentication.permissions.remove_others_reactions.description",
		PERMISSION_SCOPE_CLASS,
	}
	// DEPRECATED
	PERMISSION_PERMANENT_DELETE_USER = &Permission{
		"permanent_delete_user",
		"authentication.permissions.permanent_delete_user.name",
		"authentication.permissions.permanent_delete_user.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_UPLOAD_FILE = &Permission{
		"upload_file",
		"authentication.permissions.upload_file.name",
		"authentication.permissions.upload_file.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_GET_PUBLIC_LINK = &Permission{
		"get_public_link",
		"authentication.permissions.get_public_link.name",
		"authentication.permissions.get_public_link.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	// DEPRECATED
	PERMISSION_MANAGE_WEBHOOKS = &Permission{
		"manage_webhooks",
		"authentication.permissions.manage_webhooks.name",
		"authentication.permissions.manage_webhooks.description",
		PERMISSION_SCOPE_BRANCH,
	}
	// DEPRECATED
	PERMISSION_MANAGE_OTHERS_WEBHOOKS = &Permission{
		"manage_others_webhooks",
		"authentication.permissions.manage_others_webhooks.name",
		"authentication.permissions.manage_others_webhooks.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_MANAGE_INCOMING_WEBHOOKS = &Permission{
		"manage_incoming_webhooks",
		"authentication.permissions.manage_incoming_webhooks.name",
		"authentication.permissions.manage_incoming_webhooks.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_MANAGE_OUTGOING_WEBHOOKS = &Permission{
		"manage_outgoing_webhooks",
		"authentication.permissions.manage_outgoing_webhooks.name",
		"authentication.permissions.manage_outgoing_webhooks.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_MANAGE_OTHERS_INCOMING_WEBHOOKS = &Permission{
		"manage_others_incoming_webhooks",
		"authentication.permissions.manage_others_incoming_webhooks.name",
		"authentication.permissions.manage_others_incoming_webhooks.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_MANAGE_OTHERS_OUTGOING_WEBHOOKS = &Permission{
		"manage_others_outgoing_webhooks",
		"authentication.permissions.manage_others_outgoing_webhooks.name",
		"authentication.permissions.manage_others_outgoing_webhooks.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_MANAGE_OAUTH = &Permission{
		"manage_oauth",
		"authentication.permissions.manage_oauth.name",
		"authentication.permissions.manage_oauth.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_MANAGE_SYSTEM_WIDE_OAUTH = &Permission{
		"manage_system_wide_oauth",
		"authentication.permissions.manage_system_wide_oauth.name",
		"authentication.permissions.manage_system_wide_oauth.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	// DEPRECATED
	PERMISSION_MANAGE_EMOJIS = &Permission{
		"manage_emojis",
		"authentication.permissions.manage_emojis.name",
		"authentication.permissions.manage_emojis.description",
		PERMISSION_SCOPE_BRANCH,
	}
	// DEPRECATED
	PERMISSION_MANAGE_OTHERS_EMOJIS = &Permission{
		"manage_others_emojis",
		"authentication.permissions.manage_others_emojis.name",
		"authentication.permissions.manage_others_emojis.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_CREATE_EMOJIS = &Permission{
		"create_emojis",
		"authentication.permissions.create_emojis.name",
		"authentication.permissions.create_emojis.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_DELETE_EMOJIS = &Permission{
		"delete_emojis",
		"authentication.permissions.delete_emojis.name",
		"authentication.permissions.delete_emojis.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_DELETE_OTHERS_EMOJIS = &Permission{
		"delete_others_emojis",
		"authentication.permissions.delete_others_emojis.name",
		"authentication.permissions.delete_others_emojis.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_CREATE_POST = &Permission{
		"create_post",
		"authentication.permissions.create_post.name",
		"authentication.permissions.create_post.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_CREATE_POST_PUBLIC = &Permission{
		"create_post_public",
		"authentication.permissions.create_post_public.name",
		"authentication.permissions.create_post_public.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_CREATE_POST_EPHEMERAL = &Permission{
		"create_post_ephemeral",
		"authentication.permissions.create_post_ephemeral.name",
		"authentication.permissions.create_post_ephemeral.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_EDIT_POST = &Permission{
		"edit_post",
		"authentication.permissions.edit_post.name",
		"authentication.permissions.edit_post.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_EDIT_OTHERS_POSTS = &Permission{
		"edit_others_posts",
		"authentication.permissions.edit_others_posts.name",
		"authentication.permissions.edit_others_posts.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_DELETE_POST = &Permission{
		"delete_post",
		"authentication.permissions.delete_post.name",
		"authentication.permissions.delete_post.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_DELETE_OTHERS_POSTS = &Permission{
		"delete_others_posts",
		"authentication.permissions.delete_others_posts.name",
		"authentication.permissions.delete_others_posts.description",
		PERMISSION_SCOPE_CLASS,
	}
	PERMISSION_REMOVE_USER_FROM_BRANCH = &Permission{
		"remove_user_from_branch",
		"authentication.permissions.remove_user_from_branch.name",
		"authentication.permissions.remove_user_from_branch.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_CREATE_BRANCH = &Permission{
		"create_branch",
		"authentication.permissions.create_branch.name",
		"authentication.permissions.create_branch.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_MANAGE_BRANCH = &Permission{
		"manage_branch",
		"authentication.permissions.manage_branch.name",
		"authentication.permissions.manage_branch.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_IMPORT_BRANCH = &Permission{
		"import_branch",
		"authentication.permissions.import_branch.name",
		"authentication.permissions.import_branch.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_VIEW_BRANCH = &Permission{
		"view_branch",
		"authentication.permissions.view_branch.name",
		"authentication.permissions.view_branch.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_LIST_USERS_WITHOUT_BRANCH = &Permission{
		"list_users_without_branch",
		"authentication.permissions.list_users_without_branch.name",
		"authentication.permissions.list_users_without_branch.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_CREATE_USER_ACCESS_TOKEN = &Permission{
		"create_user_access_token",
		"authentication.permissions.create_user_access_token.name",
		"authentication.permissions.create_user_access_token.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_READ_USER_ACCESS_TOKEN = &Permission{
		"read_user_access_token",
		"authentication.permissions.read_user_access_token.name",
		"authentication.permissions.read_user_access_token.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_REVOKE_USER_ACCESS_TOKEN = &Permission{
		"revoke_user_access_token",
		"authentication.permissions.revoke_user_access_token.name",
		"authentication.permissions.revoke_user_access_token.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_CREATE_BOT = &Permission{
		"create_bot",
		"authentication.permissions.create_bot.name",
		"authentication.permissions.create_bot.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_ASSIGN_BOT = &Permission{
		"assign_bot",
		"authentication.permissions.assign_bot.name",
		"authentication.permissions.assign_bot.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_READ_BOTS = &Permission{
		"read_bots",
		"authentication.permissions.read_bots.name",
		"authentication.permissions.read_bots.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_READ_OTHERS_BOTS = &Permission{
		"read_others_bots",
		"authentication.permissions.read_others_bots.name",
		"authentication.permissions.read_others_bots.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_MANAGE_BOTS = &Permission{
		"manage_bots",
		"authentication.permissions.manage_bots.name",
		"authentication.permissions.manage_bots.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_MANAGE_OTHERS_BOTS = &Permission{
		"manage_others_bots",
		"authentication.permissions.manage_others_bots.name",
		"authentication.permissions.manage_others_bots.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_MANAGE_JOBS = &Permission{
		"manage_jobs",
		"authentication.permisssions.manage_jobs.name",
		"authentication.permisssions.manage_jobs.description",
		PERMISSION_SCOPE_SYSTEM,
	}
	PERMISSION_VIEW_MEMBERS = &Permission{
		"view_members",
		"authentication.permisssions.view_members.name",
		"authentication.permisssions.view_members.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_INVITE_GUEST = &Permission{
		"invite_guest",
		"authentication.permissions.invite_guest.name",
		"authentication.permissions.invite_guest.description",
		PERMISSION_SCOPE_BRANCH,
	}
	PERMISSION_PROMOTE_GUEST = &Permission{
		"promote_guest",
		"authentication.permissions.promote_guest.name",
		"authentication.permissions.promote_guest.description",
		PERMISSION_SCOPE_SYSTEM,
	}

	PERMISSION_DEMOTE_TO_GUEST = &Permission{
		"demote_to_guest",
		"authentication.permissions.demote_to_guest.name",
		"authentication.permissions.demote_to_guest.description",
		PERMISSION_SCOPE_SYSTEM,
	}

	PERMISSION_USE_CLASS_MENTIONS = &Permission{
		"use_class_mentions",
		"authentication.permissions.use_class_mentions.name",
		"authentication.permissions.use_class_mentions.description",
		PERMISSION_SCOPE_CLASS,
	}

	PERMISSION_USE_GROUP_MENTIONS = &Permission{
		"use_group_mentions",
		"authentication.permissions.use_group_mentions.name",
		"authentication.permissions.use_group_mentions.description",
		PERMISSION_SCOPE_CLASS,
	}

	ALL_PERMISSIONS = []*Permission{
		PERMISSION_INVITE_USER,
		PERMISSION_ADD_USER_TO_BRANCH,
		PERMISSION_USE_SLASH_COMMANDS,
		PERMISSION_MANAGE_SLASH_COMMANDS,
		PERMISSION_MANAGE_OTHERS_SLASH_COMMANDS,
		PERMISSION_CREATE_PUBLIC_CLASS,
		PERMISSION_CREATE_PRIVATE_CLASS,
		PERMISSION_MANAGE_PUBLIC_CLASS_MEMBERS,
		PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS,
		PERMISSION_ASSIGN_SYSTEM_ADMIN_ROLE,
		PERMISSION_MANAGE_ROLES,
		PERMISSION_MANAGE_BRANCH_ROLES,
		PERMISSION_MANAGE_CLASS_ROLES,
		PERMISSION_CREATE_DIRECT_CLASS,
		PERMISSION_CREATE_GROUP_CLASS,
		PERMISSION_MANAGE_PUBLIC_CLASS_PROPERTIES,
		PERMISSION_MANAGE_PRIVATE_CLASS_PROPERTIES,
		PERMISSION_LIST_PUBLIC_BRANCHES,
		PERMISSION_JOIN_PUBLIC_BRANCHES,
		PERMISSION_LIST_PRIVATE_BRANCHES,
		PERMISSION_JOIN_PRIVATE_BRANCHES,
		PERMISSION_LIST_BRANCH_CLASSES,
		PERMISSION_JOIN_PUBLIC_CLASSES,
		PERMISSION_DELETE_PUBLIC_CLASS,
		PERMISSION_DELETE_PRIVATE_CLASS,
		PERMISSION_EDIT_OTHER_USERS,
		PERMISSION_READ_CLASS,
		PERMISSION_READ_PUBLIC_CLASS,
		PERMISSION_ADD_REACTION,
		PERMISSION_REMOVE_REACTION,
		PERMISSION_REMOVE_OTHERS_REACTIONS,
		PERMISSION_PERMANENT_DELETE_USER,
		PERMISSION_UPLOAD_FILE,
		PERMISSION_GET_PUBLIC_LINK,
		PERMISSION_MANAGE_WEBHOOKS,
		PERMISSION_MANAGE_OTHERS_WEBHOOKS,
		PERMISSION_MANAGE_INCOMING_WEBHOOKS,
		PERMISSION_MANAGE_OUTGOING_WEBHOOKS,
		PERMISSION_MANAGE_OTHERS_INCOMING_WEBHOOKS,
		PERMISSION_MANAGE_OTHERS_OUTGOING_WEBHOOKS,
		PERMISSION_MANAGE_OAUTH,
		PERMISSION_MANAGE_SYSTEM_WIDE_OAUTH,
		PERMISSION_MANAGE_EMOJIS,
		PERMISSION_MANAGE_OTHERS_EMOJIS,
		PERMISSION_CREATE_EMOJIS,
		PERMISSION_DELETE_EMOJIS,
		PERMISSION_DELETE_OTHERS_EMOJIS,
		PERMISSION_CREATE_POST,
		PERMISSION_CREATE_POST_PUBLIC,
		PERMISSION_CREATE_POST_EPHEMERAL,
		PERMISSION_EDIT_POST,
		PERMISSION_EDIT_OTHERS_POSTS,
		PERMISSION_DELETE_POST,
		PERMISSION_DELETE_OTHERS_POSTS,
		PERMISSION_REMOVE_USER_FROM_BRANCH,
		PERMISSION_CREATE_BRANCH,
		PERMISSION_MANAGE_BRANCH,
		PERMISSION_IMPORT_BRANCH,
		PERMISSION_VIEW_BRANCH,
		PERMISSION_LIST_USERS_WITHOUT_BRANCH,
		PERMISSION_MANAGE_JOBS,
		PERMISSION_CREATE_USER_ACCESS_TOKEN,
		PERMISSION_READ_USER_ACCESS_TOKEN,
		PERMISSION_REVOKE_USER_ACCESS_TOKEN,
		PERMISSION_CREATE_BOT,
		PERMISSION_READ_BOTS,
		PERMISSION_READ_OTHERS_BOTS,
		PERMISSION_MANAGE_BOTS,
		PERMISSION_MANAGE_OTHERS_BOTS,
		PERMISSION_MANAGE_SYSTEM,
		PERMISSION_VIEW_MEMBERS,
		PERMISSION_INVITE_GUEST,
		PERMISSION_PROMOTE_GUEST,
		PERMISSION_DEMOTE_TO_GUEST,
		PERMISSION_USE_CLASS_MENTIONS,
		PERMISSION_USE_GROUP_MENTIONS,
	}

	CLASS_MODERATED_PERMISSIONS = []string{
		PERMISSION_CREATE_POST.Id,
		"create_reactions",
		"manage_members",
		PERMISSION_USE_CLASS_MENTIONS.Id,
	}

	CLASS_MODERATED_PERMISSIONS_MAP = map[string]string{
		PERMISSION_CREATE_POST.Id:                  CLASS_MODERATED_PERMISSIONS[0],
		PERMISSION_ADD_REACTION.Id:                 CLASS_MODERATED_PERMISSIONS[1],
		PERMISSION_REMOVE_REACTION.Id:              CLASS_MODERATED_PERMISSIONS[1],
		PERMISSION_MANAGE_PUBLIC_CLASS_MEMBERS.Id:  CLASS_MODERATED_PERMISSIONS[2],
		PERMISSION_MANAGE_PRIVATE_CLASS_MEMBERS.Id: CLASS_MODERATED_PERMISSIONS[2],
		PERMISSION_USE_CLASS_MENTIONS.Id:           CLASS_MODERATED_PERMISSIONS[3],
	}
}

func init() {
	initializePermissions()
}
