// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"io"
)

const (
	CLUSTER_EVENT_PUBLISH                                         = "publish"
	CLUSTER_EVENT_UPDATE_STATUS                                   = "update_status"
	CLUSTER_EVENT_INVALIDATE_ALL_CACHES                           = "inv_all_caches"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_REACTIONS                  = "inv_reactions"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_WEBHOOK                    = "inv_webhook"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_POSTS                = "inv_class_posts"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_MEMBERS_NOTIFY_PROPS = "inv_class_members_notify_props"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_MEMBERS              = "inv_class_members"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_BY_NAME              = "inv_class_name"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS                      = "inv_class"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_GUEST_COUNT          = "inv_class_guest_count"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_USER                       = "inv_user"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_USER_BRANCHES              = "inv_user_branches"
	CLUSTER_EVENT_CLEAR_SESSION_CACHE_FOR_USER                    = "clear_session_user"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_ROLES                      = "inv_roles"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_ROLE_PERMISSIONS           = "inv_role_permissions"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_PROFILE_BY_IDS             = "inv_profile_ids"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_PROFILE_IN_CLASS           = "inv_profile_in_class"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_SCHEMES                    = "inv_schemes"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_FILE_INFOS                 = "inv_file_infos"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_WEBHOOKS                   = "inv_webhooks"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_EMOJIS_BY_ID               = "inv_emojis_by_id"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_EMOJIS_ID_BY_NAME          = "inv_emojis_id_by_name"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_PINNEDPOSTS_COUNTS   = "inv_class_pinnedposts_counts"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_MEMBER_COUNTS        = "inv_class_member_counts"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_LAST_POSTS                 = "inv_last_posts"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_LAST_POST_TIME             = "inv_last_post_time"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_BRANCHES                   = "inv_branches"
	CLUSTER_EVENT_CLEAR_SESSION_CACHE_FOR_ALL_USERS               = "inv_all_user_sessions"
	CLUSTER_EVENT_INSTALL_PLUGIN                                  = "install_plugin"
	CLUSTER_EVENT_REMOVE_PLUGIN                                   = "remove_plugin"
	CLUSTER_EVENT_INVALIDATE_CACHE_FOR_TERMS_OF_SERVICE           = "inv_terms_of_service"
	CLUSTER_EVENT_BUSY_STATE_CHANGED                              = "busy_state_change"

	// SendTypes for ClusterMessage.
	CLUSTER_SEND_BEST_EFFORT = "best_effort"
	CLUSTER_SEND_RELIABLE    = "reliable"
)

type ClusterMessage struct {
	Event            string            `json:"event"`
	SendType         string            `json:"-"`
	WaitForAllToSend bool              `json:"-"`
	Data             string            `json:"data,omitempty"`
	Props            map[string]string `json:"props,omitempty"`
}

func (o *ClusterMessage) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func ClusterMessageFromJson(data io.Reader) *ClusterMessage {
	var o *ClusterMessage
	json.NewDecoder(data).Decode(&o)
	return o
}
