// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package localcachelayer

import (
	"github.com/vnforks/kid/v5/einterfaces"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/services/cache"
	"github.com/vnforks/kid/v5/store"
)

const (
	REACTION_CACHE_SIZE = 20000
	REACTION_CACHE_SEC  = 30 * 60

	ROLE_CACHE_SIZE = 20000
	ROLE_CACHE_SEC  = 30 * 60

	SCHEME_CACHE_SIZE = 20000
	SCHEME_CACHE_SEC  = 30 * 60

	FILE_INFO_CACHE_SIZE = 25000
	FILE_INFO_CACHE_SEC  = 30 * 60

	CLASS_GUEST_COUNT_CACHE_SIZE = model.CLASS_CACHE_SIZE
	CLASS_GUEST_COUNT_CACHE_SEC  = 30 * 60

	WEBHOOK_CACHE_SIZE = 25000
	WEBHOOK_CACHE_SEC  = 15 * 60

	EMOJI_CACHE_SIZE = 5000
	EMOJI_CACHE_SEC  = 30 * 60

	CLASS_PINNEDPOSTS_COUNTS_CACHE_SIZE = model.CLASS_CACHE_SIZE
	CLASS_PINNEDPOSTS_COUNTS_CACHE_SEC  = 30 * 60

	CLASS_MEMBERS_COUNTS_CACHE_SIZE = model.CLASS_CACHE_SIZE
	CLASS_MEMBERS_COUNTS_CACHE_SEC  = 30 * 60

	LAST_POSTS_CACHE_SIZE = 20000
	LAST_POSTS_CACHE_SEC  = 30 * 60

	TERMS_OF_SERVICE_CACHE_SIZE = 20000
	TERMS_OF_SERVICE_CACHE_SEC  = 30 * 60
	LAST_POST_TIME_CACHE_SIZE   = 25000
	LAST_POST_TIME_CACHE_SEC    = 15 * 60

	USER_PROFILE_BY_ID_CACHE_SIZE = 20000
	USER_PROFILE_BY_ID_SEC        = 30 * 60

	PROFILES_IN_CLASS_CACHE_SIZE = model.CLASS_CACHE_SIZE
	PROFILES_IN_CLASS_CACHE_SEC  = 15 * 60

	BRANCH_CACHE_SIZE = 20000
	BRANCH_CACHE_SEC  = 30 * 60

	CLEAR_CACHE_MESSAGE_DATA = ""

	CLASS_CACHE_SEC = 15 * 60 // 15 mins
)

type LocalCacheStore struct {
	store.Store
	metrics einterfaces.MetricsInterface
	cluster einterfaces.ClusterInterface

	reaction      LocalCacheReactionStore
	reactionCache cache.Cache

	fileInfo      LocalCacheFileInfoStore
	fileInfoCache cache.Cache

	role                 LocalCacheRoleStore
	roleCache            cache.Cache
	rolePermissionsCache cache.Cache

	scheme      LocalCacheSchemeStore
	schemeCache cache.Cache

	emoji              LocalCacheEmojiStore
	emojiCacheById     cache.Cache
	emojiIdCacheByName cache.Cache

	class                  LocalCacheClassStore
	classMemberCountsCache cache.Cache
	classByIdCache         cache.Cache

	webhook      LocalCacheWebhookStore
	webhookCache cache.Cache

	post               LocalCachePostStore
	postLastPostsCache cache.Cache
	lastPostTimeCache  cache.Cache

	user                  LocalCacheUserStore
	userProfileByIdsCache cache.Cache
	profilesInClassCache  cache.Cache

	branch                         LocalCacheBranchStore
	branchAllBranchIdsForUserCache cache.Cache

	termsOfService      LocalCacheTermsOfServiceStore
	termsOfServiceCache cache.Cache
}

func NewLocalCacheLayer(baseStore store.Store, metrics einterfaces.MetricsInterface, cluster einterfaces.ClusterInterface, cacheProvider cache.Provider) LocalCacheStore {

	localCacheStore := LocalCacheStore{
		Store:   baseStore,
		cluster: cluster,
		metrics: metrics,
	}
	// Reactions
	localCacheStore.reactionCache = cacheProvider.NewCacheWithParams(REACTION_CACHE_SIZE, "Reaction", REACTION_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_REACTIONS)
	localCacheStore.reaction = LocalCacheReactionStore{ReactionStore: baseStore.Reaction(), rootStore: &localCacheStore}

	// Roles
	localCacheStore.roleCache = cacheProvider.NewCacheWithParams(ROLE_CACHE_SIZE, "Role", ROLE_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_ROLES)
	localCacheStore.rolePermissionsCache = cacheProvider.NewCacheWithParams(ROLE_CACHE_SIZE, "RolePermission", ROLE_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_ROLE_PERMISSIONS)
	localCacheStore.role = LocalCacheRoleStore{RoleStore: baseStore.Role(), rootStore: &localCacheStore}

	// Schemes
	localCacheStore.schemeCache = cacheProvider.NewCacheWithParams(SCHEME_CACHE_SIZE, "Scheme", SCHEME_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_SCHEMES)
	localCacheStore.scheme = LocalCacheSchemeStore{SchemeStore: baseStore.Scheme(), rootStore: &localCacheStore}

	// FileInfo
	localCacheStore.fileInfoCache = cacheProvider.NewCacheWithParams(FILE_INFO_CACHE_SIZE, "FileInfo", FILE_INFO_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_FILE_INFOS)
	localCacheStore.fileInfo = LocalCacheFileInfoStore{FileInfoStore: baseStore.FileInfo(), rootStore: &localCacheStore}

	// Webhooks
	localCacheStore.webhookCache = cacheProvider.NewCacheWithParams(WEBHOOK_CACHE_SIZE, "Webhook", WEBHOOK_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_WEBHOOKS)
	localCacheStore.webhook = LocalCacheWebhookStore{WebhookStore: baseStore.Webhook(), rootStore: &localCacheStore}

	// Emojis
	localCacheStore.emojiCacheById = cacheProvider.NewCacheWithParams(EMOJI_CACHE_SIZE, "EmojiById", EMOJI_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_EMOJIS_BY_ID)
	localCacheStore.emojiIdCacheByName = cacheProvider.NewCacheWithParams(EMOJI_CACHE_SIZE, "EmojiByName", EMOJI_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_EMOJIS_ID_BY_NAME)
	localCacheStore.emoji = LocalCacheEmojiStore{EmojiStore: baseStore.Emoji(), rootStore: &localCacheStore}

	// Classes
	localCacheStore.classMemberCountsCache = cacheProvider.NewCacheWithParams(CLASS_MEMBERS_COUNTS_CACHE_SIZE, "ClassMemberCounts", CLASS_MEMBERS_COUNTS_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_MEMBER_COUNTS)
	localCacheStore.classByIdCache = cacheProvider.NewCacheWithParams(model.CLASS_CACHE_SIZE, "classById", CLASS_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS)
	localCacheStore.class = LocalCacheClassStore{ClassStore: baseStore.Class(), rootStore: &localCacheStore}

	// Posts
	localCacheStore.postLastPostsCache = cacheProvider.NewCacheWithParams(LAST_POSTS_CACHE_SIZE, "LastPost", LAST_POSTS_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_LAST_POSTS)
	localCacheStore.lastPostTimeCache = cacheProvider.NewCacheWithParams(LAST_POST_TIME_CACHE_SIZE, "LastPostTime", LAST_POST_TIME_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_LAST_POST_TIME)
	localCacheStore.post = LocalCachePostStore{PostStore: baseStore.Post(), rootStore: &localCacheStore}

	// TOS
	localCacheStore.termsOfServiceCache = cacheProvider.NewCacheWithParams(TERMS_OF_SERVICE_CACHE_SIZE, "TermsOfService", TERMS_OF_SERVICE_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_TERMS_OF_SERVICE)
	localCacheStore.termsOfService = LocalCacheTermsOfServiceStore{TermsOfServiceStore: baseStore.TermsOfService(), rootStore: &localCacheStore}

	// Users
	localCacheStore.userProfileByIdsCache = cacheProvider.NewCacheWithParams(USER_PROFILE_BY_ID_CACHE_SIZE, "UserProfileByIds", USER_PROFILE_BY_ID_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_PROFILE_BY_IDS)
	localCacheStore.profilesInClassCache = cacheProvider.NewCacheWithParams(PROFILES_IN_CLASS_CACHE_SIZE, "ProfilesInClass", PROFILES_IN_CLASS_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_PROFILE_IN_CLASS)
	localCacheStore.user = LocalCacheUserStore{UserStore: baseStore.User(), rootStore: &localCacheStore}

	// Branches
	localCacheStore.branchAllBranchIdsForUserCache = cacheProvider.NewCacheWithParams(BRANCH_CACHE_SIZE, "Branch", BRANCH_CACHE_SEC, model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_BRANCHES)
	localCacheStore.branch = LocalCacheBranchStore{BranchStore: baseStore.Branch(), rootStore: &localCacheStore}

	if cluster != nil {
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_REACTIONS, localCacheStore.reaction.handleClusterInvalidateReaction)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_ROLES, localCacheStore.role.handleClusterInvalidateRole)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_ROLE_PERMISSIONS, localCacheStore.role.handleClusterInvalidateRolePermissions)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_SCHEMES, localCacheStore.scheme.handleClusterInvalidateScheme)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_FILE_INFOS, localCacheStore.fileInfo.handleClusterInvalidateFileInfo)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_LAST_POST_TIME, localCacheStore.post.handleClusterInvalidateLastPostTime)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_WEBHOOKS, localCacheStore.webhook.handleClusterInvalidateWebhook)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_EMOJIS_BY_ID, localCacheStore.emoji.handleClusterInvalidateEmojiById)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_EMOJIS_ID_BY_NAME, localCacheStore.emoji.handleClusterInvalidateEmojiIdByName)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS_MEMBER_COUNTS, localCacheStore.class.handleClusterInvalidateClassMemberCounts)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_CLASS, localCacheStore.class.handleClusterInvalidateClassById)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_LAST_POSTS, localCacheStore.post.handleClusterInvalidateLastPosts)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_TERMS_OF_SERVICE, localCacheStore.termsOfService.handleClusterInvalidateTermsOfService)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_PROFILE_BY_IDS, localCacheStore.user.handleClusterInvalidateScheme)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_PROFILE_IN_CLASS, localCacheStore.user.handleClusterInvalidateProfilesInClass)
		cluster.RegisterClusterMessageHandler(model.CLUSTER_EVENT_INVALIDATE_CACHE_FOR_BRANCHES, localCacheStore.branch.handleClusterInvalidateBranch)
	}
	return localCacheStore
}

func (s LocalCacheStore) Reaction() store.ReactionStore {
	return s.reaction
}

func (s LocalCacheStore) Role() store.RoleStore {
	return s.role
}

func (s LocalCacheStore) Scheme() store.SchemeStore {
	return s.scheme
}

func (s LocalCacheStore) FileInfo() store.FileInfoStore {
	return s.fileInfo
}

func (s LocalCacheStore) Webhook() store.WebhookStore {
	return s.webhook
}

func (s LocalCacheStore) Emoji() store.EmojiStore {
	return s.emoji
}

func (s LocalCacheStore) Class() store.ClassStore {
	return s.class
}

func (s LocalCacheStore) Post() store.PostStore {
	return s.post
}

func (s LocalCacheStore) TermsOfService() store.TermsOfServiceStore {
	return s.termsOfService
}

func (s LocalCacheStore) User() store.UserStore {
	return s.user
}

func (s LocalCacheStore) Branch() store.BranchStore {
	return s.branch
}

func (s LocalCacheStore) DropAllTables() {
	s.Invalidate()
	s.Store.DropAllTables()
}

func (s *LocalCacheStore) doInvalidateCacheCluster(cache cache.Cache, key string) {
	cache.Remove(key)
	if s.cluster != nil {
		msg := &model.ClusterMessage{
			Event:    cache.GetInvalidateClusterEvent(),
			SendType: model.CLUSTER_SEND_BEST_EFFORT,
			Data:     key,
		}
		s.cluster.SendClusterMessage(msg)
	}
}

func (s *LocalCacheStore) doStandardAddToCache(cache cache.Cache, key string, value interface{}) {
	cache.AddWithDefaultExpires(key, value)
}

func (s *LocalCacheStore) doStandardReadCache(cache cache.Cache, key string) interface{} {
	if cacheItem, ok := cache.Get(key); ok {
		if s.metrics != nil {
			s.metrics.IncrementMemCacheHitCounter(cache.Name())
		}
		return cacheItem
	}

	if s.metrics != nil {
		s.metrics.IncrementMemCacheMissCounter(cache.Name())
	}

	return nil
}

func (s *LocalCacheStore) doClearCacheCluster(cache cache.Cache) {
	cache.Purge()
	if s.cluster != nil {
		msg := &model.ClusterMessage{
			Event:    cache.GetInvalidateClusterEvent(),
			SendType: model.CLUSTER_SEND_BEST_EFFORT,
			Data:     CLEAR_CACHE_MESSAGE_DATA,
		}
		s.cluster.SendClusterMessage(msg)
	}
}

func (s *LocalCacheStore) Invalidate() {
	s.doClearCacheCluster(s.reactionCache)
	s.doClearCacheCluster(s.schemeCache)
	s.doClearCacheCluster(s.roleCache)
	s.doClearCacheCluster(s.fileInfoCache)
	s.doClearCacheCluster(s.webhookCache)
	s.doClearCacheCluster(s.emojiCacheById)
	s.doClearCacheCluster(s.emojiIdCacheByName)
	s.doClearCacheCluster(s.classMemberCountsCache)
	s.doClearCacheCluster(s.classByIdCache)
	s.doClearCacheCluster(s.postLastPostsCache)
	s.doClearCacheCluster(s.termsOfServiceCache)
	s.doClearCacheCluster(s.lastPostTimeCache)
	s.doClearCacheCluster(s.userProfileByIdsCache)
	s.doClearCacheCluster(s.profilesInClassCache)
	s.doClearCacheCluster(s.branchAllBranchIdsForUserCache)
	s.doClearCacheCluster(s.rolePermissionsCache)
}
