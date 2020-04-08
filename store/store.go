//go:generate go run layer_generators/main.go

// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package store

import (
	"context"

	"github.com/vnforks/kid/v5/model"
)

type StoreResult struct {
	Data interface{}
	Err  *model.AppError
}

type Store interface {
	Branch() BranchStore
	Class() ClassStore
	Post() PostStore
	User() UserStore
	Audit() AuditStore
	ClusterDiscovery() ClusterDiscoveryStore
	Compliance() ComplianceStore
	Session() SessionStore
	OAuth() OAuthStore
	System() SystemStore
	Webhook() WebhookStore
	Command() CommandStore
	CommandWebhook() CommandWebhookStore
	Preference() PreferenceStore
	License() LicenseStore
	Token() TokenStore
	Emoji() EmojiStore
	Status() StatusStore
	FileInfo() FileInfoStore
	Reaction() ReactionStore
	Role() RoleStore
	Scheme() SchemeStore
	Job() JobStore
	UserAccessToken() UserAccessTokenStore
	TermsOfService() TermsOfServiceStore
	UserTermsOfService() UserTermsOfServiceStore
	LinkMetadata() LinkMetadataStore
	MarkSystemRanUnitTests()
	Close()
	LockToMaster()
	UnlockFromMaster()
	DropAllTables()
	GetCurrentSchemaVersion() string
	TotalMasterDbConnections() int
	TotalReadDbConnections() int
	TotalSearchDbConnections() int
	CheckIntegrity() <-chan IntegrityCheckResult
	SetContext(context context.Context)
	Context() context.Context
}

type BranchStore interface {
	Save(branch *model.Branch) (*model.Branch, *model.AppError)
	Update(branch *model.Branch) (*model.Branch, *model.AppError)
	Get(id string) (*model.Branch, *model.AppError)
	GetByName(name string) (*model.Branch, *model.AppError)
	GetByNames(name []string) ([]*model.Branch, *model.AppError)
	GetAll() ([]*model.Branch, *model.AppError)
	GetAllPage(offset int, limit int) ([]*model.Branch, *model.AppError)
	GetBranchesByUserId(userId string) ([]*model.Branch, *model.AppError)
	GetBySchoolId(schoolId string) (*model.Branch, *model.AppError)
	PermanentDelete(branchId string) *model.AppError
	AnalyticsBranchCount(includeDeleted bool) (int64, *model.AppError)
	SaveMember(member *model.BranchMember, maxUsersPerBranch int) (*model.BranchMember, *model.AppError)
	UpdateMember(member *model.BranchMember) (*model.BranchMember, *model.AppError)
	GetMember(branchId string, userId string) (*model.BranchMember, *model.AppError)
	GetMembers(branchId string, offset int, limit int, branchMembersGetOptions *model.BranchMembersGetOptions) ([]*model.BranchMember, *model.AppError)
	GetMembersByIds(branchId string, userIds []string, restrictions *model.ViewUsersRestrictions) ([]*model.BranchMember, *model.AppError)
	GetTotalMemberCount(branchId string, restrictions *model.ViewUsersRestrictions) (int64, *model.AppError)
	GetActiveMemberCount(branchId string, restrictions *model.ViewUsersRestrictions) (int64, *model.AppError)
	GetBranchesForUser(userId string) ([]*model.BranchMember, *model.AppError)
	GetBranchesForUserWithPagination(userId string, page, perPage int) ([]*model.BranchMember, *model.AppError)
	RemoveMember(branchId string, userId string) *model.AppError
	RemoveAllMembersByBranch(branchId string) *model.AppError
	RemoveAllMembersByUser(userId string) *model.AppError
	UpdateLastBranchIconUpdate(branchId string, curTime int64) *model.AppError
	GetBranchesByScheme(schemeId string, offset int, limit int) ([]*model.Branch, *model.AppError)
	MigrateBranchMembers(fromBranchId string, fromUserId string) (map[string]string, *model.AppError)
	ResetAllBranchSchemes() *model.AppError
	ClearAllCustomRoleAssignments() *model.AppError
	AnalyticsGetBranchCountForScheme(schemeId string) (int64, *model.AppError)
	GetAllForExportAfter(limit int, afterId string) ([]*model.BranchForExport, *model.AppError)
	GetBranchMembersForExport(userId string) ([]*model.BranchMemberForExport, *model.AppError)
	UserBelongsToBranches(userId string, branchIds []string) (bool, *model.AppError)
	GetUserBranchIds(userId string, allowFromCache bool) ([]string, *model.AppError)
	InvalidateAllBranchIdsForUser(userId string)
	ClearCaches()

	// UpdateMembersRole sets all of the given branch members to admins and all of the other members of the branch to
	// non-admin members.
	UpdateMembersRole(branchID string, userIDs []string) *model.AppError
}

type ClassStore interface {
	Save(class *model.Class, maxClassesPerBranch int64) (*model.Class, *model.AppError)
	CreateDirectClass(userId *model.User, otherUserId *model.User) (*model.Class, *model.AppError)
	SaveDirectClass(class *model.Class, member1 *model.ClassMember, member2 *model.ClassMember) (*model.Class, *model.AppError)
	Update(class *model.Class) (*model.Class, *model.AppError)
	Get(id string, allowFromCache bool) (*model.Class, *model.AppError)
	InvalidateClass(id string)
	InvalidateClassByName(branchId, name string)
	GetFromMaster(id string) (*model.Class, *model.AppError)
	Delete(classId string, time int64) *model.AppError
	Restore(classId string, time int64) *model.AppError
	SetDeleteAt(classId string, deleteAt int64, updateAt int64) *model.AppError
	PermanentDelete(classId string) *model.AppError
	PermanentDeleteByBranch(branchId string) *model.AppError
	GetForPost(postId string) (*model.Class, *model.AppError)
	GetByName(branch_id string, name string, allowFromCache bool) (*model.Class, *model.AppError)
	GetByNames(branch_id string, names []string, allowFromCache bool) ([]*model.Class, *model.AppError)
	GetByNameIncludeDeleted(branch_id string, name string, allowFromCache bool) (*model.Class, *model.AppError)
	GetDeletedByName(branch_id string, name string) (*model.Class, *model.AppError)
	GetDeleted(branch_id string, offset int, limit int, userId string) (*model.ClassList, *model.AppError)
	GetClasses(branchId string, userId string, includeDeleted bool) (*model.ClassList, *model.AppError)
	GetAllClasses(page, perPage int, opts ClassSearchOpts) (*model.ClassListWithBranchData, *model.AppError)
	GetAllClassesCount(opts ClassSearchOpts) (int64, *model.AppError)
	GetMoreClasses(branchId string, userId string, offset int, limit int) (*model.ClassList, *model.AppError)
	GetBranchClasses(branchId string) (*model.ClassList, *model.AppError)
	GetAll(branchId string) ([]*model.Class, *model.AppError)
	GetClassesByIds(classIds []string, includeDeleted bool) ([]*model.Class, *model.AppError)
	GetMemberForPost(postId string, userId string) (*model.ClassMember, *model.AppError)
	SaveMember(member *model.ClassMember) (*model.ClassMember, *model.AppError)
	UpdateMember(member *model.ClassMember) (*model.ClassMember, *model.AppError)
	GetMembers(classId string, offset, limit int) (*model.ClassMembers, *model.AppError)
	GetMember(classId string, userId string) (*model.ClassMember, *model.AppError)
	GetClassMembersTimezones(classId string) ([]model.StringMap, *model.AppError)
	GetAllClassMembersForUser(userId string, allowFromCache bool, includeDeleted bool) (map[string]string, *model.AppError)
	InvalidateAllClassMembersForUser(userId string)
	IsUserInClassUseCache(userId string, classId string) bool
	GetAllClassMembersNotifyPropsForClass(classId string, allowFromCache bool) (map[string]model.StringMap, *model.AppError)
	InvalidateCacheForClassMembersNotifyProps(classId string)
	InvalidateMemberCount(classId string)
	GetMemberCountFromCache(classId string) int64
	GetMemberCount(classId string, allowFromCache bool) (int64, *model.AppError)
	RemoveMember(classId string, userId string) *model.AppError
	PermanentDeleteMembersByUser(userId string) *model.AppError
	PermanentDeleteMembersByClass(classId string) *model.AppError
	GetMembersForUser(branchId string, userId string) (*model.ClassMembers, *model.AppError)
	GetMembersForUserWithPagination(branchId, userId string, page, perPage int) (*model.ClassMembers, *model.AppError)
	GetMembersByIds(classId string, userIds []string) (*model.ClassMembers, *model.AppError)
	ClearCaches()
	GetClassesByScheme(schemeId string, offset int, limit int) (model.ClassList, *model.AppError)
	MigrateClassMembers(fromClassId string, fromUserId string) (map[string]string, *model.AppError)
	ResetAllClassSchemes() *model.AppError
	ClearAllCustomRoleAssignments() *model.AppError
	GetAllClassesForExportAfter(limit int, afterId string) ([]*model.ClassForExport, *model.AppError)
	GetClassMembersForExport(userId string, branchId string) ([]*model.ClassMemberForExport, *model.AppError)
	RemoveAllDeactivatedMembers(classId string) *model.AppError
	GetClassesBatchForIndexing(startTime, endTime int64, limit int) ([]*model.Class, *model.AppError)
	UserBelongsToClasses(userId string, classIds []string) (bool, *model.AppError)

	// UpdateMembersRole sets all of the given branch members to admins and all of the other members of the branch to
	// non-admin members.
	UpdateMembersRole(classID string, userIDs []string) *model.AppError
}

type PostStore interface {
	SaveMultiple(posts []*model.Post) ([]*model.Post, *model.AppError)
	Save(post *model.Post) (*model.Post, *model.AppError)
	Update(newPost *model.Post, oldPost *model.Post) (*model.Post, *model.AppError)
	Get(id string, skipFetchThreads bool) (*model.PostList, *model.AppError)
	GetSingle(id string) (*model.Post, *model.AppError)
	Delete(postId string, time int64, deleteByID string) *model.AppError
	PermanentDeleteByUser(userId string) *model.AppError
	PermanentDeleteByClass(classId string) *model.AppError
	GetPosts(options model.GetPostsOptions, allowFromCache bool) (*model.PostList, *model.AppError)
	GetFlaggedPosts(userId string, offset int, limit int) (*model.PostList, *model.AppError)
	// @openTracingParams userId, branchId, offset, limit
	GetFlaggedPostsForBranch(userId, branchId string, offset int, limit int) (*model.PostList, *model.AppError)
	GetFlaggedPostsForClass(userId, classId string, offset int, limit int) (*model.PostList, *model.AppError)
	GetPostsBefore(options model.GetPostsOptions) (*model.PostList, *model.AppError)
	GetPostsAfter(options model.GetPostsOptions) (*model.PostList, *model.AppError)
	GetPostsSince(options model.GetPostsSinceOptions, allowFromCache bool) (*model.PostList, *model.AppError)
	GetPostAfterTime(classId string, time int64) (*model.Post, *model.AppError)
	GetPostIdAfterTime(classId string, time int64) (string, *model.AppError)
	GetPostIdBeforeTime(classId string, time int64) (string, *model.AppError)
	GetEtag(classId string, allowFromCache bool) string
	Search(branchId string, userId string, params *model.SearchParams) (*model.PostList, *model.AppError)
	AnalyticsUserCountsWithPostsByDay(branchId string) (model.AnalyticsRows, *model.AppError)
	AnalyticsPostCountsByDay(options *model.AnalyticsPostCountsOptions) (model.AnalyticsRows, *model.AppError)
	AnalyticsPostCount(branchId string, mustHaveFile bool, mustHaveHashtag bool) (int64, *model.AppError)
	ClearCaches()
	InvalidateLastPostTimeCache(classId string)
	GetPostsCreatedAt(classId string, time int64) ([]*model.Post, *model.AppError)
	Overwrite(post *model.Post) (*model.Post, *model.AppError)
	OverwriteMultiple(posts []*model.Post) ([]*model.Post, *model.AppError)
	GetPostsByIds(postIds []string) ([]*model.Post, *model.AppError)
	GetPostsBatchForIndexing(startTime int64, endTime int64, limit int) ([]*model.PostForIndexing, *model.AppError)
	PermanentDeleteBatch(endTime int64, limit int64) (int64, *model.AppError)
	GetOldest() (*model.Post, *model.AppError)
	GetMaxPostSize() int
}

type UserStore interface {
	Save(user *model.User) (*model.User, *model.AppError)
	Update(user *model.User, allowRoleUpdate bool) (*model.UserUpdate, *model.AppError)
	UpdateLastPictureUpdate(userId string) *model.AppError
	ResetLastPictureUpdate(userId string) *model.AppError
	UpdatePassword(userId, newPassword string) *model.AppError
	UpdateUpdateAt(userId string) (int64, *model.AppError)
	UpdateAuthData(userId string, service string, authData *string, email string, resetMfa bool) (string, *model.AppError)
	UpdateMfaSecret(userId, secret string) *model.AppError
	UpdateMfaActive(userId string, active bool) *model.AppError
	Get(id string) (*model.User, *model.AppError)
	GetAll() ([]*model.User, *model.AppError)
	ClearCaches()
	InvalidateProfilesInClassCacheByUser(userId string)
	InvalidateProfilesInClassCache(classId string)
	GetProfilesInClass(classId string, offset int, limit int) ([]*model.User, *model.AppError)
	GetProfilesInClassByStatus(classId string, offset int, limit int) ([]*model.User, *model.AppError)
	GetAllProfilesInClass(classId string, allowFromCache bool) (map[string]*model.User, *model.AppError)
	GetProfilesNotInClass(branchId string, classId string, groupConstrained bool, offset int, limit int, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError)
	GetProfilesWithoutBranch(options *model.UserGetOptions) ([]*model.User, *model.AppError)
	GetProfilesByUsernames(usernames []string, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError)
	GetAllProfiles(options *model.UserGetOptions) ([]*model.User, *model.AppError)
	GetProfiles(options *model.UserGetOptions) ([]*model.User, *model.AppError)
	GetProfileByIds(userIds []string, options *UserGetByIdsOpts, allowFromCache bool) ([]*model.User, *model.AppError)
	InvalidateProfileCacheForUser(userId string)
	GetByEmail(email string) (*model.User, *model.AppError)
	GetByAuth(authData *string, authService string) (*model.User, *model.AppError)
	GetAllUsingAuthService(authService string) ([]*model.User, *model.AppError)
	GetByUsername(username string) (*model.User, *model.AppError)
	GetForLogin(loginId string, allowSignInWithUsername, allowSignInWithEmail bool) (*model.User, *model.AppError)
	GetUnreadCount(userId string) (int64, *model.AppError)
	VerifyEmail(userId, email string) (string, *model.AppError)
	GetEtagForAllProfiles() string
	GetEtagForProfiles(branchId string) string
	UpdateFailedPasswordAttempts(userId string, attempts int) *model.AppError
	GetSystemAdminProfiles() (map[string]*model.User, *model.AppError)
	PermanentDelete(userId string) *model.AppError
	AnalyticsActiveCount(time int64, options model.UserCountOptions) (int64, *model.AppError)
	GetRecentlyActiveUsersForBranch(branchId string, offset, limit int, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError)
	GetNewUsersForBranch(branchId string, offset, limit int, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError)
	AnalyticsGetInactiveUsersCount() (int64, *model.AppError)
	AnalyticsGetSystemAdminCount() (int64, *model.AppError)
	ClearAllCustomRoleAssignments() *model.AppError
	InferSystemInstallDate() (int64, *model.AppError)
	GetAllAfter(limit int, afterId string) ([]*model.User, *model.AppError)
	GetUsersBatchForIndexing(startTime, endTime int64, limit int) ([]*model.UserForIndexing, *model.AppError)
	Count(options model.UserCountOptions) (int64, *model.AppError)
}

type SessionStore interface {
	Get(sessionIdOrToken string) (*model.Session, *model.AppError)
	Save(session *model.Session) (*model.Session, *model.AppError)
	GetSessions(userId string) ([]*model.Session, *model.AppError)
	GetSessionsWithActiveDeviceIds(userId string) ([]*model.Session, *model.AppError)
	Remove(sessionIdOrToken string) *model.AppError
	RemoveAllSessions() *model.AppError
	PermanentDeleteSessionsByUser(branchId string) *model.AppError
	UpdateLastActivityAt(sessionId string, time int64) *model.AppError
	UpdateRoles(userId string, roles string) (string, *model.AppError)
	UpdateDeviceId(id string, deviceId string, expiresAt int64) (string, *model.AppError)
	UpdateProps(session *model.Session) *model.AppError
	AnalyticsSessionCount() (int64, *model.AppError)
	Cleanup(expiryTime int64, batchSize int64)
}

type AuditStore interface {
	Save(audit *model.Audit) *model.AppError
	Get(user_id string, offset int, limit int) (model.Audits, *model.AppError)
	PermanentDeleteByUser(userId string) *model.AppError
}

type ClusterDiscoveryStore interface {
	Save(discovery *model.ClusterDiscovery) *model.AppError
	Delete(discovery *model.ClusterDiscovery) (bool, *model.AppError)
	Exists(discovery *model.ClusterDiscovery) (bool, *model.AppError)
	GetAll(discoveryType, clusterName string) ([]*model.ClusterDiscovery, *model.AppError)
	SetLastPingAt(discovery *model.ClusterDiscovery) *model.AppError
	Cleanup() *model.AppError
}

type ComplianceStore interface {
	Save(compliance *model.Compliance) (*model.Compliance, *model.AppError)
	Update(compliance *model.Compliance) (*model.Compliance, *model.AppError)
	Get(id string) (*model.Compliance, *model.AppError)
	GetAll(offset, limit int) (model.Compliances, *model.AppError)
	ComplianceExport(compliance *model.Compliance) ([]*model.CompliancePost, *model.AppError)
	MessageExport(after int64, limit int) ([]*model.MessageExport, *model.AppError)
}

type OAuthStore interface {
	SaveApp(app *model.OAuthApp) (*model.OAuthApp, *model.AppError)
	UpdateApp(app *model.OAuthApp) (*model.OAuthApp, *model.AppError)
	GetApp(id string) (*model.OAuthApp, *model.AppError)
	GetAppByUser(userId string, offset, limit int) ([]*model.OAuthApp, *model.AppError)
	GetApps(offset, limit int) ([]*model.OAuthApp, *model.AppError)
	GetAuthorizedApps(userId string, offset, limit int) ([]*model.OAuthApp, *model.AppError)
	DeleteApp(id string) *model.AppError
	SaveAuthData(authData *model.AuthData) (*model.AuthData, *model.AppError)
	GetAuthData(code string) (*model.AuthData, *model.AppError)
	RemoveAuthData(code string) *model.AppError
	PermanentDeleteAuthDataByUser(userId string) *model.AppError
	SaveAccessData(accessData *model.AccessData) (*model.AccessData, *model.AppError)
	UpdateAccessData(accessData *model.AccessData) (*model.AccessData, *model.AppError)
	GetAccessData(token string) (*model.AccessData, *model.AppError)
	GetAccessDataByUserForApp(userId, clientId string) ([]*model.AccessData, *model.AppError)
	GetAccessDataByRefreshToken(token string) (*model.AccessData, *model.AppError)
	GetPreviousAccessData(userId, clientId string) (*model.AccessData, *model.AppError)
	RemoveAccessData(token string) *model.AppError
	RemoveAllAccessData() *model.AppError
}

type SystemStore interface {
	Save(system *model.System) *model.AppError
	SaveOrUpdate(system *model.System) *model.AppError
	Update(system *model.System) *model.AppError
	Get() (model.StringMap, *model.AppError)
	GetByName(name string) (*model.System, *model.AppError)
	PermanentDeleteByName(name string) (*model.System, *model.AppError)
}

type WebhookStore interface {
	SaveIncoming(webhook *model.IncomingWebhook) (*model.IncomingWebhook, *model.AppError)
	GetIncoming(id string, allowFromCache bool) (*model.IncomingWebhook, *model.AppError)
	GetIncomingList(offset, limit int) ([]*model.IncomingWebhook, *model.AppError)
	GetIncomingListByUser(userId string, offset, limit int) ([]*model.IncomingWebhook, *model.AppError)
	GetIncomingByBranch(branchId string, offset, limit int) ([]*model.IncomingWebhook, *model.AppError)
	GetIncomingByBranchByUser(branchId string, userId string, offset, limit int) ([]*model.IncomingWebhook, *model.AppError)
	UpdateIncoming(webhook *model.IncomingWebhook) (*model.IncomingWebhook, *model.AppError)
	GetIncomingByClass(classId string) ([]*model.IncomingWebhook, *model.AppError)
	DeleteIncoming(webhookId string, time int64) *model.AppError
	PermanentDeleteIncomingByClass(classId string) *model.AppError
	PermanentDeleteIncomingByUser(userId string) *model.AppError

	SaveOutgoing(webhook *model.OutgoingWebhook) (*model.OutgoingWebhook, *model.AppError)
	GetOutgoing(id string) (*model.OutgoingWebhook, *model.AppError)
	GetOutgoingByClass(classId string, offset, limit int) ([]*model.OutgoingWebhook, *model.AppError)
	GetOutgoingByClassByUser(classId string, userId string, offset, limit int) ([]*model.OutgoingWebhook, *model.AppError)
	GetOutgoingList(offset, limit int) ([]*model.OutgoingWebhook, *model.AppError)
	GetOutgoingListByUser(userId string, offset, limit int) ([]*model.OutgoingWebhook, *model.AppError)
	GetOutgoingByBranch(branchId string, offset, limit int) ([]*model.OutgoingWebhook, *model.AppError)
	GetOutgoingByBranchByUser(branchId string, userId string, offset, limit int) ([]*model.OutgoingWebhook, *model.AppError)
	DeleteOutgoing(webhookId string, time int64) *model.AppError
	PermanentDeleteOutgoingByClass(classId string) *model.AppError
	PermanentDeleteOutgoingByUser(userId string) *model.AppError
	UpdateOutgoing(hook *model.OutgoingWebhook) (*model.OutgoingWebhook, *model.AppError)

	AnalyticsIncomingCount(branchId string) (int64, *model.AppError)
	AnalyticsOutgoingCount(branchId string) (int64, *model.AppError)
	InvalidateWebhookCache(webhook string)
	ClearCaches()
}

type CommandStore interface {
	Save(webhook *model.Command) (*model.Command, *model.AppError)
	GetByTrigger(branchId string, trigger string) (*model.Command, *model.AppError)
	Get(id string) (*model.Command, *model.AppError)
	GetByBranch(branchId string) ([]*model.Command, *model.AppError)
	Delete(commandId string, time int64) *model.AppError
	PermanentDeleteByBranch(branchId string) *model.AppError
	PermanentDeleteByUser(userId string) *model.AppError
	Update(hook *model.Command) (*model.Command, *model.AppError)
	AnalyticsCommandCount(branchId string) (int64, *model.AppError)
}

type CommandWebhookStore interface {
	Save(webhook *model.CommandWebhook) (*model.CommandWebhook, *model.AppError)
	Get(id string) (*model.CommandWebhook, *model.AppError)
	TryUse(id string, limit int) *model.AppError
	Cleanup()
}

type PreferenceStore interface {
	Save(preferences *model.Preferences) *model.AppError
	GetCategory(userId string, category string) (model.Preferences, *model.AppError)
	Get(userId string, category string, name string) (*model.Preference, *model.AppError)
	GetAll(userId string) (model.Preferences, *model.AppError)
	Delete(userId, category, name string) *model.AppError
	DeleteCategory(userId string, category string) *model.AppError
	DeleteCategoryAndName(category string, name string) *model.AppError
	PermanentDeleteByUser(userId string) *model.AppError
	CleanupFlagsBatch(limit int64) (int64, *model.AppError)
}

type LicenseStore interface {
	Save(license *model.LicenseRecord) (*model.LicenseRecord, *model.AppError)
	Get(id string) (*model.LicenseRecord, *model.AppError)
}

type TokenStore interface {
	Save(recovery *model.Token) *model.AppError
	Delete(token string) *model.AppError
	GetByToken(token string) (*model.Token, *model.AppError)
	Cleanup()
	RemoveAllTokensByType(tokenType string) *model.AppError
}

type EmojiStore interface {
	Save(emoji *model.Emoji) (*model.Emoji, *model.AppError)
	Get(id string, allowFromCache bool) (*model.Emoji, *model.AppError)
	GetByName(name string, allowFromCache bool) (*model.Emoji, *model.AppError)
	GetMultipleByName(names []string) ([]*model.Emoji, *model.AppError)
	GetList(offset, limit int, sort string) ([]*model.Emoji, *model.AppError)
	Delete(emoji *model.Emoji, time int64) *model.AppError
	Search(name string, prefixOnly bool, limit int) ([]*model.Emoji, *model.AppError)
}

type StatusStore interface {
	SaveOrUpdate(status *model.Status) *model.AppError
	Get(userId string) (*model.Status, *model.AppError)
	GetByIds(userIds []string) ([]*model.Status, *model.AppError)
	ResetAll() *model.AppError
	GetTotalActiveUsersCount() (int64, *model.AppError)
	UpdateLastActivityAt(userId string, lastActivityAt int64) *model.AppError
}

type FileInfoStore interface {
	Save(info *model.FileInfo) (*model.FileInfo, *model.AppError)
	Get(id string) (*model.FileInfo, *model.AppError)
	GetByPath(path string) (*model.FileInfo, *model.AppError)
	GetForPost(postId string, readFromMaster, includeDeleted, allowFromCache bool) ([]*model.FileInfo, *model.AppError)
	GetForUser(userId string) ([]*model.FileInfo, *model.AppError)
	GetWithOptions(page, perPage int, opt *model.GetFileInfosOptions) ([]*model.FileInfo, *model.AppError)
	InvalidateFileInfosForPostCache(postId string, deleted bool)
	AttachToPost(fileId string, postId string, creatorId string) *model.AppError
	DeleteForPost(postId string) (string, *model.AppError)
	PermanentDelete(fileId string) *model.AppError
	PermanentDeleteBatch(endTime int64, limit int64) (int64, *model.AppError)
	PermanentDeleteByUser(userId string) (int64, *model.AppError)
	ClearCaches()
}

type ReactionStore interface {
	Save(reaction *model.Reaction) (*model.Reaction, *model.AppError)
	Delete(reaction *model.Reaction) (*model.Reaction, *model.AppError)
	GetForPost(postId string, allowFromCache bool) ([]*model.Reaction, *model.AppError)
	DeleteAllWithEmojiName(emojiName string) *model.AppError
	PermanentDeleteBatch(endTime int64, limit int64) (int64, *model.AppError)
	BulkGetForPosts(postIds []string) ([]*model.Reaction, *model.AppError)
}

type JobStore interface {
	Save(job *model.Job) (*model.Job, *model.AppError)
	UpdateOptimistically(job *model.Job, currentStatus string) (bool, *model.AppError)
	UpdateStatus(id string, status string) (*model.Job, *model.AppError)
	UpdateStatusOptimistically(id string, currentStatus string, newStatus string) (bool, *model.AppError)
	Get(id string) (*model.Job, *model.AppError)
	GetAllPage(offset int, limit int) ([]*model.Job, *model.AppError)
	GetAllByType(jobType string) ([]*model.Job, *model.AppError)
	GetAllByTypePage(jobType string, offset int, limit int) ([]*model.Job, *model.AppError)
	GetAllByStatus(status string) ([]*model.Job, *model.AppError)
	GetNewestJobByStatusAndType(status string, jobType string) (*model.Job, *model.AppError)
	GetCountByStatusAndType(status string, jobType string) (int64, *model.AppError)
	Delete(id string) (string, *model.AppError)
}

type UserAccessTokenStore interface {
	Save(token *model.UserAccessToken) (*model.UserAccessToken, *model.AppError)
	DeleteAllForUser(userId string) *model.AppError
	Delete(tokenId string) *model.AppError
	Get(tokenId string) (*model.UserAccessToken, *model.AppError)
	GetAll(offset int, limit int) ([]*model.UserAccessToken, *model.AppError)
	GetByToken(tokenString string) (*model.UserAccessToken, *model.AppError)
	GetByUser(userId string, page, perPage int) ([]*model.UserAccessToken, *model.AppError)
	Search(term string) ([]*model.UserAccessToken, *model.AppError)
	UpdateTokenEnable(tokenId string) *model.AppError
	UpdateTokenDisable(tokenId string) *model.AppError
}

type RoleStore interface {
	Save(role *model.Role) (*model.Role, *model.AppError)
	Get(roleId string) (*model.Role, *model.AppError)
	GetAll() ([]*model.Role, *model.AppError)
	GetByName(name string) (*model.Role, *model.AppError)
	GetByNames(names []string) ([]*model.Role, *model.AppError)
	Delete(roleId string) (*model.Role, *model.AppError)
	PermanentDeleteAll() *model.AppError

	// HigherScopedPermissions retrieves the higher-scoped permissions of a list of role names. The higher-scope
	// (either branch scheme or system scheme) is determined based on whether the branch has a scheme or not.
	ClassHigherScopedPermissions(roleNames []string) (map[string]*model.RolePermissions, *model.AppError)

	// AllClassSchemeRoles returns all of the roles associated to class schemes.
	AllClassSchemeRoles() ([]*model.Role, *model.AppError)

	// ClassRolesUnderBranchRole returns all of the non-deleted roles that are affected by updates to the
	// given role.
	ClassRolesUnderBranchRole(roleName string) ([]*model.Role, *model.AppError)
}

type SchemeStore interface {
	Save(scheme *model.Scheme) (*model.Scheme, *model.AppError)
	Get(schemeId string) (*model.Scheme, *model.AppError)
	GetByName(schemeName string) (*model.Scheme, *model.AppError)
	GetAllPage(scope string, offset int, limit int) ([]*model.Scheme, *model.AppError)
	Delete(schemeId string) (*model.Scheme, *model.AppError)
	PermanentDeleteAll() *model.AppError
	CountByScope(scope string) (int64, *model.AppError)
	CountWithoutPermission(scope, permissionID string, roleScope model.RoleScope, roleType model.RoleType) (int64, *model.AppError)
}

type TermsOfServiceStore interface {
	Save(termsOfService *model.TermsOfService) (*model.TermsOfService, *model.AppError)
	GetLatest(allowFromCache bool) (*model.TermsOfService, *model.AppError)
	Get(id string, allowFromCache bool) (*model.TermsOfService, *model.AppError)
}

type UserTermsOfServiceStore interface {
	GetByUser(userId string) (*model.UserTermsOfService, *model.AppError)
	Save(userTermsOfService *model.UserTermsOfService) (*model.UserTermsOfService, *model.AppError)
	Delete(userId, termsOfServiceId string) *model.AppError
}

type LinkMetadataStore interface {
	Save(linkMetadata *model.LinkMetadata) (*model.LinkMetadata, *model.AppError)
	Get(url string, timestamp int64) (*model.LinkMetadata, *model.AppError)
}

// ClassSearchOpts contains options for searching classes.
//
// NotAssociatedToGroup will exclude classes that have associated, active GroupClasses records.
// IncludeDeleted will include class records where DeleteAt != 0.
// ExcludeClassNames will exclude classes from the results by name.
// Paginate whether to paginate the results.
// Page page requested, if results are paginated.
// PerPage number of results per page, if paginated.
//
type ClassSearchOpts struct {
	IncludeDeleted    bool
	ExcludeClassNames []string
	Page              *int
	PerPage           *int
}

func (c *ClassSearchOpts) IsPaginated() bool {
	return c.Page != nil && c.PerPage != nil
}

type UserGetByIdsOpts struct {
	// IsAdmin tracks whether or not the request is being made by an administrator. Does nothing when provided by a client.
	IsAdmin bool

	// Restrict to search in a list of branches and classes. Does nothing when provided by a client.
	ViewRestrictions *model.ViewUsersRestrictions

	// Since filters the users based on their UpdateAt timestamp.
	Since int64
}

type OrphanedRecord struct {
	ParentId *string
	ChildId  *string
}

type RelationalIntegrityCheckData struct {
	ParentName   string
	ChildName    string
	ParentIdAttr string
	ChildIdAttr  string
	Records      []OrphanedRecord
}

type IntegrityCheckResult struct {
	Data interface{}
	Err  error
}
