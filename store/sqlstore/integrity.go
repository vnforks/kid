// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/store"

	sq "github.com/Masterminds/squirrel"
)

type relationalCheckConfig struct {
	parentName         string
	parentIdAttr       string
	childName          string
	childIdAttr        string
	canParentIdBeEmpty bool
	sortRecords        bool
}

func getOrphanedRecords(ss *SqlSupplier, cfg relationalCheckConfig) ([]store.OrphanedRecord, error) {
	var records []store.OrphanedRecord

	sub := ss.getQueryBuilder().
		Select("TRUE").
		From(cfg.parentName + " AS PT").
		Prefix("NOT EXISTS (").
		Suffix(")").
		Where("PT.id = CT." + cfg.parentIdAttr)

	main := ss.getQueryBuilder().
		Select().
		Column("CT." + cfg.parentIdAttr + " AS ParentId").
		From(cfg.childName + " AS CT").
		Where(sub)

	if cfg.childIdAttr != "" {
		main = main.Column("CT." + cfg.childIdAttr + " AS ChildId")
	}

	if cfg.canParentIdBeEmpty {
		main = main.Where(sq.NotEq{"CT." + cfg.parentIdAttr: ""})
	}

	if cfg.sortRecords {
		main = main.OrderBy("CT." + cfg.parentIdAttr)
	}

	query, args, _ := main.ToSql()

	_, err := ss.GetMaster().Select(&records, query, args...)

	return records, err
}

func checkParentChildIntegrity(ss *SqlSupplier, config relationalCheckConfig) store.IntegrityCheckResult {
	var result store.IntegrityCheckResult
	var data store.RelationalIntegrityCheckData

	config.sortRecords = true
	data.Records, result.Err = getOrphanedRecords(ss, config)
	if result.Err != nil {
		mlog.Error(result.Err.Error())
		return result
	}
	data.ParentName = config.parentName
	data.ChildName = config.childName
	data.ParentIdAttr = config.parentIdAttr
	data.ChildIdAttr = config.childIdAttr
	result.Data = data

	return result
}

func checkClassesCommandWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Classes",
		parentIdAttr: "ClassId",
		childName:    "CommandWebhooks",
		childIdAttr:  "Id",
	})
}

func checkClassesClassMemberHistoryIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Classes",
		parentIdAttr: "ClassId",
		childName:    "ClassMemberHistory",
		childIdAttr:  "",
	})
}

func checkClassesClassMembersIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Classes",
		parentIdAttr: "ClassId",
		childName:    "ClassMembers",
		childIdAttr:  "",
	})
}

func checkClassesIncomingWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Classes",
		parentIdAttr: "ClassId",
		childName:    "IncomingWebhooks",
		childIdAttr:  "Id",
	})
}

func checkClassesOutgoingWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Classes",
		parentIdAttr: "ClassId",
		childName:    "OutgoingWebhooks",
		childIdAttr:  "Id",
	})
}

func checkClassesPostsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Classes",
		parentIdAttr: "ClassId",
		childName:    "Posts",
		childIdAttr:  "Id",
	})
}

func checkCommandsCommandWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Commands",
		parentIdAttr: "CommandId",
		childName:    "CommandWebhooks",
		childIdAttr:  "Id",
	})
}

func checkPostsFileInfoIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Posts",
		parentIdAttr: "PostId",
		childName:    "FileInfo",
		childIdAttr:  "Id",
	})
}

func checkPostsPostsParentIdIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:         "Posts",
		parentIdAttr:       "ParentId",
		childName:          "Posts",
		childIdAttr:        "Id",
		canParentIdBeEmpty: true,
	})
}

func checkPostsPostsRootIdIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:         "Posts",
		parentIdAttr:       "RootId",
		childName:          "Posts",
		childIdAttr:        "Id",
		canParentIdBeEmpty: true,
	})
}

func checkPostsReactionsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Posts",
		parentIdAttr: "PostId",
		childName:    "Reactions",
		childIdAttr:  "",
	})
}

func checkSchemesClassesIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:         "Schemes",
		parentIdAttr:       "SchemeId",
		childName:          "Classes",
		childIdAttr:        "Id",
		canParentIdBeEmpty: true,
	})
}

func checkSchemesBranchesIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:         "Schemes",
		parentIdAttr:       "SchemeId",
		childName:          "Branches",
		childIdAttr:        "Id",
		canParentIdBeEmpty: true,
	})
}

func checkSessionsAuditsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:         "Sessions",
		parentIdAttr:       "SessionId",
		childName:          "Audits",
		childIdAttr:        "Id",
		canParentIdBeEmpty: true,
	})
}

func checkBranchesClassesIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Branches",
		parentIdAttr: "BranchId",
		childName:    "Classes",
		childIdAttr:  "Id",
	})
}

func checkBranchesCommandsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Branches",
		parentIdAttr: "BranchId",
		childName:    "Commands",
		childIdAttr:  "Id",
	})
}

func checkBranchesIncomingWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Branches",
		parentIdAttr: "BranchId",
		childName:    "IncomingWebhooks",
		childIdAttr:  "Id",
	})
}

func checkBranchesOutgoingWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Branches",
		parentIdAttr: "BranchId",
		childName:    "OutgoingWebhooks",
		childIdAttr:  "Id",
	})
}

func checkBranchesBranchMembersIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Branches",
		parentIdAttr: "BranchId",
		childName:    "BranchMembers",
		childIdAttr:  "",
	})
}

func checkUsersAuditsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:         "Users",
		parentIdAttr:       "UserId",
		childName:          "Audits",
		childIdAttr:        "Id",
		canParentIdBeEmpty: true,
	})
}

func checkUsersCommandWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "CommandWebhooks",
		childIdAttr:  "Id",
	})
}

func checkUsersClassMemberHistoryIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "ClassMemberHistory",
		childIdAttr:  "",
	})
}

func checkUsersClassMembersIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "ClassMembers",
		childIdAttr:  "",
	})
}

func checkUsersClassesIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:         "Users",
		parentIdAttr:       "CreatorId",
		childName:          "Classes",
		childIdAttr:        "Id",
		canParentIdBeEmpty: true,
	})
}

func checkUsersCommandsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "CreatorId",
		childName:    "Commands",
		childIdAttr:  "Id",
	})
}

func checkUsersCompliancesIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "Compliances",
		childIdAttr:  "Id",
	})
}

func checkUsersEmojiIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "CreatorId",
		childName:    "Emoji",
		childIdAttr:  "Id",
	})
}

func checkUsersFileInfoIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "CreatorId",
		childName:    "FileInfo",
		childIdAttr:  "Id",
	})
}

func checkUsersIncomingWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "IncomingWebhooks",
		childIdAttr:  "Id",
	})
}

func checkUsersOAuthAccessDataIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "OAuthAccessData",
		childIdAttr:  "Token",
	})
}

func checkUsersOAuthAppsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "CreatorId",
		childName:    "OAuthApps",
		childIdAttr:  "Id",
	})
}

func checkUsersOAuthAuthDataIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "OAuthAuthData",
		childIdAttr:  "Code",
	})
}

func checkUsersOutgoingWebhooksIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "CreatorId",
		childName:    "OutgoingWebhooks",
		childIdAttr:  "Id",
	})
}

func checkUsersPostsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "Posts",
		childIdAttr:  "Id",
	})
}

func checkUsersPreferencesIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "Preferences",
		childIdAttr:  "",
	})
}

func checkUsersReactionsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "Reactions",
		childIdAttr:  "",
	})
}

func checkUsersSessionsIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "Sessions",
		childIdAttr:  "Id",
	})
}

func checkUsersStatusIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "Status",
		childIdAttr:  "",
	})
}

func checkUsersBranchMembersIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "BranchMembers",
		childIdAttr:  "",
	})
}

func checkUsersUserAccessTokensIntegrity(ss *SqlSupplier) store.IntegrityCheckResult {
	return checkParentChildIntegrity(ss, relationalCheckConfig{
		parentName:   "Users",
		parentIdAttr: "UserId",
		childName:    "UserAccessTokens",
		childIdAttr:  "Id",
	})
}

func checkClassesIntegrity(ss *SqlSupplier, results chan<- store.IntegrityCheckResult) {
	results <- checkClassesCommandWebhooksIntegrity(ss)
	results <- checkClassesClassMemberHistoryIntegrity(ss)
	results <- checkClassesClassMembersIntegrity(ss)
	results <- checkClassesIncomingWebhooksIntegrity(ss)
	results <- checkClassesOutgoingWebhooksIntegrity(ss)
	results <- checkClassesPostsIntegrity(ss)
}

func checkCommandsIntegrity(ss *SqlSupplier, results chan<- store.IntegrityCheckResult) {
	results <- checkCommandsCommandWebhooksIntegrity(ss)
}

func checkPostsIntegrity(ss *SqlSupplier, results chan<- store.IntegrityCheckResult) {
	results <- checkPostsFileInfoIntegrity(ss)
	results <- checkPostsPostsParentIdIntegrity(ss)
	results <- checkPostsPostsRootIdIntegrity(ss)
	results <- checkPostsReactionsIntegrity(ss)
}

func checkSchemesIntegrity(ss *SqlSupplier, results chan<- store.IntegrityCheckResult) {
	results <- checkSchemesClassesIntegrity(ss)
	results <- checkSchemesBranchesIntegrity(ss)
}

func checkSessionsIntegrity(ss *SqlSupplier, results chan<- store.IntegrityCheckResult) {
	results <- checkSessionsAuditsIntegrity(ss)
}

func checkBranchesIntegrity(ss *SqlSupplier, results chan<- store.IntegrityCheckResult) {
	results <- checkBranchesClassesIntegrity(ss)
	results <- checkBranchesCommandsIntegrity(ss)
	results <- checkBranchesIncomingWebhooksIntegrity(ss)
	results <- checkBranchesOutgoingWebhooksIntegrity(ss)
	results <- checkBranchesBranchMembersIntegrity(ss)
}

func checkUsersIntegrity(ss *SqlSupplier, results chan<- store.IntegrityCheckResult) {
	results <- checkUsersAuditsIntegrity(ss)
	results <- checkUsersCommandWebhooksIntegrity(ss)
	results <- checkUsersClassMemberHistoryIntegrity(ss)
	results <- checkUsersClassMembersIntegrity(ss)
	results <- checkUsersClassesIntegrity(ss)
	results <- checkUsersCommandsIntegrity(ss)
	results <- checkUsersCompliancesIntegrity(ss)
	results <- checkUsersEmojiIntegrity(ss)
	results <- checkUsersFileInfoIntegrity(ss)
	results <- checkUsersIncomingWebhooksIntegrity(ss)
	results <- checkUsersOAuthAccessDataIntegrity(ss)
	results <- checkUsersOAuthAppsIntegrity(ss)
	results <- checkUsersOAuthAuthDataIntegrity(ss)
	results <- checkUsersOutgoingWebhooksIntegrity(ss)
	results <- checkUsersPostsIntegrity(ss)
	results <- checkUsersPreferencesIntegrity(ss)
	results <- checkUsersReactionsIntegrity(ss)
	results <- checkUsersSessionsIntegrity(ss)
	results <- checkUsersStatusIntegrity(ss)
	results <- checkUsersBranchMembersIntegrity(ss)
	results <- checkUsersUserAccessTokensIntegrity(ss)
}

func CheckRelationalIntegrity(ss *SqlSupplier, results chan<- store.IntegrityCheckResult) {
	mlog.Info("Starting relational integrity checks...")
	checkClassesIntegrity(ss, results)
	checkCommandsIntegrity(ss, results)
	checkPostsIntegrity(ss, results)
	checkSchemesIntegrity(ss, results)
	checkSessionsIntegrity(ss, results)
	checkBranchesIntegrity(ss, results)
	checkUsersIntegrity(ss, results)
	mlog.Info("Done with relational integrity checks")
	close(results)
}
