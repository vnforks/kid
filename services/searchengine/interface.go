// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package searchengine

import (
	"time"

	"github.com/vnforks/kid/v5/model"
)

type SearchEngineInterface interface {
	Start() *model.AppError
	Stop() *model.AppError
	GetVersion() int
	UpdateConfig(cfg *model.Config)
	GetName() string
	IsActive() bool
	IsIndexingEnabled() bool
	IsSearchEnabled() bool
	IsAutocompletionEnabled() bool
	IsIndexingSync() bool
	IndexClass(class *model.Class) *model.AppError
	DeleteClass(class *model.Class) *model.AppError
	IndexUser(user *model.User, branchesIds, classesIds []string) *model.AppError
	//	SearchUsersInBranch(branchId string, restrictedToClasses []string, term string, options *model.UserSearchOptions) ([]string, *model.AppError)
	DeleteUser(user *model.User) *model.AppError
	TestConfig(cfg *model.Config) *model.AppError
	PurgeIndexes() *model.AppError
	RefreshIndexes() *model.AppError
	DataRetentionDeleteIndexes(cutoff time.Time) *model.AppError
}
