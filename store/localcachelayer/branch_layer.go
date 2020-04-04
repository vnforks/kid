// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package localcachelayer

import (
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

type LocalCacheBranchStore struct {
	store.BranchStore
	rootStore *LocalCacheStore
}

func (s *LocalCacheBranchStore) handleClusterInvalidateBranch(msg *model.ClusterMessage) {
	if msg.Data == CLEAR_CACHE_MESSAGE_DATA {
		s.rootStore.branchAllBranchIdsForUserCache.Purge()
	} else {
		s.rootStore.branchAllBranchIdsForUserCache.Remove(msg.Data)
	}
}

func (s LocalCacheBranchStore) ClearCaches() {
	s.rootStore.branchAllBranchIdsForUserCache.Purge()
	if s.rootStore.metrics != nil {
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("All Branch Ids for User - Purge")
	}
}

func (s LocalCacheBranchStore) InvalidateAllBranchIdsForUser(userId string) {
	s.rootStore.doInvalidateCacheCluster(s.rootStore.branchAllBranchIdsForUserCache, userId)
	if s.rootStore.metrics != nil {
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("All Branch Ids for User - Remove by UserId")
	}
}

func (s LocalCacheBranchStore) GetUserBranchIds(userID string, allowFromCache bool) ([]string, *model.AppError) {
	if !allowFromCache {
		return s.BranchStore.GetUserBranchIds(userID, allowFromCache)
	}

	if userBranchIds := s.rootStore.doStandardReadCache(s.rootStore.branchAllBranchIdsForUserCache, userID); userBranchIds != nil {
		return userBranchIds.([]string), nil
	}

	userBranchIds, err := s.BranchStore.GetUserBranchIds(userID, allowFromCache)
	if err != nil {
		return nil, err
	}

	if len(userBranchIds) > 0 {
		s.rootStore.doStandardAddToCache(s.rootStore.branchAllBranchIdsForUserCache, userID, userBranchIds)
	}

	return userBranchIds, nil
}

func (s LocalCacheBranchStore) Update(branch *model.Branch) (*model.Branch, *model.AppError) {
	var oldBranch *model.Branch
	var err *model.AppError
	if branch.DeleteAt != 0 {
		oldBranch, err = s.BranchStore.Get(branch.Id)
		if err != nil {
			return nil, err
		}
	}

	tm, err := s.BranchStore.Update(branch)
	if err != nil {
		return nil, err
	}
	defer s.rootStore.doClearCacheCluster(s.rootStore.rolePermissionsCache)

	if oldBranch != nil && oldBranch.DeleteAt == 0 {
		s.rootStore.doClearCacheCluster(s.rootStore.branchAllBranchIdsForUserCache)
	}

	return tm, err
}
