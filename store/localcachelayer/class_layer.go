// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package localcachelayer

import (
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

type LocalCacheClassStore struct {
	store.ClassStore
	rootStore *LocalCacheStore
}

func (s *LocalCacheClassStore) handleClusterInvalidateClassMemberCounts(msg *model.ClusterMessage) {
	if msg.Data == CLEAR_CACHE_MESSAGE_DATA {
		s.rootStore.classMemberCountsCache.Purge()
	} else {
		s.rootStore.classMemberCountsCache.Remove(msg.Data)
	}
}

func (s *LocalCacheClassStore) handleClusterInvalidateClassById(msg *model.ClusterMessage) {
	if msg.Data == CLEAR_CACHE_MESSAGE_DATA {
		s.rootStore.classByIdCache.Purge()
	} else {
		s.rootStore.classByIdCache.Remove(msg.Data)
	}
}

func (s LocalCacheClassStore) ClearCaches() {
	s.rootStore.doClearCacheCluster(s.rootStore.classMemberCountsCache)
	s.rootStore.doClearCacheCluster(s.rootStore.classByIdCache)
	s.ClassStore.ClearCaches()
	if s.rootStore.metrics != nil {
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Class Member Counts - Purge")
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Class - Purge")
	}
}

func (s LocalCacheClassStore) InvalidateMemberCount(classId string) {
	s.rootStore.doInvalidateCacheCluster(s.rootStore.classMemberCountsCache, classId)
	if s.rootStore.metrics != nil {
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Class Member Counts - Remove by ClassId")
	}
}

func (s LocalCacheClassStore) InvalidateClass(classId string) {
	s.rootStore.doInvalidateCacheCluster(s.rootStore.classByIdCache, classId)
	if s.rootStore.metrics != nil {
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Class - Remove by ClassId")
	}
}

func (s LocalCacheClassStore) GetMemberCount(classId string, allowFromCache bool) (int64, *model.AppError) {
	if allowFromCache {
		if count := s.rootStore.doStandardReadCache(s.rootStore.classMemberCountsCache, classId); count != nil {
			return count.(int64), nil
		}
	}
	count, err := s.ClassStore.GetMemberCount(classId, allowFromCache)

	if allowFromCache && err == nil {
		s.rootStore.doStandardAddToCache(s.rootStore.classMemberCountsCache, classId, count)
	}

	return count, err
}

func (s LocalCacheClassStore) GetMemberCountFromCache(classId string) int64 {
	if count := s.rootStore.doStandardReadCache(s.rootStore.classMemberCountsCache, classId); count != nil {
		return count.(int64)
	}

	count, err := s.GetMemberCount(classId, true)
	if err != nil {
		return 0
	}

	return count
}

func (s LocalCacheClassStore) Get(id string, allowFromCache bool) (*model.Class, *model.AppError) {

	if allowFromCache {
		if cacheItem := s.rootStore.doStandardReadCache(s.rootStore.classByIdCache, id); cacheItem != nil {
			ch := cacheItem.(*model.Class).DeepCopy()
			return ch, nil
		}
	}

	ch, err := s.ClassStore.Get(id, allowFromCache)

	if allowFromCache && err == nil {
		s.rootStore.doStandardAddToCache(s.rootStore.classByIdCache, id, ch)
	}

	return ch, err
}

func (s LocalCacheClassStore) SaveMember(member *model.ClassMember) (*model.ClassMember, *model.AppError) {
	member, err := s.ClassStore.SaveMember(member)
	if err != nil {
		return nil, err
	}
	s.InvalidateMemberCount(member.ClassId)
	return member, nil
}

func (s LocalCacheClassStore) UpdateMember(member *model.ClassMember) (*model.ClassMember, *model.AppError) {
	member, err := s.ClassStore.UpdateMember(member)
	if err != nil {
		return nil, err
	}
	s.InvalidateMemberCount(member.ClassId)
	return member, nil
}

func (s LocalCacheClassStore) RemoveMember(classId, userId string) *model.AppError {
	err := s.ClassStore.RemoveMember(classId, userId)
	if err != nil {
		return err
	}
	s.InvalidateMemberCount(classId)
	return nil
}
