// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package localcachelayer

import (
	"net/http"

	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

type LocalCacheUserStore struct {
	store.UserStore
	rootStore *LocalCacheStore
}

func (s *LocalCacheUserStore) handleClusterInvalidateScheme(msg *model.ClusterMessage) {
	if msg.Data == CLEAR_CACHE_MESSAGE_DATA {
		s.rootStore.userProfileByIdsCache.Purge()
	} else {
		s.rootStore.userProfileByIdsCache.Remove(msg.Data)
	}
}

func (s *LocalCacheUserStore) handleClusterInvalidateProfilesInClass(msg *model.ClusterMessage) {
	if msg.Data == CLEAR_CACHE_MESSAGE_DATA {
		s.rootStore.profilesInClassCache.Purge()
	} else {
		s.rootStore.profilesInClassCache.Remove(msg.Data)
	}
}

func (s LocalCacheUserStore) ClearCaches() {
	s.rootStore.userProfileByIdsCache.Purge()
	s.rootStore.profilesInClassCache.Purge()

	if s.rootStore.metrics != nil {
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Profile By Ids - Purge")
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Profiles in Class - Purge")
	}
}

func (s LocalCacheUserStore) InvalidateProfileCacheForUser(userId string) {
	s.rootStore.doInvalidateCacheCluster(s.rootStore.userProfileByIdsCache, userId)

	if s.rootStore.metrics != nil {
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Profile By Ids - Remove")
	}
}

func (s LocalCacheUserStore) InvalidateProfilesInClassCacheByUser(userId string) {
	keys := s.rootStore.profilesInClassCache.Keys()

	for _, key := range keys {
		if cacheItem, ok := s.rootStore.profilesInClassCache.Get(key); ok {
			userMap := cacheItem.(map[string]*model.User)
			if _, userInCache := userMap[userId]; userInCache {
				s.rootStore.doInvalidateCacheCluster(s.rootStore.profilesInClassCache, key)
				if s.rootStore.metrics != nil {
					s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Profiles in Class - Remove by User")
				}
			}
		}
	}
}

func (s LocalCacheUserStore) InvalidateProfilesInClassCache(classId string) {
	s.rootStore.doInvalidateCacheCluster(s.rootStore.profilesInClassCache, classId)
	if s.rootStore.metrics != nil {
		s.rootStore.metrics.IncrementMemCacheInvalidationCounter("Profiles in Class - Remove by Class")
	}
}

func (s LocalCacheUserStore) GetAllProfilesInClass(classId string, allowFromCache bool) (map[string]*model.User, *model.AppError) {
	if allowFromCache {
		if cacheItem := s.rootStore.doStandardReadCache(s.rootStore.profilesInClassCache, classId); cacheItem != nil {
			return cacheItem.(map[string]*model.User), nil
		}
	}

	userMap, err := s.UserStore.GetAllProfilesInClass(classId, allowFromCache)
	if err != nil {
		return nil, err
	}

	if allowFromCache {
		s.rootStore.doStandardAddToCache(s.rootStore.profilesInClassCache, classId, userMap)
	}

	return userMap, nil
}

func (s LocalCacheUserStore) GetProfileByIds(userIds []string, options *store.UserGetByIdsOpts, allowFromCache bool) ([]*model.User, *model.AppError) {
	if !allowFromCache {
		return s.UserStore.GetProfileByIds(userIds, options, false)
	}

	if options == nil {
		options = &store.UserGetByIdsOpts{}
	}

	users := []*model.User{}
	remainingUserIds := make([]string, 0)

	for _, userId := range userIds {
		if cacheItem := s.rootStore.doStandardReadCache(s.rootStore.userProfileByIdsCache, userId); cacheItem != nil {
			u := cacheItem.(*model.User)

			if options.Since == 0 || u.UpdateAt > options.Since {
				users = append(users, u.DeepCopy())
			}
		} else {
			remainingUserIds = append(remainingUserIds, userId)
		}
	}

	if s.rootStore.metrics != nil {
		s.rootStore.metrics.AddMemCacheHitCounter("Profile By Ids", float64(len(users)))
		s.rootStore.metrics.AddMemCacheMissCounter("Profile By Ids", float64(len(remainingUserIds)))
	}

	if len(remainingUserIds) > 0 {
		remainingUsers, err := s.UserStore.GetProfileByIds(remainingUserIds, options, false)
		if err != nil {
			return nil, model.NewAppError("SqlUserStore.GetProfileByIds", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		for _, user := range remainingUsers {
			users = append(users, user.DeepCopy())
			s.rootStore.doStandardAddToCache(s.rootStore.userProfileByIdsCache, user.Id, user)
		}

	}

	return users, nil
}
