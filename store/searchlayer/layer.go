// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package searchlayer

import (
	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/services/searchengine"
	"github.com/vnforks/kid/v5/store"
)

type SearchStore struct {
	store.Store
	searchEngine *searchengine.Broker
	user         *SearchUserStore
	branch       *SearchBranchStore
	class        *SearchClassStore
}

func NewSearchLayer(baseStore store.Store, searchEngine *searchengine.Broker) SearchStore {
	searchStore := SearchStore{
		Store:        baseStore,
		searchEngine: searchEngine,
	}
	searchStore.class = &SearchClassStore{ClassStore: baseStore.Class(), rootStore: &searchStore}
	searchStore.branch = &SearchBranchStore{BranchStore: baseStore.Branch(), rootStore: &searchStore}
	searchStore.user = &SearchUserStore{UserStore: baseStore.User(), rootStore: &searchStore}

	return searchStore
}

func (s SearchStore) Class() store.ClassStore {
	return s.class
}

func (s SearchStore) Branch() store.BranchStore {
	return s.branch
}

func (s SearchStore) User() store.UserStore {
	return s.user
}

func (s SearchStore) indexUserFromID(userId string) {
	user, err := s.User().Get(userId)
	if err != nil {
		return
	}
	s.indexUser(user)
}

func (s SearchStore) indexUser(user *model.User) {
	for _, engine := range s.searchEngine.GetActiveEngines() {
		if engine.IsIndexingEnabled() {
			runIndexFn(engine, func(engineCopy searchengine.SearchEngineInterface) {
				userBranches, err := s.Branch().GetBranchesByUserId(user.Id)
				if err != nil {
					mlog.Error("Encountered error indexing user", mlog.String("user_id", user.Id), mlog.String("search_engine", engineCopy.GetName()), mlog.Err(err))
					return
				}

				userBranchesIds := []string{}
				for _, branch := range userBranches {
					userBranchesIds = append(userBranchesIds, branch.Id)
				}

				userClassMembers, err := s.Class().GetAllClassMembersForUser(user.Id, false, true)
				if err != nil {
					mlog.Error("Encountered error indexing user", mlog.String("user_id", user.Id), mlog.String("search_engine", engineCopy.GetName()), mlog.Err(err))
					return
				}

				userClassesIds := []string{}
				for classId := range userClassMembers {
					userClassesIds = append(userClassesIds, classId)
				}

				if err := engineCopy.IndexUser(user, userBranchesIds, userClassesIds); err != nil {
					mlog.Error("Encountered error indexing user", mlog.String("user_id", user.Id), mlog.String("search_engine", engineCopy.GetName()), mlog.Err(err))
					return
				}
				mlog.Debug("Indexed user in search engine", mlog.String("search_engine", engineCopy.GetName()), mlog.String("user_id", user.Id))
			})
		}
	}
}

// Runs an indexing function synchronously or asynchronously depending on the engine
func runIndexFn(engine searchengine.SearchEngineInterface, indexFn func(searchengine.SearchEngineInterface)) {
	if engine.IsIndexingSync() {
		indexFn(engine)
		if err := engine.RefreshIndexes(); err != nil {
			mlog.Error("Encountered error refresh the indexes", mlog.Err(err))
		}
	} else {
		go (func(engineCopy searchengine.SearchEngineInterface) {
			indexFn(engineCopy)
		})(engine)
	}
}
