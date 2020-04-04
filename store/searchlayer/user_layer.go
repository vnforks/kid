// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package searchlayer

import (
	"net/http"
	"strings"

	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/services/searchengine"
	"github.com/vnforks/kid/v5/store"
)

type SearchUserStore struct {
	store.UserStore
	rootStore *SearchStore
}

func (s *SearchUserStore) deleteUserIndex(user *model.User) {
	for _, engine := range s.rootStore.searchEngine.GetActiveEngines() {
		if engine.IsIndexingEnabled() {
			runIndexFn(engine, func(engineCopy searchengine.SearchEngineInterface) {
				if err := engineCopy.DeleteUser(user); err != nil {
					mlog.Error("Encountered error deleting user", mlog.String("user_id", user.Id), mlog.String("search_engine", engineCopy.GetName()), mlog.Err(err))
					return
				}
				mlog.Debug("Removed user from the index in search engine", mlog.String("search_engine", engineCopy.GetName()), mlog.String("user_id", user.Id))
			})
		}
	}
}

func (s *SearchUserStore) Update(user *model.User, trustedUpdateData bool) (*model.UserUpdate, *model.AppError) {
	userUpdate, err := s.UserStore.Update(user, trustedUpdateData)

	if err == nil {
		s.rootStore.indexUser(userUpdate.New)
	}
	return userUpdate, err
}

func (s *SearchUserStore) Save(user *model.User) (*model.User, *model.AppError) {
	nuser, err := s.UserStore.Save(user)

	if err == nil {
		s.rootStore.indexUser(nuser)
	}
	return nuser, err
}

func (s *SearchUserStore) PermanentDelete(userId string) *model.AppError {
	user, userErr := s.UserStore.Get(userId)
	if userErr != nil {
		mlog.Error("Encountered error deleting user", mlog.String("user_id", userId), mlog.Err(userErr))
	}
	err := s.UserStore.PermanentDelete(userId)
	if err == nil && userErr == nil {
		s.deleteUserIndex(user)
	}
	return err
}

func (s *SearchUserStore) getListOfAllowedClassesForBranch(branchId string, viewRestrictions *model.ViewUsersRestrictions) ([]string, *model.AppError) {
	if len(branchId) == 0 {
		return nil, model.NewAppError("SearchUserStore", "store.search_user_store.empty_branch_id", nil, "", http.StatusInternalServerError)
	}

	var listOfAllowedClasses []string
	if viewRestrictions == nil && branchId == "" {
		return nil, nil
	}

	if viewRestrictions == nil || strings.Contains(strings.Join(viewRestrictions.Branches, "."), branchId) {
		classes, err := s.rootStore.Class().GetBranchClasses(branchId)
		if err != nil {
			return nil, err
		}
		classIds := []string{}
		for _, class := range *classes {
			classIds = append(classIds, class.Id)
		}

		return classIds, nil
	}

	if len(viewRestrictions.Classes) == 0 {
		return []string{}, nil
	}

	classes, err := s.rootStore.Class().GetClassesByIds(viewRestrictions.Classes, false)

	if err != nil {
		return nil, err
	}
	for _, c := range classes {
		if c.BranchId == branchId {
			listOfAllowedClasses = append(listOfAllowedClasses, c.Id)
		}
	}

	return listOfAllowedClasses, nil
}
