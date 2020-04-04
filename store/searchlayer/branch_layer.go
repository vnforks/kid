// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package searchlayer

import (
	model "github.com/vnforks/kid/v5/model"
	store "github.com/vnforks/kid/v5/store"
)

type SearchBranchStore struct {
	store.BranchStore
	rootStore *SearchStore
}

func (s SearchBranchStore) SaveMember(branchMember *model.BranchMember, maxUsersPerBranch int) (*model.BranchMember, *model.AppError) {
	member, err := s.BranchStore.SaveMember(branchMember, maxUsersPerBranch)
	if err == nil {
		s.rootStore.indexUserFromID(member.UserId)
	}
	return member, err
}

func (s SearchBranchStore) UpdateMember(branchMember *model.BranchMember) (*model.BranchMember, *model.AppError) {
	member, err := s.BranchStore.UpdateMember(branchMember)
	if err == nil {
		s.rootStore.indexUserFromID(member.UserId)
	}
	return member, err
}

func (s SearchBranchStore) RemoveMember(branchId string, userId string) *model.AppError {
	err := s.BranchStore.RemoveMember(branchId, userId)
	if err == nil {
		s.rootStore.indexUserFromID(userId)
	}
	return err
}

func (s SearchBranchStore) RemoveAllMembersByUser(userId string) *model.AppError {
	err := s.BranchStore.RemoveAllMembersByUser(userId)
	if err == nil {
		s.rootStore.indexUserFromID(userId)
	}
	return err
}
