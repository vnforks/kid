// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

type UserGetOptions struct {
	// Filters the users in the team
	InBranchId string
	// Filters the users not in the team
	NotInBranchId string
	// Filters the users in the channel
	InClassId string
	// Filters the users not in the channel
	NotInClassId string
	// Filters the users group constrained
	GroupConstrained bool
	// Filters the users without a team
	WithoutBranch bool
	// Filters the inactive users
	Inactive bool
	// Filters for the given role
	Role string
	// Sorting option
	Sort string
	// Restrict to search in a list of teams and channels
	ViewRestrictions *ViewUsersRestrictions
	// Page
	Page int
	// Page size
	PerPage int
}

type UserGetByIdsOptions struct {
	// Since filters the users based on their UpdateAt timestamp.
	Since int64
}
