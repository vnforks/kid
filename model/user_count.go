// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

// Options for counting users
type UserCountOptions struct {
	// Should include deleted users (of any type)
	IncludeDeleted bool
	// Exclude regular users
	ExcludeRegularUsers bool
	// Only include users on a specific branch. "" for any branch.
	BranchId string
	// Restrict to search in a list of branches and classes
	ViewRestrictions *ViewUsersRestrictions
}
