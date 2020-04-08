// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

type MessageExport struct {
	BranchId          *string
	BranchName        *string
	BranchDisplayName *string

	ClassId          *string
	ClassName        *string
	ClassDisplayName *string
	ClassType        *string

	UserId    *string
	UserEmail *string
	Username  *string
	IsBot     bool

	PostId         *string
	PostCreateAt   *int64
	PostUpdateAt   *int64
	PostDeleteAt   *int64
	PostMessage    *string
	PostType       *string
	PostRootId     *string
	PostProps      *string
	PostOriginalId *string
	PostFileIds    StringArray
}
