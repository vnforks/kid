// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	USERNAME = "Username"
)

type BranchMember struct {
	BranchId      string `json:"branch_id"`
	UserId        string `json:"user_id"`
	Roles         string `json:"roles"`
	DeleteAt      int64  `json:"delete_at"`
	SchemeUser    bool   `json:"scheme_user"`
	SchemeAdmin   bool   `json:"scheme_admin"`
	ExplicitRoles string `json:"explicit_roles"`
}

type BranchMemberForExport struct {
	BranchMember
	BranchName string
}

type BranchMemberWithError struct {
	UserId string        `json:"user_id"`
	Member *BranchMember `json:"member"`
	Error  *AppError     `json:"error"`
}

type BranchMembersGetOptions struct {
	// Sort the branch members. Accepts "Username", but defaults to "Id".
	Sort string

	// If true, exclude branch members whose corresponding user is deleted.
	ExcludeDeletedUsers bool

	// Restrict to search in a list of branches and classes
	ViewRestrictions *ViewUsersRestrictions
}

func (o *BranchMember) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func BranchMemberFromJson(data io.Reader) *BranchMember {
	var o *BranchMember
	json.NewDecoder(data).Decode(&o)
	return o
}

func BranchMembersWithErrorToBranchMembers(o []*BranchMemberWithError) []*BranchMember {
	var ret []*BranchMember
	for _, o := range o {
		if o.Error == nil {
			ret = append(ret, o.Member)
		}
	}
	return ret
}

func BranchMembersWithErrorToJson(o []*BranchMemberWithError) string {
	if b, err := json.Marshal(o); err != nil {
		return "[]"
	} else {
		return string(b)
	}
}

func BranchMemberWithErrorToString(o *BranchMemberWithError) string {
	return fmt.Sprintf("%s:%s", o.UserId, o.Error.Error())
}

func BranchMembersWithErrorFromJson(data io.Reader) []*BranchMemberWithError {
	var o []*BranchMemberWithError
	json.NewDecoder(data).Decode(&o)
	return o
}

func BranchMembersToJson(o []*BranchMember) string {
	if b, err := json.Marshal(o); err != nil {
		return "[]"
	} else {
		return string(b)
	}
}

func BranchMembersFromJson(data io.Reader) []*BranchMember {
	var o []*BranchMember
	json.NewDecoder(data).Decode(&o)
	return o
}

func (o *BranchMember) IsValid() *AppError {

	if len(o.BranchId) != 26 {
		return NewAppError("BranchMember.IsValid", "model.branch_member.is_valid.branch_id.app_error", nil, "", http.StatusBadRequest)
	}

	if len(o.UserId) != 26 {
		return NewAppError("BranchMember.IsValid", "model.branch_member.is_valid.user_id.app_error", nil, "", http.StatusBadRequest)
	}

	return nil
}

func (o *BranchMember) PreUpdate() {
}

func (o *BranchMember) GetRoles() []string {
	return strings.Fields(o.Roles)
}
