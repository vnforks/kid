// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	BRANCH_OPEN                       = "O"
	BRANCH_INVITE                     = "I"
	BRANCH_ALLOWED_DOMAINS_MAX_LENGTH = 500
	BRANCH_COMPANY_NAME_MAX_LENGTH    = 64
	BRANCH_DESCRIPTION_MAX_LENGTH     = 255
	BRANCH_DISPLAY_NAME_MAX_RUNES     = 64
	BRANCH_EMAIL_MAX_LENGTH           = 128
	BRANCH_NAME_MAX_LENGTH            = 64
	BRANCH_NAME_MIN_LENGTH            = 2
)

type Branch struct {
	Id                   string  `json:"id"`
	CreateAt             int64   `json:"create_at"`
	UpdateAt             int64   `json:"update_at"`
	DeleteAt             int64   `json:"delete_at"`
	DisplayName          string  `json:"display_name"`
	Name                 string  `json:"name"`
	Description          string  `json:"description"`
	Email                string  `json:"email"`
	SchoolId             string  `json:"school_id"`
	LastBranchIconUpdate int64   `json:"last_branch_icon_update,omitempty"`
	SchemeId             *string `json:"scheme_id"`
}

type BranchPatch struct {
	DisplayName *string `json:"display_name"`
	Description *string `json:"description"`
}

type BranchForExport struct {
	Branch
	SchemeName *string
}

type BranchesWithCount struct {
	Branches   []*Branch `json:"branches"`
	TotalCount int64     `json:"total_count"`
}

func (o *Branch) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func BranchFromJson(data io.Reader) *Branch {
	var o *Branch
	json.NewDecoder(data).Decode(&o)
	return o
}

func BranchMapToJson(u map[string]*Branch) string {
	b, _ := json.Marshal(u)
	return string(b)
}

func BranchMapFromJson(data io.Reader) map[string]*Branch {
	var branches map[string]*Branch
	json.NewDecoder(data).Decode(&branches)
	return branches
}

func BranchListToJson(t []*Branch) string {
	b, _ := json.Marshal(t)
	return string(b)
}

func BranchesWithCountToJson(tlc *BranchesWithCount) []byte {
	b, _ := json.Marshal(tlc)
	return b
}

func BranchesWithCountFromJson(data io.Reader) *BranchesWithCount {
	var twc *BranchesWithCount
	json.NewDecoder(data).Decode(&twc)
	return twc
}

func BranchListFromJson(data io.Reader) []*Branch {
	var branches []*Branch
	json.NewDecoder(data).Decode(&branches)
	return branches
}

func (o *Branch) Etag() string {
	return Etag(o.Id, o.UpdateAt)
}

func (o *Branch) IsValid() *AppError {

	if len(o.Id) != 26 {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.id.app_error", nil, "", http.StatusBadRequest)
	}

	if o.CreateAt == 0 {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.create_at.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if o.UpdateAt == 0 {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.update_at.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if len(o.Email) > BRANCH_EMAIL_MAX_LENGTH {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.email.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if len(o.Email) > 0 && !IsValidEmail(o.Email) {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.email.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if utf8.RuneCountInString(o.DisplayName) == 0 || utf8.RuneCountInString(o.DisplayName) > BRANCH_DISPLAY_NAME_MAX_RUNES {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.name.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if len(o.Name) > BRANCH_NAME_MAX_LENGTH {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.url.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if len(o.Description) > BRANCH_DESCRIPTION_MAX_LENGTH {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.description.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if len(o.SchoolId) == 0 {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.school_id.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if IsReservedBranchName(o.Name) {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.reserved.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if !IsValidBranchName(o.Name) {
		return NewAppError("Branch.IsValid", "model.branch.is_valid.characters.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	return nil
}

func (o *Branch) PreSave() {
	if o.Id == "" {
		o.Id = NewId()
	}

	o.CreateAt = GetMillis()
	o.UpdateAt = o.CreateAt

}

func (o *Branch) PreUpdate() {
	o.UpdateAt = GetMillis()
}

func IsReservedBranchName(s string) bool {
	s = strings.ToLower(s)

	for _, value := range reservedName {
		if strings.Index(s, value) == 0 {
			return true
		}
	}

	return false
}

func IsValidBranchName(s string) bool {

	if !IsValidAlphaNum(s) {
		return false
	}

	if len(s) < BRANCH_NAME_MIN_LENGTH {
		return false
	}

	return true
}

var validBranchNameCharacter = regexp.MustCompile(`^[a-z0-9-]$`)

func CleanBranchName(s string) string {
	s = strings.ToLower(strings.Replace(s, " ", "-", -1))

	for _, value := range reservedName {
		if strings.Index(s, value) == 0 {
			s = strings.Replace(s, value, "", -1)
		}
	}

	s = strings.TrimSpace(s)

	for _, c := range s {
		char := fmt.Sprintf("%c", c)
		if !validBranchNameCharacter.MatchString(char) {
			s = strings.Replace(s, char, "", -1)
		}
	}

	s = strings.Trim(s, "-")

	if !IsValidBranchName(s) {
		s = NewId()
	}

	return s
}

func (o *Branch) Sanitize() {
	o.Email = ""
}

func (o *Branch) Patch(patch *BranchPatch) {
	if patch.DisplayName != nil {
		o.DisplayName = *patch.DisplayName
	}

	if patch.Description != nil {
		o.Description = *patch.Description
	}
}

func (t *BranchPatch) ToJson() string {
	b, err := json.Marshal(t)
	if err != nil {
		return ""
	}

	return string(b)
}

func BranchPatchFromJson(data io.Reader) *BranchPatch {
	decoder := json.NewDecoder(data)
	var branch BranchPatch
	err := decoder.Decode(&branch)
	if err != nil {
		return nil
	}

	return &branch
}
