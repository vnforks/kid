// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	CLASS_DISPLAY_NAME_MAX_RUNES = 64
	CLASS_NAME_MIN_LENGTH        = 2
	CLASS_NAME_MAX_LENGTH        = 64
	CLASS_HEADER_MAX_RUNES       = 1024
	CLASS_PURPOSE_MAX_RUNES      = 250
	CLASS_CACHE_SIZE             = 25000

	CLASS_SORT_BY_USERNAME = "username"
	CLASS_SORT_BY_STATUS   = "status"
	DEFAULT_CLASS          = "town-square"
)

type Class struct {
	Id            string                 `json:"id"`
	CreateAt      int64                  `json:"create_at"`
	UpdateAt      int64                  `json:"update_at"`
	DeleteAt      int64                  `json:"delete_at"`
	BranchId      string                 `json:"branch_id"`
	DisplayName   string                 `json:"display_name"`
	Name          string                 `json:"name"`
	Header        string                 `json:"header"`
	Purpose       string                 `json:"purpose"`
	ExtraUpdateAt int64                  `json:"extra_update_at"`
	CreatorId     string                 `json:"creator_id"`
	SchemeId      *string                `json:"scheme_id"`
	Props         map[string]interface{} `json:"props" db:"-"`
}

type ClassWithBranchData struct {
	Class
	BranchDisplayName string `json:"branch_display_name"`
	BranchName        string `json:"branch_name"`
	BranchUpdateAt    int64  `json:"branch_update_at"`
}

type ClassesWithCount struct {
	Classes    *ClassListWithBranchData `json:"classes"`
	TotalCount int64                    `json:"total_count"`
}

type ClassPatch struct {
	DisplayName *string `json:"display_name"`
	Name        *string `json:"name"`
	Header      *string `json:"header"`
	Purpose     *string `json:"purpose"`
}

type ClassForExport struct {
	Class
	BranchName string
	SchemeName *string
}

type DirectClassForExport struct {
	Class
	Members *[]string
}

type ClassModeration struct {
	Name  string               `json:"name"`
	Roles *ClassModeratedRoles `json:"roles"`
}

type ClassModeratedRoles struct {
	Members *ClassModeratedRole `json:"members"`
}

type ClassModeratedRole struct {
	Value   bool `json:"value"`
	Enabled bool `json:"enabled"`
}

type ClassModerationPatch struct {
	Name  *string                   `json:"name"`
	Roles *ClassModeratedRolesPatch `json:"roles"`
}

type ClassModeratedRolesPatch struct {
	Members *bool `json:"members"`
}

// ClassSearchOpts contains options for searching classes.
//
// NotAssociatedToGroup will exclude classes that have associated, active GroupClasses records.
// ExcludeDefaultClasses will exclude the configured default classes (ex 'town-square' and 'off-topic').
// IncludeDeleted will include class records where DeleteAt != 0.
// ExcludeClassNames will exclude classes from the results by name.
// Paginate whether to paginate the results.
// Page page requested, if results are paginated.
// PerPage number of results per page, if paginated.
//
type ClassSearchOpts struct {
	NotAssociatedToGroup  string
	ExcludeDefaultClasses bool
	IncludeDeleted        bool
	ExcludeClassNames     []string
	Page                  *int
	PerPage               *int
}

func (o *Class) DeepCopy() *Class {
	copy := *o
	if copy.SchemeId != nil {
		copy.SchemeId = NewString(*o.SchemeId)
	}
	return &copy
}

func (o *Class) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func (o *ClassPatch) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func (o *ClassesWithCount) ToJson() []byte {
	b, _ := json.Marshal(o)
	return b
}

func ClassesWithCountFromJson(data io.Reader) *ClassesWithCount {
	var o *ClassesWithCount
	json.NewDecoder(data).Decode(&o)
	return o
}

func ClassFromJson(data io.Reader) *Class {
	var o *Class
	json.NewDecoder(data).Decode(&o)
	return o
}

func ClassPatchFromJson(data io.Reader) *ClassPatch {
	var o *ClassPatch
	json.NewDecoder(data).Decode(&o)
	return o
}

func ClassModerationsFromJson(data io.Reader) []*ClassModeration {
	var o []*ClassModeration
	json.NewDecoder(data).Decode(&o)
	return o
}

func ClassModerationsPatchFromJson(data io.Reader) []*ClassModerationPatch {
	var o []*ClassModerationPatch
	json.NewDecoder(data).Decode(&o)
	return o
}

func (o *Class) Etag() string {
	return Etag(o.Id, o.UpdateAt)
}

func (o *Class) IsValid() *AppError {
	if len(o.Id) != 26 {
		return NewAppError("Class.IsValid", "model.class.is_valid.id.app_error", nil, "", http.StatusBadRequest)
	}

	if o.CreateAt == 0 {
		return NewAppError("Class.IsValid", "model.class.is_valid.create_at.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if o.UpdateAt == 0 {
		return NewAppError("Class.IsValid", "model.class.is_valid.update_at.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if utf8.RuneCountInString(o.DisplayName) > CLASS_DISPLAY_NAME_MAX_RUNES {
		return NewAppError("Class.IsValid", "model.class.is_valid.display_name.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if !IsValidClassIdentifier(o.Name) {
		return NewAppError("Class.IsValid", "model.class.is_valid.2_or_more.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if utf8.RuneCountInString(o.Header) > CLASS_HEADER_MAX_RUNES {
		return NewAppError("Class.IsValid", "model.class.is_valid.header.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if utf8.RuneCountInString(o.Purpose) > CLASS_PURPOSE_MAX_RUNES {
		return NewAppError("Class.IsValid", "model.class.is_valid.purpose.app_error", nil, "id="+o.Id, http.StatusBadRequest)
	}

	if len(o.CreatorId) > 26 {
		return NewAppError("Class.IsValid", "model.class.is_valid.creator_id.app_error", nil, "", http.StatusBadRequest)
	}

	return nil
}

func (o *Class) PreSave() {
	if o.Id == "" {
		o.Id = NewId()
	}

	o.CreateAt = GetMillis()
	o.UpdateAt = o.CreateAt
	o.ExtraUpdateAt = 0
}

func (o *Class) PreUpdate() {
	o.UpdateAt = GetMillis()
}

func (o *Class) Patch(patch *ClassPatch) {
	if patch.DisplayName != nil {
		o.DisplayName = *patch.DisplayName
	}

	if patch.Name != nil {
		o.Name = *patch.Name
	}

	if patch.Header != nil {
		o.Header = *patch.Header
	}

	if patch.Purpose != nil {
		o.Purpose = *patch.Purpose
	}

}

func (o *Class) MakeNonNil() {
	if o.Props == nil {
		o.Props = make(map[string]interface{})
	}
}

func (o *Class) AddProp(key string, value interface{}) {
	o.MakeNonNil()

	o.Props[key] = value
}

func (o *Class) GetOtherUserIdForDM(userId string) string {

	userIds := strings.Split(o.Name, "__")

	var otherUserId string

	if userIds[0] != userIds[1] {
		if userIds[0] == userId {
			otherUserId = userIds[1]
		} else {
			otherUserId = userIds[0]
		}
	}

	return otherUserId
}

func GetDMNameFromIds(userId1, userId2 string) string {
	if userId1 > userId2 {
		return userId2 + "__" + userId1
	} else {
		return userId1 + "__" + userId2
	}
}

func GetGroupDisplayNameFromUsers(users []*User, truncate bool) string {
	usernames := make([]string, len(users))
	for index, user := range users {
		usernames[index] = user.Username
	}

	sort.Strings(usernames)

	name := strings.Join(usernames, ", ")

	if truncate && len(name) > CLASS_NAME_MAX_LENGTH {
		name = name[:CLASS_NAME_MAX_LENGTH]
	}

	return name
}

func GetGroupNameFromUserIds(userIds []string) string {
	sort.Strings(userIds)

	h := sha1.New()
	for _, id := range userIds {
		io.WriteString(h, id)
	}

	return hex.EncodeToString(h.Sum(nil))
}
