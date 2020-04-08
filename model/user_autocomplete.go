// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"io"
)

type UserAutocompleteInClass struct {
	InClass    []*User `json:"in_class"`
	OutOfClass []*User `json:"out_of_class"`
}

type UserAutocompleteInBranch struct {
	InBranch []*User `json:"in_branch"`
}

type UserAutocomplete struct {
	Users      []*User `json:"users"`
	OutOfClass []*User `json:"out_of_class,omitempty"`
}

func (o *UserAutocomplete) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func UserAutocompleteFromJson(data io.Reader) *UserAutocomplete {
	decoder := json.NewDecoder(data)
	autocomplete := new(UserAutocomplete)
	err := decoder.Decode(&autocomplete)
	if err == nil {
		return autocomplete
	} else {
		return nil
	}
}

func (o *UserAutocompleteInClass) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func UserAutocompleteInClassFromJson(data io.Reader) *UserAutocompleteInClass {
	var o *UserAutocompleteInClass
	json.NewDecoder(data).Decode(&o)
	return o
}

func (o *UserAutocompleteInBranch) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func UserAutocompleteInBranchFromJson(data io.Reader) *UserAutocompleteInBranch {
	var o *UserAutocompleteInBranch
	json.NewDecoder(data).Decode(&o)
	return o
}
