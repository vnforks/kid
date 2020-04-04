// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"io"
)

type ClassList []*Class

func (o *ClassList) ToJson() string {
	if b, err := json.Marshal(o); err != nil {
		return "[]"
	} else {
		return string(b)
	}
}

func (o *ClassList) Etag() string {

	id := "0"
	var t int64 = 0
	var delta int64 = 0

	for _, v := range *o {

		if v.UpdateAt > t {
			t = v.UpdateAt
			id = v.Id
		}

	}

	return Etag(id, t, delta, len(*o))
}

func ClassListFromJson(data io.Reader) *ClassList {
	var o *ClassList
	json.NewDecoder(data).Decode(&o)
	return o
}

func ClassSliceFromJson(data io.Reader) []*Class {
	var o []*Class
	json.NewDecoder(data).Decode(&o)
	return o
}

type ClassListWithBranchData []*ClassWithBranchData

func (o *ClassListWithBranchData) ToJson() string {
	if b, err := json.Marshal(o); err != nil {
		return "[]"
	} else {
		return string(b)
	}
}

func (o *ClassListWithBranchData) Etag() string {

	id := "0"
	var t int64 = 0
	var delta int64 = 0

	for _, v := range *o {

		if v.UpdateAt > t {
			t = v.UpdateAt
			id = v.Id
		}

		if v.BranchUpdateAt > t {
			t = v.BranchUpdateAt
			id = v.Id
		}
	}

	return Etag(id, t, delta, len(*o))
}

func ClassListWithBranchDataFromJson(data io.Reader) *ClassListWithBranchData {
	var o *ClassListWithBranchData
	json.NewDecoder(data).Decode(&o)
	return o
}
