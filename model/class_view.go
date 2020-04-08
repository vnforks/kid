// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"io"
)

type ClassView struct {
	ClassId     string `json:"class_id"`
	PrevClassId string `json:"prev_class_id"`
}

func (o *ClassView) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func ClassViewFromJson(data io.Reader) *ClassView {
	var o *ClassView
	json.NewDecoder(data).Decode(&o)
	return o
}

type ClassViewResponse struct {
	Status            string           `json:"status"`
	LastViewedAtTimes map[string]int64 `json:"last_viewed_at_times"`
}

func (o *ClassViewResponse) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func ClassViewResponseFromJson(data io.Reader) *ClassViewResponse {
	var o *ClassViewResponse
	json.NewDecoder(data).Decode(&o)
	return o
}
