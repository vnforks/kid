// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
)

type ClassCounts struct {
	Counts      map[string]int64 `json:"counts"`
	UpdateTimes map[string]int64 `json:"update_times"`
}

func (o *ClassCounts) Etag() string {

	ids := []string{}
	for id := range o.Counts {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	str := ""
	for _, id := range ids {
		str += id + strconv.FormatInt(o.Counts[id], 10)
	}

	md5Counts := fmt.Sprintf("%x", md5.Sum([]byte(str)))

	var update int64 = 0
	for _, u := range o.UpdateTimes {
		if u > update {
			update = u
		}
	}

	return Etag(md5Counts, update)
}

func (o *ClassCounts) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func ClassCountsFromJson(data io.Reader) *ClassCounts {
	var o *ClassCounts
	json.NewDecoder(data).Decode(&o)
	return o
}
