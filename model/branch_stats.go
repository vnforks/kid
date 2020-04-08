// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package model

import (
	"encoding/json"
	"io"
)

type BranchStats struct {
	BranchId            string `json:"branch_id"`
	TotalMemberCount  int64  `json:"total_member_count"`
	ActiveMemberCount int64  `json:"active_member_count"`
}

func (o *BranchStats) ToJson() string {
	b, _ := json.Marshal(o)
	return string(b)
}

func BranchStatsFromJson(data io.Reader) *BranchStats {
	var o *BranchStats
	json.NewDecoder(data).Decode(&o)
	return o
}