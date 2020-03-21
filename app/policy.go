// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"context"
	"fmt"

	"github.com/mattermost/mattermost-server/v5/mlog"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/open-policy-agent/opa/rego"
)

type PolicyInput struct {
	RBACAccessGranted bool                      `json:"rbac_access_granted"`
	User              *model.User               `json:"user"`
	Permission        *model.Permission         `json:"permission"`
	Roles             []string                  `json:"roles"`
	Team              *model.Team               `json:"team"`
	Channel           *model.Channel            `json:"channel"`
	Groups            []*model.GroupNameMembers `json:"groups"`
	ChannelMembers    []string                  `json:"channel_members"`
}

func (a *App) PoliciesAllow(input *PolicyInput) bool {
	r := rego.New(
		rego.Query("x = data.application.authz.allow"),
		rego.Load([]string{"./example.rego"}, nil),
	)

	ctx := context.Background()

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		mlog.Error(err.Error())
		return false
	}

	// b, marshalErr := json.Marshal(input)
	// if marshalErr != nil {
	// 	panic(marshalErr)
	// }
	// fmt.Println(string(b))

	fmt.Printf("%+v\n", input)

	resultSet, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		mlog.Error(err.Error())
		return false
	}

	allow := resultSet[0].Bindings["x"].(bool)

	mlog.Info(fmt.Sprintf("PoliciesAllow: %v\n", allow))

	return allow
}
