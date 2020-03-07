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

// SystemPolicyInput, TeamPolicyInput, and ChannelPolicyInput will become the values that the public expect for
// their Rego policies, so we will want a model that does not change.

type SystemPolicyInput struct {
	RBACAccessGranted bool              `json:"rbac_access_granted"`
	User              *model.User       `json:"user"`
	Permission        *model.Permission `json:"permission"`
	Roles             []string          `json:"roles"`
}

type TeamPolicyInput struct {
	SystemPolicyInput
	Team *model.Team `json:"team"`
}

type ChannelPolicyInput struct {
	TeamPolicyInput
	Channel *model.Channel `json:"channel"`
}

func (a *App) PoliciesAllow(input interface{}) bool {
	r := rego.New(
		rego.Query("x = data.application.authz.allow"),
		rego.Load([]string{"./example.rego"}, nil))

	ctx := context.Background()

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		mlog.Error(err.Error())
		return false
	}

	resultSet, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		mlog.Error(err.Error())
		return false
	}

	allow := resultSet[0].Bindings["x"].(bool)

	mlog.Info(fmt.Sprintf("PoliciesAllow: %v\n", allow))

	return allow
}
