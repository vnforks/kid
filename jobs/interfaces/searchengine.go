// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package interfaces

import (
	"github.com/vnforks/kid/v5/model"
)

type SearchEngineIndexerInterface interface {
	MakeWorker() model.Worker
}

type SearchEngineAggregatorInterface interface {
	MakeWorker() model.Worker
	MakeScheduler() model.Scheduler
}
