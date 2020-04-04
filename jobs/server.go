// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package jobs

import (
	ejobs "github.com/vnforks/kid/v5/einterfaces/jobs"
	tjobs "github.com/vnforks/kid/v5/jobs/interfaces"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/services/configservice"
	"github.com/vnforks/kid/v5/store"
)

type JobServer struct {
	ConfigService configservice.ConfigService
	Store         store.Store
	Workers       *Workers
	Schedulers    *Schedulers

	DataRetentionJob        ejobs.DataRetentionJobInterface
	MessageExportJob        ejobs.MessageExportJobInterface
	ElasticsearchAggregator ejobs.ElasticsearchAggregatorInterface
	ElasticsearchIndexer    ejobs.ElasticsearchIndexerInterface
	LdapSync                ejobs.LdapSyncInterface
	Migrations              tjobs.MigrationsJobInterface
	Plugins                 tjobs.PluginsJobInterface
}

func NewJobServer(configService configservice.ConfigService, store store.Store) *JobServer {
	return &JobServer{
		ConfigService: configService,
		Store:         store,
	}
}

func (srv *JobServer) Config() *model.Config {
	return srv.ConfigService.Config()
}

func (srv *JobServer) StartWorkers() {
	srv.Workers = srv.Workers.Start()
}

func (srv *JobServer) StartSchedulers() {
	srv.Schedulers = srv.Schedulers.Start()
}

func (srv *JobServer) StopWorkers() {
	if srv.Workers != nil {
		srv.Workers.Stop()
	}
}

func (srv *JobServer) StopSchedulers() {
	if srv.Schedulers != nil {
		srv.Schedulers.Stop()
	}
}
