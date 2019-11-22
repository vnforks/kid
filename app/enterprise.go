// Copyright (c) 2017-present Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	"github.com/mattermost/mattermost-server/einterfaces"
	ejobs "github.com/mattermost/mattermost-server/einterfaces/jobs"
	tjobs "github.com/mattermost/mattermost-server/jobs/interfaces"
	"github.com/mattermost/mattermost-server/mlog"
	"github.com/mattermost/mattermost-server/model"
	"github.com/mattermost/mattermost-server/services/searchengine"
)

var accountMigrationInterface func(*Server) einterfaces.AccountMigrationInterface

func RegisterAccountMigrationInterface(f func(*Server) einterfaces.AccountMigrationInterface) {
	accountMigrationInterface = f
}

var clusterInterface func(*Server) einterfaces.ClusterInterface

func RegisterClusterInterface(f func(*Server) einterfaces.ClusterInterface) {
	clusterInterface = f
}

var complianceInterface func(*App) einterfaces.ComplianceInterface

func RegisterComplianceInterface(f func(*App) einterfaces.ComplianceInterface) {
	complianceInterface = f
}

var dataRetentionInterface func(*App) einterfaces.DataRetentionInterface

func RegisterDataRetentionInterface(f func(*App) einterfaces.DataRetentionInterface) {
	dataRetentionInterface = f
}

var searchEngineInterface func(*App) searchengine.SearchEngineInterface

func RegisterSearchEngineInterface(f func(*App) searchengine.SearchEngineInterface) {
	searchEngineInterface = f
}

var jobsDataRetentionJobInterface func(*App) ejobs.DataRetentionJobInterface

func RegisterJobsDataRetentionJobInterface(f func(*App) ejobs.DataRetentionJobInterface) {
	jobsDataRetentionJobInterface = f
}

var jobsMessageExportJobInterface func(*App) ejobs.MessageExportJobInterface

func RegisterJobsMessageExportJobInterface(f func(*App) ejobs.MessageExportJobInterface) {
	jobsMessageExportJobInterface = f
}

var jobsSearchEngineAggregatorInterface func(*App) tjobs.SearchEngineAggregatorInterface

func RegisterJobsSearchEngineAggregatorInterface(f func(*App) tjobs.SearchEngineAggregatorInterface) {
	jobsSearchEngineAggregatorInterface = f
}

var jobsSearchEngineIndexerInterface func(*App) tjobs.SearchEngineIndexerInterface

func RegisterJobsSearchEngineIndexerInterface(f func(*App) tjobs.SearchEngineIndexerInterface) {
	jobsSearchEngineIndexerInterface = f
}

var jobsLdapSyncInterface func(*App) ejobs.LdapSyncInterface

func RegisterJobsLdapSyncInterface(f func(*App) ejobs.LdapSyncInterface) {
	jobsLdapSyncInterface = f
}

var jobsMigrationsInterface func(*App) tjobs.MigrationsJobInterface

func RegisterJobsMigrationsJobInterface(f func(*App) tjobs.MigrationsJobInterface) {
	jobsMigrationsInterface = f
}

var jobsPluginsInterface func(*App) tjobs.PluginsJobInterface

func RegisterJobsPluginsJobInterface(f func(*App) tjobs.PluginsJobInterface) {
	jobsPluginsInterface = f
}

var ldapInterface func(*App) einterfaces.LdapInterface

func RegisterLdapInterface(f func(*App) einterfaces.LdapInterface) {
	ldapInterface = f
}

var messageExportInterface func(*App) einterfaces.MessageExportInterface

func RegisterMessageExportInterface(f func(*App) einterfaces.MessageExportInterface) {
	messageExportInterface = f
}

var metricsInterface func(*App) einterfaces.MetricsInterface

func RegisterMetricsInterface(f func(*App) einterfaces.MetricsInterface) {
	metricsInterface = f
}

var samlInterface func(*App) einterfaces.SamlInterface

func RegisterSamlInterface(f func(*App) einterfaces.SamlInterface) {
	samlInterface = f
}

func (s *Server) initEnterprise() {
	if accountMigrationInterface != nil {
		s.AccountMigration = accountMigrationInterface(s)
	}
	if complianceInterface != nil {
		s.Compliance = complianceInterface(s.FakeApp())
	}
	if searchEngineInterface != nil {
		s.SearchEngine = searchEngineInterface(s.FakeApp())
	}
	if ldapInterface != nil {
		s.Ldap = ldapInterface(s.FakeApp())
	}
	if messageExportInterface != nil {
		s.MessageExport = messageExportInterface(s.FakeApp())
	}
	if metricsInterface != nil {
		s.Metrics = metricsInterface(s.FakeApp())
	}
	if samlInterface != nil {
		s.Saml = samlInterface(s.FakeApp())
		s.AddConfigListener(func(_, cfg *model.Config) {
			if err := s.Saml.ConfigureSP(); err != nil {
				mlog.Error("An error occurred while configuring SAML Service Provider", mlog.Err(err))
			}
		})
	}
	if dataRetentionInterface != nil {
		s.DataRetention = dataRetentionInterface(s.FakeApp())
	}
	if clusterInterface != nil {
		s.Cluster = clusterInterface(s)
	}
}
