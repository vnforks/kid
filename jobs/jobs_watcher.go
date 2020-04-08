// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package jobs

import (
	"math/rand"
	"time"

	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
)

// Default polling interval for jobs termination.
// (Defining as `var` rather than `const` allows tests to lower the interval.)
var DEFAULT_WATCHER_POLLING_INTERVAL = 15000

type Watcher struct {
	srv     *JobServer
	workers *Workers

	stop            chan struct{}
	stopped         chan struct{}
	pollingInterval int
}

func (srv *JobServer) MakeWatcher(workers *Workers, pollingInterval int) *Watcher {
	return &Watcher{
		stop:            make(chan struct{}),
		stopped:         make(chan struct{}),
		pollingInterval: pollingInterval,
		workers:         workers,
		srv:             srv,
	}
}

func (watcher *Watcher) Start() {
	mlog.Debug("Watcher Started")

	// Delay for some random number of milliseconds before starting to ensure that multiple
	// instances of the jobserver  don't poll at a time too close to each other.
	rand.Seed(time.Now().UTC().UnixNano())
	<-time.After(time.Duration(rand.Intn(watcher.pollingInterval)) * time.Millisecond)

	defer func() {
		mlog.Debug("Watcher Finished")
		close(watcher.stopped)
	}()

	for {
		select {
		case <-watcher.stop:
			mlog.Debug("Watcher: Received stop signal")
			return
		case <-time.After(time.Duration(watcher.pollingInterval) * time.Millisecond):
			watcher.PollAndNotify()
		}
	}
}

func (watcher *Watcher) Stop() {
	mlog.Debug("Watcher Stopping")
	close(watcher.stop)
	<-watcher.stopped
}

func (watcher *Watcher) PollAndNotify() {
	jobs, err := watcher.srv.Store.Job().GetAllByStatus(model.JOB_STATUS_PENDING)
	if err != nil {
		mlog.Error("Error occurred getting all pending statuses.", mlog.Err(err))
		return
	}

	for _, job := range jobs {
		if job.Type == model.JOB_TYPE_DATA_RETENTION {
			if watcher.workers.DataRetention != nil {
				select {
				case watcher.workers.DataRetention.JobClass() <- *job:
				default:
				}
			}
		} else if job.Type == model.JOB_TYPE_MESSAGE_EXPORT {
			if watcher.workers.MessageExport != nil {
				select {
				case watcher.workers.MessageExport.JobClass() <- *job:
				default:
				}
			}
		} else if job.Type == model.JOB_TYPE_ELASTICSEARCH_POST_INDEXING {
			if watcher.workers.ElasticsearchIndexing != nil {
				select {
				case watcher.workers.ElasticsearchIndexing.JobClass() <- *job:
				default:
				}
			}
		} else if job.Type == model.JOB_TYPE_ELASTICSEARCH_POST_AGGREGATION {
			if watcher.workers.ElasticsearchAggregation != nil {
				select {
				case watcher.workers.ElasticsearchAggregation.JobClass() <- *job:
				default:
				}
			}
		} else if job.Type == model.JOB_TYPE_LDAP_SYNC {
			if watcher.workers.LdapSync != nil {
				select {
				case watcher.workers.LdapSync.JobClass() <- *job:
				default:
				}
			}
		} else if job.Type == model.JOB_TYPE_MIGRATIONS {
			if watcher.workers.Migrations != nil {
				select {
				case watcher.workers.Migrations.JobClass() <- *job:
				default:
				}
			}
		} else if job.Type == model.JOB_TYPE_PLUGINS {
			if watcher.workers.Plugins != nil {
				select {
				case watcher.workers.Plugins.JobClass() <- *job:
				default:
				}
			}
		}
	}
}
