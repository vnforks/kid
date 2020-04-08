// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

const (
	DAY_MILLISECONDS   = 24 * 60 * 60 * 1000
	MONTH_MILLISECONDS = 31 * DAY_MILLISECONDS
)

func (a *App) GetAnalytics(name string, branchId string) (model.AnalyticsRows, *model.AppError) {
	var systemUserCount int64
	systemUserCount, err := a.Srv().Store.User().Count(model.UserCountOptions{})
	if err != nil {
		return nil, err
	}

	if systemUserCount > int64(*a.Config().AnalyticsSettings.MaxUsersForStatistics) {
		mlog.Debug("More than limit users are on the system, intensive queries skipped", mlog.Int("limit", *a.Config().AnalyticsSettings.MaxUsersForStatistics))
	}

	if name == "standard" {
		var rows model.AnalyticsRows = make([]*model.AnalyticsRow, 11)
		rows[0] = &model.AnalyticsRow{Name: "class_open_count", Value: 0}
		rows[1] = &model.AnalyticsRow{Name: "class_private_count", Value: 0}
		rows[2] = &model.AnalyticsRow{Name: "post_count", Value: 0}
		rows[3] = &model.AnalyticsRow{Name: "unique_user_count", Value: 0}
		rows[4] = &model.AnalyticsRow{Name: "branch_count", Value: 0}
		rows[5] = &model.AnalyticsRow{Name: "total_websocket_connections", Value: 0}
		rows[6] = &model.AnalyticsRow{Name: "total_master_db_connections", Value: 0}
		rows[7] = &model.AnalyticsRow{Name: "total_read_db_connections", Value: 0}
		rows[8] = &model.AnalyticsRow{Name: "daily_active_users", Value: 0}
		rows[9] = &model.AnalyticsRow{Name: "monthly_active_users", Value: 0}
		rows[10] = &model.AnalyticsRow{Name: "inactive_user_count", Value: 0}

		var userChan chan store.StoreResult
		var userInactiveChan chan store.StoreResult
		if branchId == "" {
			userInactiveChan = make(chan store.StoreResult, 1)
			go func() {
				count, err := a.Srv().Store.User().AnalyticsGetInactiveUsersCount()
				userInactiveChan <- store.StoreResult{Data: count, Err: err}
				close(userInactiveChan)
			}()
		} else {
			userChan = make(chan store.StoreResult, 1)
			go func() {
				count, err := a.Srv().Store.User().Count(model.UserCountOptions{BranchId: branchId})
				userChan <- store.StoreResult{Data: count, Err: err}
				close(userChan)
			}()
		}

		branchCountChan := make(chan store.StoreResult, 1)
		go func() {
			branchCount, err := a.Srv().Store.Branch().AnalyticsBranchCount(false)
			branchCountChan <- store.StoreResult{Data: branchCount, Err: err}
			close(branchCountChan)
		}()

		dailyActiveChan := make(chan store.StoreResult, 1)
		go func() {
			dailyActive, err := a.Srv().Store.User().AnalyticsActiveCount(DAY_MILLISECONDS, model.UserCountOptions{IncludeDeleted: false})
			dailyActiveChan <- store.StoreResult{Data: dailyActive, Err: err}
			close(dailyActiveChan)
		}()

		monthlyActiveChan := make(chan store.StoreResult, 1)
		go func() {
			monthlyActive, err := a.Srv().Store.User().AnalyticsActiveCount(MONTH_MILLISECONDS, model.UserCountOptions{IncludeDeleted: false})
			monthlyActiveChan <- store.StoreResult{Data: monthlyActive, Err: err}
			close(monthlyActiveChan)
		}()

		r := <-userChan
		if r.Err != nil {
			return nil, r.Err
		}
		rows[0].Value = float64(r.Data.(int64))

		if userChan == nil {
			rows[3].Value = float64(systemUserCount)
		} else {
			r = <-userChan
			if r.Err != nil {
				return nil, r.Err
			}
			rows[3].Value = float64(r.Data.(int64))
		}

		if userInactiveChan == nil {
			rows[10].Value = -1
		} else {
			r = <-userInactiveChan
			if r.Err != nil {
				return nil, r.Err
			}
			rows[10].Value = float64(r.Data.(int64))
		}

		r = <-branchCountChan
		if r.Err != nil {
			return nil, r.Err
		}
		rows[4].Value = float64(r.Data.(int64))

		// If in HA mode then aggregate all the stats
		if a.Cluster() != nil && *a.Config().ClusterSettings.Enable {
			stats, err := a.Cluster().GetClusterStats()
			if err != nil {
				return nil, err
			}

			totalSockets := a.TotalWebsocketConnections()
			totalMasterDb := a.Srv().Store.TotalMasterDbConnections()
			totalReadDb := a.Srv().Store.TotalReadDbConnections()

			for _, stat := range stats {
				totalSockets = totalSockets + stat.TotalWebsocketConnections
				totalMasterDb = totalMasterDb + stat.TotalMasterDbConnections
				totalReadDb = totalReadDb + stat.TotalReadDbConnections
			}

			rows[5].Value = float64(totalSockets)
			rows[6].Value = float64(totalMasterDb)
			rows[7].Value = float64(totalReadDb)

		} else {
			rows[5].Value = float64(a.TotalWebsocketConnections())
			rows[6].Value = float64(a.Srv().Store.TotalMasterDbConnections())
			rows[7].Value = float64(a.Srv().Store.TotalReadDbConnections())
		}

		r = <-dailyActiveChan
		if r.Err != nil {
			return nil, r.Err
		}
		rows[8].Value = float64(r.Data.(int64))

		r = <-monthlyActiveChan
		if r.Err != nil {
			return nil, r.Err
		}
		rows[9].Value = float64(r.Data.(int64))

		return rows, nil
	} else if name == "extra_counts" {
		var rows model.AnalyticsRows = make([]*model.AnalyticsRow, 6)
		rows[0] = &model.AnalyticsRow{Name: "file_post_count", Value: 0}
		rows[1] = &model.AnalyticsRow{Name: "hashtag_post_count", Value: 0}
		rows[2] = &model.AnalyticsRow{Name: "incoming_webhook_count", Value: 0}
		rows[3] = &model.AnalyticsRow{Name: "outgoing_webhook_count", Value: 0}
		rows[4] = &model.AnalyticsRow{Name: "command_count", Value: 0}
		rows[5] = &model.AnalyticsRow{Name: "session_count", Value: 0}

		iHookChan := make(chan store.StoreResult, 1)
		go func() {
			c, err := a.Srv().Store.Webhook().AnalyticsIncomingCount(branchId)
			iHookChan <- store.StoreResult{Data: c, Err: err}
			close(iHookChan)
		}()

		oHookChan := make(chan store.StoreResult, 1)
		go func() {
			c, err := a.Srv().Store.Webhook().AnalyticsOutgoingCount(branchId)
			oHookChan <- store.StoreResult{Data: c, Err: err}
			close(oHookChan)
		}()

		commandChan := make(chan store.StoreResult, 1)
		go func() {
			c, err := a.Srv().Store.Command().AnalyticsCommandCount(branchId)
			commandChan <- store.StoreResult{Data: c, Err: err}
			close(commandChan)
		}()

		sessionChan := make(chan store.StoreResult, 1)
		go func() {
			count, err := a.Srv().Store.Session().AnalyticsSessionCount()
			sessionChan <- store.StoreResult{Data: count, Err: err}
			close(sessionChan)
		}()

		var fileChan chan store.StoreResult
		var hashtagChan chan store.StoreResult

		if fileChan == nil {
			rows[0].Value = -1
		} else {
			r := <-fileChan
			if r.Err != nil {
				return nil, r.Err
			}
			rows[0].Value = float64(r.Data.(int64))
		}

		if hashtagChan == nil {
			rows[1].Value = -1
		} else {
			r := <-hashtagChan
			if r.Err != nil {
				return nil, r.Err
			}
			rows[1].Value = float64(r.Data.(int64))
		}

		r := <-iHookChan
		if r.Err != nil {
			return nil, r.Err
		}
		rows[2].Value = float64(r.Data.(int64))

		r = <-oHookChan
		if r.Err != nil {
			return nil, r.Err
		}
		rows[3].Value = float64(r.Data.(int64))

		r = <-commandChan
		if r.Err != nil {
			return nil, r.Err
		}
		rows[4].Value = float64(r.Data.(int64))

		r = <-sessionChan
		if r.Err != nil {
			return nil, r.Err
		}
		rows[5].Value = float64(r.Data.(int64))

		return rows, nil
	}

	return nil, nil
}

func (a *App) GetRecentlyActiveUsersForBranch(branchId string) (map[string]*model.User, *model.AppError) {
	users, err := a.Srv().Store.User().GetRecentlyActiveUsersForBranch(branchId, 0, 100, nil)
	if err != nil {
		return nil, err
	}

	userMap := make(map[string]*model.User)

	for _, user := range users {
		userMap[user.Id] = user
	}

	return userMap, nil
}

func (a *App) GetRecentlyActiveUsersForBranchPage(branchId string, page, perPage int, asAdmin bool, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError) {
	users, err := a.Srv().Store.User().GetRecentlyActiveUsersForBranch(branchId, page*perPage, perPage, viewRestrictions)
	if err != nil {
		return nil, err
	}

	return a.sanitizeProfiles(users, asAdmin), nil
}

func (a *App) GetNewUsersForBranchPage(branchId string, page, perPage int, asAdmin bool, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError) {
	users, err := a.Srv().Store.User().GetNewUsersForBranch(branchId, page*perPage, perPage, viewRestrictions)
	if err != nil {
		return nil, err
	}

	return a.sanitizeProfiles(users, asAdmin), nil
}
