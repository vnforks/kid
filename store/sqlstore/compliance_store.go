// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

type SqlComplianceStore struct {
	SqlStore
}

func newSqlComplianceStore(sqlStore SqlStore) store.ComplianceStore {
	s := &SqlComplianceStore{sqlStore}

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(model.Compliance{}, "Compliances").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("UserId").SetMaxSize(26)
		table.ColMap("Status").SetMaxSize(64)
		table.ColMap("Desc").SetMaxSize(512)
		table.ColMap("Type").SetMaxSize(64)
		table.ColMap("Keywords").SetMaxSize(512)
		table.ColMap("Emails").SetMaxSize(1024)
	}

	return s
}

func (s SqlComplianceStore) createIndexesIfNotExists() {
}

func (s SqlComplianceStore) Save(compliance *model.Compliance) (*model.Compliance, *model.AppError) {
	compliance.PreSave()
	if err := compliance.IsValid(); err != nil {
		return nil, err
	}

	if err := s.GetMaster().Insert(compliance); err != nil {
		return nil, model.NewAppError("SqlComplianceStore.Save", "store.sql_compliance.save.saving.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return compliance, nil
}

func (s SqlComplianceStore) Update(compliance *model.Compliance) (*model.Compliance, *model.AppError) {
	if err := compliance.IsValid(); err != nil {
		return nil, err
	}

	if _, err := s.GetMaster().Update(compliance); err != nil {
		return nil, model.NewAppError("SqlComplianceStore.Update", "store.sql_compliance.save.saving.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return compliance, nil
}

func (s SqlComplianceStore) GetAll(offset, limit int) (model.Compliances, *model.AppError) {
	query := "SELECT * FROM Compliances ORDER BY CreateAt DESC LIMIT :Limit OFFSET :Offset"

	var compliances model.Compliances
	if _, err := s.GetReplica().Select(&compliances, query, map[string]interface{}{"Offset": offset, "Limit": limit}); err != nil {
		return nil, model.NewAppError("SqlComplianceStore.Get", "store.sql_compliance.get.finding.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return compliances, nil
}

func (s SqlComplianceStore) Get(id string) (*model.Compliance, *model.AppError) {
	obj, err := s.GetReplica().Get(model.Compliance{}, id)
	if err != nil {
		return nil, model.NewAppError("SqlComplianceStore.Get", "store.sql_compliance.get.finding.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	if obj == nil {
		return nil, model.NewAppError("SqlComplianceStore.Get", "store.sql_compliance.get.finding.app_error", nil, "", http.StatusNotFound)
	}
	return obj.(*model.Compliance), nil
}

func (s SqlComplianceStore) ComplianceExport(job *model.Compliance) ([]*model.CompliancePost, *model.AppError) {
	props := map[string]interface{}{"StartTime": job.StartAt, "EndTime": job.EndAt}

	keywordQuery := ""
	keywords := strings.Fields(strings.TrimSpace(strings.ToLower(strings.Replace(job.Keywords, ",", " ", -1))))
	if len(keywords) > 0 {

		keywordQuery = "AND ("

		for index, keyword := range keywords {
			keyword = sanitizeSearchTerm(keyword, "\\")
			if index >= 1 {
				keywordQuery += " OR LOWER(Posts.Message) LIKE :Keyword" + strconv.Itoa(index)
			} else {
				keywordQuery += "LOWER(Posts.Message) LIKE :Keyword" + strconv.Itoa(index)
			}

			props["Keyword"+strconv.Itoa(index)] = "%" + keyword + "%"
		}

		keywordQuery += ")"
	}

	emailQuery := ""
	emails := strings.Fields(strings.TrimSpace(strings.ToLower(strings.Replace(job.Emails, ",", " ", -1))))
	if len(emails) > 0 {

		emailQuery = "AND ("

		for index, email := range emails {
			if index >= 1 {
				emailQuery += " OR Users.Email = :Email" + strconv.Itoa(index)
			} else {
				emailQuery += "Users.Email = :Email" + strconv.Itoa(index)
			}

			props["Email"+strconv.Itoa(index)] = email
		}

		emailQuery += ")"
	}

	query :=
		`(SELECT
			Branches.Name AS BranchName,
			Branches.DisplayName AS BranchDisplayName,
			Classes.Name AS ClassName,
			Classes.DisplayName AS ClassDisplayName,
			Classes.Type AS ClassType,
			Users.Username AS UserUsername,
			Users.Email AS UserEmail,
			Users.Nickname AS UserNickname,
			Posts.Id AS PostId,
			Posts.CreateAt AS PostCreateAt,
			Posts.UpdateAt AS PostUpdateAt,
			Posts.DeleteAt AS PostDeleteAt,
			Posts.RootId AS PostRootId,
			Posts.ParentId AS PostParentId,
			Posts.OriginalId AS PostOriginalId,
			Posts.Message AS PostMessage,
			Posts.Type AS PostType,
			Posts.Props AS PostProps,
			Posts.Hashtags AS PostHashtags,
			Posts.FileIds AS PostFileIds,
		FROM
			Branches,
			Classes,
			Users,
			Posts
		WHERE
			Branches.Id = Classes.BranchId
				AND Posts.ClassId = Classes.Id
				AND Posts.UserId = Users.Id
				AND Posts.CreateAt > :StartTime
				AND Posts.CreateAt <= :EndTime
				` + emailQuery + `
				` + keywordQuery + `)
		UNION ALL
		(SELECT
			'direct-messages' AS BranchName,
			'Direct Messages' AS BranchDisplayName,
			Classes.Name AS ClassName,
			Classes.DisplayName AS ClassDisplayName,
			Classes.Type AS ClassType,
			Users.Username AS UserUsername,
			Users.Email AS UserEmail,
			Users.Nickname AS UserNickname,
			Posts.Id AS PostId,
			Posts.CreateAt AS PostCreateAt,
			Posts.UpdateAt AS PostUpdateAt,
			Posts.DeleteAt AS PostDeleteAt,
			Posts.RootId AS PostRootId,
			Posts.ParentId AS PostParentId,
			Posts.OriginalId AS PostOriginalId,
			Posts.Message AS PostMessage,
			Posts.Type AS PostType,
			Posts.Props AS PostProps,
			Posts.Hashtags AS PostHashtags,
			Posts.FileIds AS PostFileIds,
		FROM
			Classes,
			Users,
			Posts
		WHERE
			Classes.BranchId = ''
				AND Posts.ClassId = Classes.Id
				AND Posts.UserId = Users.Id
				AND Posts.CreateAt > :StartTime
				AND Posts.CreateAt <= :EndTime
				` + emailQuery + `
				` + keywordQuery + `)
		ORDER BY PostCreateAt
		LIMIT 30000`

	var cposts []*model.CompliancePost

	if _, err := s.GetReplica().Select(&cposts, query, props); err != nil {
		return nil, model.NewAppError("SqlPostStore.ComplianceExport", "store.sql_post.compliance_export.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return cposts, nil
}

func (s SqlComplianceStore) MessageExport(after int64, limit int) ([]*model.MessageExport, *model.AppError) {
	props := map[string]interface{}{"StartTime": after, "Limit": limit}
	query :=
		`SELECT
			Posts.Id AS PostId,
			Posts.CreateAt AS PostCreateAt,
			Posts.UpdateAt AS PostUpdateAt,
			Posts.DeleteAt AS PostDeleteAt,
			Posts.Message AS PostMessage,
			Posts.Type AS PostType,
			Posts.Props AS PostProps,
			Posts.OriginalId AS PostOriginalId,
			Posts.RootId AS PostRootId,
			Posts.Props AS PostProps,
			Posts.FileIds AS PostFileIds,
			Branches.Id AS BranchId,
			Branches.Name AS BranchName,
			Branches.DisplayName AS BranchDisplayName,
			Classes.Id AS ClassId,
			CASE
				WHEN Classes.Type = 'D' THEN 'Direct Message'
				WHEN Classes.Type = 'G' THEN 'Group Message'
				ELSE Classes.DisplayName
			END AS ClassDisplayName,
			Classes.Name AS ClassName,
			Classes.Type AS ClassType,
			Users.Id AS UserId,
			Users.Email AS UserEmail,
			Users.Username,
		FROM
			Posts
		LEFT OUTER JOIN Classes ON Posts.ClassId = Classes.Id
		LEFT OUTER JOIN Branches ON Classes.BranchId = Branches.Id
		LEFT OUTER JOIN Users ON Posts.UserId = Users.Id
		WHERE
			(Posts.CreateAt > :StartTime OR Posts.UpdateAt > :StartTime OR Posts.DeleteAt > :StartTime) AND
			Posts.Type NOT LIKE 'system_%'
		ORDER BY PostUpdateAt
		LIMIT :Limit`

	var cposts []*model.MessageExport
	if _, err := s.GetReplica().Select(&cposts, query, props); err != nil {
		return nil, model.NewAppError("SqlComplianceStore.MessageExport", "store.sql_compliance.message_export.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return cposts, nil
}
