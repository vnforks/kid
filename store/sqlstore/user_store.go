// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Masterminds/squirrel"
	sq "github.com/Masterminds/squirrel"
	"github.com/mattermost/gorp"

	"github.com/vnforks/kid/v5/einterfaces"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

const (
	MAX_GROUP_CLASSES_FOR_PROFILES = 50
)

var (
	USER_SEARCH_TYPE_NAMES_NO_FULL_NAME = []string{"Username", "Nickname"}
	USER_SEARCH_TYPE_NAMES              = []string{"Username", "FirstName", "LastName", "Nickname"}
	USER_SEARCH_TYPE_ALL_NO_FULL_NAME   = []string{"Username", "Nickname", "Email"}
	USER_SEARCH_TYPE_ALL                = []string{"Username", "FirstName", "LastName", "Nickname", "Email"}
)

type SqlUserStore struct {
	SqlStore
	metrics einterfaces.MetricsInterface

	// usersQuery is a starting point for all queries that return one or more Users.
	usersQuery sq.SelectBuilder
}

func (us SqlUserStore) ClearCaches() {}

func (us SqlUserStore) InvalidateProfileCacheForUser(userId string) {}

func newSqlUserStore(sqlStore SqlStore, metrics einterfaces.MetricsInterface) store.UserStore {
	us := &SqlUserStore{
		SqlStore: sqlStore,
		metrics:  metrics,
	}

	// note: we are providing field names explicitly here to maintain order of columns (needed when using raw queries)
	us.usersQuery = us.getQueryBuilder().
		Select("u.Id", "u.CreateAt", "u.UpdateAt", "u.DeleteAt", "u.Username", "u.Password", "u.AuthData", "u.AuthService", "u.Email", "u.EmailVerified", "u.Nickname", "u.FirstName", "u.LastName", "u.Position", "u.Roles", "u.AllowMarketing", "u.Props", "u.NotifyProps", "u.LastPasswordUpdate", "u.LastPictureUpdate", "u.FailedAttempts", "u.Locale", "u.Timezone", "u.MfaActive", "u.MfaSecret",
			"b.UserId IS NOT NULL AS IsBot", "COALESCE(b.Description, '') AS BotDescription", "COALESCE(b.LastIconUpdate, 0) AS BotLastIconUpdate").
		From("Users u").
		LeftJoin("Bots b ON ( b.UserId = u.Id )")

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(model.User{}, "Users").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("Username").SetMaxSize(64).SetUnique(true)
		table.ColMap("Password").SetMaxSize(128)
		table.ColMap("AuthData").SetMaxSize(128).SetUnique(true)
		table.ColMap("AuthService").SetMaxSize(32)
		table.ColMap("Email").SetMaxSize(128).SetUnique(true)
		table.ColMap("Nickname").SetMaxSize(64)
		table.ColMap("FirstName").SetMaxSize(64)
		table.ColMap("LastName").SetMaxSize(64)
		table.ColMap("Roles").SetMaxSize(256)
		table.ColMap("Props").SetMaxSize(4000)
		table.ColMap("NotifyProps").SetMaxSize(2000)
		table.ColMap("Locale").SetMaxSize(5)
		table.ColMap("MfaSecret").SetMaxSize(128)
		table.ColMap("Position").SetMaxSize(128)
		table.ColMap("Timezone").SetMaxSize(256)
	}

	return us
}

func (us SqlUserStore) createIndexesIfNotExists() {
	us.CreateIndexIfNotExists("idx_users_email", "Users", "Email")
	us.CreateIndexIfNotExists("idx_users_update_at", "Users", "UpdateAt")
	us.CreateIndexIfNotExists("idx_users_create_at", "Users", "CreateAt")
	us.CreateIndexIfNotExists("idx_users_delete_at", "Users", "DeleteAt")

	if us.DriverName() == model.DATABASE_DRIVER_POSTGRES {
		us.CreateIndexIfNotExists("idx_users_email_lower_textpattern", "Users", "lower(Email) text_pattern_ops")
		us.CreateIndexIfNotExists("idx_users_username_lower_textpattern", "Users", "lower(Username) text_pattern_ops")
		us.CreateIndexIfNotExists("idx_users_nickname_lower_textpattern", "Users", "lower(Nickname) text_pattern_ops")
		us.CreateIndexIfNotExists("idx_users_firstname_lower_textpattern", "Users", "lower(FirstName) text_pattern_ops")
		us.CreateIndexIfNotExists("idx_users_lastname_lower_textpattern", "Users", "lower(LastName) text_pattern_ops")
	}

	us.CreateFullTextIndexIfNotExists("idx_users_all_txt", "Users", strings.Join(USER_SEARCH_TYPE_ALL, ", "))
	us.CreateFullTextIndexIfNotExists("idx_users_all_no_full_name_txt", "Users", strings.Join(USER_SEARCH_TYPE_ALL_NO_FULL_NAME, ", "))
	us.CreateFullTextIndexIfNotExists("idx_users_names_txt", "Users", strings.Join(USER_SEARCH_TYPE_NAMES, ", "))
	us.CreateFullTextIndexIfNotExists("idx_users_names_no_full_name_txt", "Users", strings.Join(USER_SEARCH_TYPE_NAMES_NO_FULL_NAME, ", "))
}

func (us SqlUserStore) Save(user *model.User) (*model.User, *model.AppError) {
	if len(user.Id) > 0 {
		return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.existing.app_error", nil, "user_id="+user.Id, http.StatusBadRequest)
	}

	user.PreSave()
	if err := user.IsValid(); err != nil {
		return nil, err
	}

	if err := us.GetMaster().Insert(user); err != nil {
		if IsUniqueConstraintError(err, []string{"Email", "users_email_key", "idx_users_email_unique"}) {
			return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.email_exists.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
		}
		if IsUniqueConstraintError(err, []string{"Username", "users_username_key", "idx_users_username_unique"}) {
			return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.username_exists.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
		}
		return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
	}

	return user, nil
}

func (us SqlUserStore) Update(user *model.User, trustedUpdateData bool) (*model.UserUpdate, *model.AppError) {
	user.PreUpdate()

	if err := user.IsValid(); err != nil {
		return nil, err
	}

	oldUserResult, err := us.GetMaster().Get(model.User{}, user.Id)
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.Update", "store.sql_user.update.finding.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
	}

	if oldUserResult == nil {
		return nil, model.NewAppError("SqlUserStore.Update", "store.sql_user.update.find.app_error", nil, "user_id="+user.Id, http.StatusBadRequest)
	}

	oldUser := oldUserResult.(*model.User)
	user.CreateAt = oldUser.CreateAt
	user.AuthData = oldUser.AuthData
	user.AuthService = oldUser.AuthService
	user.Password = oldUser.Password
	user.LastPasswordUpdate = oldUser.LastPasswordUpdate
	user.LastPictureUpdate = oldUser.LastPictureUpdate
	user.EmailVerified = oldUser.EmailVerified
	user.FailedAttempts = oldUser.FailedAttempts
	user.MfaSecret = oldUser.MfaSecret
	user.MfaActive = oldUser.MfaActive

	if !trustedUpdateData {
		user.Roles = oldUser.Roles
		user.DeleteAt = oldUser.DeleteAt
	}

	if user.IsOAuthUser() {
		if !trustedUpdateData {
			user.Email = oldUser.Email
		}
	} else if user.IsLDAPUser() && !trustedUpdateData {
		if user.Username != oldUser.Username || user.Email != oldUser.Email {
			return nil, model.NewAppError("SqlUserStore.Update", "store.sql_user.update.can_not_change_ldap.app_error", nil, "user_id="+user.Id, http.StatusBadRequest)
		}
	} else if user.Email != oldUser.Email {
		user.EmailVerified = false
	}

	if user.Username != oldUser.Username {
		user.UpdateMentionKeysFromUsername(oldUser.Username)
	}

	count, err := us.GetMaster().Update(user)
	if err != nil {
		if IsUniqueConstraintError(err, []string{"Email", "users_email_key", "idx_users_email_unique"}) {
			return nil, model.NewAppError("SqlUserStore.Update", "store.sql_user.update.email_taken.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
		}
		if IsUniqueConstraintError(err, []string{"Username", "users_username_key", "idx_users_username_unique"}) {
			return nil, model.NewAppError("SqlUserStore.Update", "store.sql_user.update.username_taken.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusBadRequest)
		}
		return nil, model.NewAppError("SqlUserStore.Update", "store.sql_user.update.updating.app_error", nil, "user_id="+user.Id+", "+err.Error(), http.StatusInternalServerError)
	}

	if count != 1 {
		return nil, model.NewAppError("SqlUserStore.Update", "store.sql_user.update.app_error", nil, fmt.Sprintf("user_id=%v, count=%v", user.Id, count), http.StatusInternalServerError)
	}

	user.Sanitize(map[string]bool{})
	oldUser.Sanitize(map[string]bool{})
	return &model.UserUpdate{New: user, Old: oldUser}, nil
}

func (us SqlUserStore) UpdateLastPictureUpdate(userId string) *model.AppError {
	curTime := model.GetMillis()

	if _, err := us.GetMaster().Exec("UPDATE Users SET LastPictureUpdate = :Time, UpdateAt = :Time WHERE Id = :UserId", map[string]interface{}{"Time": curTime, "UserId": userId}); err != nil {
		return model.NewAppError("SqlUserStore.UpdateLastPictureUpdate", "store.sql_user.update_last_picture_update.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
	}

	return nil
}

func (us SqlUserStore) ResetLastPictureUpdate(userId string) *model.AppError {
	curTime := model.GetMillis()

	if _, err := us.GetMaster().Exec("UPDATE Users SET LastPictureUpdate = :PictureUpdateTime, UpdateAt = :UpdateTime WHERE Id = :UserId", map[string]interface{}{"PictureUpdateTime": 0, "UpdateTime": curTime, "UserId": userId}); err != nil {
		return model.NewAppError("SqlUserStore.ResetLastPictureUpdate", "store.sql_user.update_last_picture_update.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
	}

	return nil
}

func (us SqlUserStore) UpdateUpdateAt(userId string) (int64, *model.AppError) {
	curTime := model.GetMillis()

	if _, err := us.GetMaster().Exec("UPDATE Users SET UpdateAt = :Time WHERE Id = :UserId", map[string]interface{}{"Time": curTime, "UserId": userId}); err != nil {
		return curTime, model.NewAppError("SqlUserStore.UpdateUpdateAt", "store.sql_user.update_update.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
	}

	return curTime, nil
}

func (us SqlUserStore) UpdatePassword(userId, hashedPassword string) *model.AppError {
	updateAt := model.GetMillis()

	if _, err := us.GetMaster().Exec("UPDATE Users SET Password = :Password, LastPasswordUpdate = :LastPasswordUpdate, UpdateAt = :UpdateAt, AuthData = NULL, AuthService = '', FailedAttempts = 0 WHERE Id = :UserId", map[string]interface{}{"Password": hashedPassword, "LastPasswordUpdate": updateAt, "UpdateAt": updateAt, "UserId": userId}); err != nil {
		return model.NewAppError("SqlUserStore.UpdatePassword", "store.sql_user.update_password.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (us SqlUserStore) UpdateFailedPasswordAttempts(userId string, attempts int) *model.AppError {
	if _, err := us.GetMaster().Exec("UPDATE Users SET FailedAttempts = :FailedAttempts WHERE Id = :UserId", map[string]interface{}{"FailedAttempts": attempts, "UserId": userId}); err != nil {
		return model.NewAppError("SqlUserStore.UpdateFailedPasswordAttempts", "store.sql_user.update_failed_pwd_attempts.app_error", nil, "user_id="+userId, http.StatusInternalServerError)
	}

	return nil
}

func (us SqlUserStore) UpdateAuthData(userId string, service string, authData *string, email string, resetMfa bool) (string, *model.AppError) {
	email = strings.ToLower(email)

	updateAt := model.GetMillis()

	query := `
			UPDATE
			     Users
			SET
			     Password = '',
			     LastPasswordUpdate = :LastPasswordUpdate,
			     UpdateAt = :UpdateAt,
			     FailedAttempts = 0,
			     AuthService = :AuthService,
			     AuthData = :AuthData`

	if len(email) != 0 {
		query += ", Email = :Email"
	}

	if resetMfa {
		query += ", MfaActive = false, MfaSecret = ''"
	}

	query += " WHERE Id = :UserId"

	if _, err := us.GetMaster().Exec(query, map[string]interface{}{"LastPasswordUpdate": updateAt, "UpdateAt": updateAt, "UserId": userId, "AuthService": service, "AuthData": authData, "Email": email}); err != nil {
		if IsUniqueConstraintError(err, []string{"Email", "users_email_key", "idx_users_email_unique", "AuthData", "users_authdata_key"}) {
			return "", model.NewAppError("SqlUserStore.UpdateAuthData", "store.sql_user.update_auth_data.email_exists.app_error", map[string]interface{}{"Service": service, "Email": email}, "user_id="+userId+", "+err.Error(), http.StatusBadRequest)
		}
		return "", model.NewAppError("SqlUserStore.UpdateAuthData", "store.sql_user.update_auth_data.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
	}
	return userId, nil
}

func (us SqlUserStore) UpdateMfaSecret(userId, secret string) *model.AppError {
	updateAt := model.GetMillis()

	if _, err := us.GetMaster().Exec("UPDATE Users SET MfaSecret = :Secret, UpdateAt = :UpdateAt WHERE Id = :UserId", map[string]interface{}{"Secret": secret, "UpdateAt": updateAt, "UserId": userId}); err != nil {
		return model.NewAppError("SqlUserStore.UpdateMfaSecret", "store.sql_user.update_mfa_secret.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (us SqlUserStore) UpdateMfaActive(userId string, active bool) *model.AppError {
	updateAt := model.GetMillis()

	if _, err := us.GetMaster().Exec("UPDATE Users SET MfaActive = :Active, UpdateAt = :UpdateAt WHERE Id = :UserId", map[string]interface{}{"Active": active, "UpdateAt": updateAt, "UserId": userId}); err != nil {
		return model.NewAppError("SqlUserStore.UpdateMfaActive", "store.sql_user.update_mfa_active.app_error", nil, "id="+userId+", "+err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (us SqlUserStore) Get(id string) (*model.User, *model.AppError) {
	query := us.usersQuery.Where("Id = ?", id)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.Get", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	user := &model.User{}
	if err := us.GetReplica().SelectOne(user, queryString, args...); err == sql.ErrNoRows {
		return nil, model.NewAppError("SqlUserStore.Get", store.MISSING_ACCOUNT_ERROR, nil, "user_id="+id, http.StatusNotFound)
	} else if err != nil {
		return nil, model.NewAppError("SqlUserStore.Get", "store.sql_user.get.app_error", nil, "user_id="+id+", "+err.Error(), http.StatusInternalServerError)
	}

	return user, nil
}

func (us SqlUserStore) GetAll() ([]*model.User, *model.AppError) {
	query := us.usersQuery.OrderBy("Username ASC")

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetAll", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var data []*model.User
	if _, err := us.GetReplica().Select(&data, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetAll", "store.sql_user.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return data, nil
}

func (us SqlUserStore) GetAllAfter(limit int, afterId string) ([]*model.User, *model.AppError) {
	query := us.usersQuery.
		Where("Id > ?", afterId).
		OrderBy("Id ASC").
		Limit(uint64(limit))

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetAllAfter", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetAllAfter", "store.sql_user.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return users, nil
}

func (us SqlUserStore) GetEtagForAllProfiles() string {
	updateAt, err := us.GetReplica().SelectInt("SELECT UpdateAt FROM Users ORDER BY UpdateAt DESC LIMIT 1")
	if err != nil {
		return fmt.Sprintf("%v.%v", model.CurrentVersion, model.GetMillis())
	}
	return fmt.Sprintf("%v.%v", model.CurrentVersion, updateAt)
}

func (us SqlUserStore) GetAllProfiles(options *model.UserGetOptions) ([]*model.User, *model.AppError) {
	isPostgreSQL := us.DriverName() == model.DATABASE_DRIVER_POSTGRES
	query := us.usersQuery.
		OrderBy("u.Username ASC").
		Offset(uint64(options.Page * options.PerPage)).Limit(uint64(options.PerPage))

	query = applyViewRestrictionsFilter(query, options.ViewRestrictions, true)

	query = applyRoleFilter(query, options.Role, isPostgreSQL)

	if options.Inactive {
		query = query.Where("u.DeleteAt != 0")
	}

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetAllProfiles", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetAllProfiles", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, u := range users {
		u.Sanitize(map[string]bool{})
	}

	return users, nil
}

func applyRoleFilter(query sq.SelectBuilder, role string, isPostgreSQL bool) sq.SelectBuilder {
	if role == "" {
		return query
	}

	if isPostgreSQL {
		roleParam := fmt.Sprintf("%%%s%%", sanitizeSearchTerm(role, "\\"))
		return query.Where("u.Roles LIKE LOWER(?)", roleParam)
	}

	roleParam := fmt.Sprintf("%%%s%%", sanitizeSearchTerm(role, "*"))

	return query.Where("u.Roles LIKE ? ESCAPE '*'", roleParam)
}

func (us SqlUserStore) GetEtagForProfiles(branchId string) string {
	updateAt, err := us.GetReplica().SelectInt("SELECT UpdateAt FROM Users, BranchMembers WHERE BranchMembers.BranchId = :BranchId AND Users.Id = BranchMembers.UserId ORDER BY UpdateAt DESC LIMIT 1", map[string]interface{}{"BranchId": branchId})
	if err != nil {
		return fmt.Sprintf("%v.%v", model.CurrentVersion, model.GetMillis())
	}
	return fmt.Sprintf("%v.%v", model.CurrentVersion, updateAt)
}

func (us SqlUserStore) GetProfiles(options *model.UserGetOptions) ([]*model.User, *model.AppError) {
	isPostgreSQL := us.DriverName() == model.DATABASE_DRIVER_POSTGRES
	query := us.usersQuery.
		Join("BranchMembers tm ON ( tm.UserId = u.Id AND tm.DeleteAt = 0 )").
		Where("tm.BranchId = ?", options.InBranchId).
		OrderBy("u.Username ASC").
		Offset(uint64(options.Page * options.PerPage)).Limit(uint64(options.PerPage))

	query = applyViewRestrictionsFilter(query, options.ViewRestrictions, true)

	query = applyRoleFilter(query, options.Role, isPostgreSQL)

	if options.Inactive {
		query = query.Where("u.DeleteAt != 0")
	}

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfiles", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfiles", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, u := range users {
		u.Sanitize(map[string]bool{})
	}

	return users, nil
}

func (us SqlUserStore) InvalidateProfilesInClassCacheByUser(userId string) {}

func (us SqlUserStore) InvalidateProfilesInClassCache(classId string) {}

func (us SqlUserStore) GetProfilesInClass(classId string, offset int, limit int) ([]*model.User, *model.AppError) {
	query := us.usersQuery.
		Join("ClassMembers cm ON ( cm.UserId = u.Id )").
		Where("cm.ClassId = ?", classId).
		OrderBy("u.Username ASC").
		Offset(uint64(offset)).Limit(uint64(limit))

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesInClass", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesInClass", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, u := range users {
		u.Sanitize(map[string]bool{})
	}

	return users, nil
}

func (us SqlUserStore) GetProfilesInClassByStatus(classId string, offset int, limit int) ([]*model.User, *model.AppError) {
	query := us.usersQuery.
		Join("ClassMembers cm ON ( cm.UserId = u.Id )").
		LeftJoin("Status s ON ( s.UserId = u.Id )").
		Where("cm.ClassId = ?", classId).
		OrderBy(`
			CASE s.Status
				WHEN 'online' THEN 1
				WHEN 'away' THEN 2
				WHEN 'dnd' THEN 3
				ELSE 4
			END
			`).
		OrderBy("u.Username ASC").
		Offset(uint64(offset)).Limit(uint64(limit))

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesInClassByStatus", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesInClassByStatus", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, u := range users {
		u.Sanitize(map[string]bool{})
	}

	return users, nil
}

func (us SqlUserStore) GetAllProfilesInClass(classId string, allowFromCache bool) (map[string]*model.User, *model.AppError) {
	failure := func(e error) (map[string]*model.User, *model.AppError) {
		return nil, model.NewAppError("SqlUserStore.GetAllProfilesInClass", "store.sql_user.app_error", nil, e.Error(), http.StatusInternalServerError)
	}
	query := us.usersQuery.
		Join("ClassMembers cm ON ( cm.UserId = u.Id )").
		Where("cm.ClassId = ?", classId).
		Where("u.DeleteAt = 0").
		OrderBy("u.Username ASC")

	queryString, args, err := query.ToSql()
	if err != nil {
		return failure(err)
	}
	var users []*model.User
	rows, err := us.GetReplica().Db.Query(queryString, args...)
	if err != nil {
		return failure(err)
	}

	defer rows.Close()
	for rows.Next() {
		var user model.User
		var props, notifyProps, timezone []byte
		if err = rows.Scan(&user.Id, &user.CreateAt, &user.UpdateAt, &user.DeleteAt, &user.Username, &user.Password, &user.AuthData, &user.AuthService, &user.Email, &user.EmailVerified, &user.Nickname, &user.FirstName, &user.LastName, &user.Position, &user.Roles, &user.AllowMarketing, &props, &notifyProps, &user.LastPasswordUpdate, &user.LastPictureUpdate, &user.FailedAttempts, &user.Locale, &timezone, &user.MfaActive, &user.MfaSecret, &user.IsBot, &user.BotDescription, &user.BotLastIconUpdate); err != nil {
			return failure(err)
		}
		if err = json.Unmarshal(props, &user.Props); err != nil {
			return failure(err)
		}
		if err = json.Unmarshal(notifyProps, &user.NotifyProps); err != nil {
			return failure(err)
		}
		if err = json.Unmarshal(timezone, &user.Timezone); err != nil {
			return failure(err)
		}
		users = append(users, &user)
	}
	err = rows.Err()
	if err != nil {
		return failure(err)
	}

	userMap := make(map[string]*model.User)

	for _, u := range users {
		u.Sanitize(map[string]bool{})
		userMap[u.Id] = u
	}

	return userMap, nil
}

func (us SqlUserStore) GetProfilesNotInClass(branchId string, classId string, groupConstrained bool, offset int, limit int, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError) {
	query := us.usersQuery.
		Join("BranchMembers tm ON ( tm.UserId = u.Id AND tm.DeleteAt = 0 AND tm.BranchId = ? )", branchId).
		LeftJoin("ClassMembers cm ON ( cm.UserId = u.Id AND cm.ClassId = ? )", classId).
		Where("cm.UserId IS NULL").
		OrderBy("u.Username ASC").
		Offset(uint64(offset)).Limit(uint64(limit))

	query = applyViewRestrictionsFilter(query, viewRestrictions, true)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesNotInClass", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesNotInClass", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, u := range users {
		u.Sanitize(map[string]bool{})
	}

	return users, nil
}

func (us SqlUserStore) GetProfilesWithoutBranch(options *model.UserGetOptions) ([]*model.User, *model.AppError) {
	isPostgreSQL := us.DriverName() == model.DATABASE_DRIVER_POSTGRES
	query := us.usersQuery.
		Where(`(
			SELECT
				COUNT(0)
			FROM
				BranchMembers
			WHERE
				BranchMembers.UserId = u.Id
				AND BranchMembers.DeleteAt = 0
		) = 0`).
		OrderBy("u.Username ASC").
		Offset(uint64(options.Page * options.PerPage)).Limit(uint64(options.PerPage))

	query = applyViewRestrictionsFilter(query, options.ViewRestrictions, true)

	query = applyRoleFilter(query, options.Role, isPostgreSQL)

	if options.Inactive {
		query = query.Where("u.DeleteAt != 0")
	}

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesWithoutBranch", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesWithoutBranch", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, u := range users {
		u.Sanitize(map[string]bool{})
	}

	return users, nil
}

func (us SqlUserStore) GetProfilesByUsernames(usernames []string, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError) {
	query := us.usersQuery

	query = applyViewRestrictionsFilter(query, viewRestrictions, true)

	query = query.
		Where(map[string]interface{}{
			"Username": usernames,
		}).
		OrderBy("u.Username ASC")

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesByUsernames", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfilesByUsernames", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return users, nil
}

type UserWithLastActivityAt struct {
	model.User
	LastActivityAt int64
}

func (us SqlUserStore) GetRecentlyActiveUsersForBranch(branchId string, offset, limit int, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError) {
	query := us.usersQuery.
		Column("s.LastActivityAt").
		Join("BranchMembers tm ON (tm.UserId = u.Id AND tm.BranchId = ?)", branchId).
		Join("Status s ON (s.UserId = u.Id)").
		OrderBy("s.LastActivityAt DESC").
		OrderBy("u.Username ASC").
		Offset(uint64(offset)).Limit(uint64(limit))

	query = applyViewRestrictionsFilter(query, viewRestrictions, true)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetRecentlyActiveUsers", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*UserWithLastActivityAt
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetRecentlyActiveUsers", "store.sql_user.get_recently_active_users.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	userList := []*model.User{}

	for _, userWithLastActivityAt := range users {
		u := userWithLastActivityAt.User
		u.Sanitize(map[string]bool{})
		u.LastActivityAt = userWithLastActivityAt.LastActivityAt
		userList = append(userList, &u)
	}

	return userList, nil
}

func (us SqlUserStore) GetNewUsersForBranch(branchId string, offset, limit int, viewRestrictions *model.ViewUsersRestrictions) ([]*model.User, *model.AppError) {
	query := us.usersQuery.
		Join("BranchMembers tm ON (tm.UserId = u.Id AND tm.BranchId = ?)", branchId).
		OrderBy("u.CreateAt DESC").
		OrderBy("u.Username ASC").
		Offset(uint64(offset)).Limit(uint64(limit))

	query = applyViewRestrictionsFilter(query, viewRestrictions, true)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetNewUsersForBranch", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetNewUsersForBranch", "store.sql_user.get_new_users.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, u := range users {
		u.Sanitize(map[string]bool{})
	}

	return users, nil
}

func (us SqlUserStore) GetProfileByIds(userIds []string, options *store.UserGetByIdsOpts, _ bool) ([]*model.User, *model.AppError) {
	if options == nil {
		options = &store.UserGetByIdsOpts{}
	}

	users := []*model.User{}
	query := us.usersQuery.
		Where(map[string]interface{}{
			"u.Id": userIds,
		}).
		OrderBy("u.Username ASC")

	if options.Since > 0 {
		query = query.Where(squirrel.Gt(map[string]interface{}{
			"u.UpdateAt": options.Since,
		}))
	}

	query = applyViewRestrictionsFilter(query, options.ViewRestrictions, true)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfileByIds", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetProfileByIds", "store.sql_user.get_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, u := range users {
		u.Sanitize(map[string]bool{})
	}

	return users, nil
}

type UserWithClass struct {
	model.User
	ClassId string
}

func (us SqlUserStore) GetSystemAdminProfiles() (map[string]*model.User, *model.AppError) {
	query := us.usersQuery.
		Where("Roles LIKE ?", "%system_admin%").
		OrderBy("u.Username ASC")

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetSystemAdminProfiles", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetSystemAdminProfiles", "store.sql_user.get_sysadmin_profiles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	userMap := make(map[string]*model.User)

	for _, u := range users {
		u.Sanitize(map[string]bool{})
		userMap[u.Id] = u
	}

	return userMap, nil
}

func (us SqlUserStore) GetByEmail(email string) (*model.User, *model.AppError) {
	email = strings.ToLower(email)

	query := us.usersQuery.Where("Email = ?", email)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetByEmail", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	user := model.User{}
	if err := us.GetReplica().SelectOne(&user, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetByEmail", store.MISSING_ACCOUNT_ERROR, nil, "email="+email+", "+err.Error(), http.StatusInternalServerError)
	}

	return &user, nil
}

func (us SqlUserStore) GetByAuth(authData *string, authService string) (*model.User, *model.AppError) {
	if authData == nil || *authData == "" {
		return nil, model.NewAppError("SqlUserStore.GetByAuth", store.MISSING_AUTH_ACCOUNT_ERROR, nil, "authData='', authService="+authService, http.StatusBadRequest)
	}

	query := us.usersQuery.
		Where("u.AuthData = ?", authData).
		Where("u.AuthService = ?", authService)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetByAuth", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	user := model.User{}
	if err := us.GetReplica().SelectOne(&user, queryString, args...); err == sql.ErrNoRows {
		return nil, model.NewAppError("SqlUserStore.GetByAuth", store.MISSING_AUTH_ACCOUNT_ERROR, nil, "authData="+*authData+", authService="+authService+", "+err.Error(), http.StatusInternalServerError)
	} else if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetByAuth", "store.sql_user.get_by_auth.other.app_error", nil, "authData="+*authData+", authService="+authService+", "+err.Error(), http.StatusInternalServerError)
	}
	return &user, nil
}

func (us SqlUserStore) GetAllUsingAuthService(authService string) ([]*model.User, *model.AppError) {
	query := us.usersQuery.
		Where("u.AuthService = ?", authService).
		OrderBy("u.Username ASC")

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetAllUsingAuthService", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var users []*model.User
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetAllUsingAuthService", "store.sql_user.get_by_auth.other.app_error", nil, "authService="+authService+", "+err.Error(), http.StatusInternalServerError)
	}

	return users, nil
}

func (us SqlUserStore) GetByUsername(username string) (*model.User, *model.AppError) {
	query := us.usersQuery.Where("u.Username = ?", username)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetByUsername", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var user *model.User
	if err := us.GetReplica().SelectOne(&user, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetByUsername", "store.sql_user.get_by_username.app_error", nil, err.Error()+" -- "+queryString, http.StatusInternalServerError)
	}

	return user, nil
}

func (us SqlUserStore) GetForLogin(loginId string, allowSignInWithUsername, allowSignInWithEmail bool) (*model.User, *model.AppError) {
	query := us.usersQuery
	if allowSignInWithUsername && allowSignInWithEmail {
		query = query.Where("Username = ? OR Email = ?", loginId, loginId)
	} else if allowSignInWithUsername {
		query = query.Where("Username = ?", loginId)
	} else if allowSignInWithEmail {
		query = query.Where("Email = ?", loginId)
	} else {
		return nil, model.NewAppError("SqlUserStore.GetForLogin", "store.sql_user.get_for_login.app_error", nil, "", http.StatusInternalServerError)
	}

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetForLogin", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	users := []*model.User{}
	if _, err := us.GetReplica().Select(&users, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlUserStore.GetForLogin", "store.sql_user.get_for_login.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	if len(users) == 0 {
		return nil, model.NewAppError("SqlUserStore.GetForLogin", "store.sql_user.get_for_login.app_error", nil, "", http.StatusInternalServerError)
	}

	if len(users) > 1 {
		return nil, model.NewAppError("SqlUserStore.GetForLogin", "store.sql_user.get_for_login.multiple_users", nil, "", http.StatusInternalServerError)
	}

	return users[0], nil

}

func (us SqlUserStore) VerifyEmail(userId, email string) (string, *model.AppError) {
	curTime := model.GetMillis()
	if _, err := us.GetMaster().Exec("UPDATE Users SET Email = :email, EmailVerified = true, UpdateAt = :Time WHERE Id = :UserId", map[string]interface{}{"email": email, "Time": curTime, "UserId": userId}); err != nil {
		return "", model.NewAppError("SqlUserStore.VerifyEmail", "store.sql_user.verify_email.app_error", nil, "userId="+userId+", "+err.Error(), http.StatusInternalServerError)
	}

	return userId, nil
}

func (us SqlUserStore) PermanentDelete(userId string) *model.AppError {
	if _, err := us.GetMaster().Exec("DELETE FROM Users WHERE Id = :UserId", map[string]interface{}{"UserId": userId}); err != nil {
		return model.NewAppError("SqlUserStore.PermanentDelete", "store.sql_user.permanent_delete.app_error", nil, "userId="+userId+", "+err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (us SqlUserStore) Count(options model.UserCountOptions) (int64, *model.AppError) {
	query := us.getQueryBuilder().Select("COUNT(DISTINCT u.Id)").From("Users AS u")

	if !options.IncludeDeleted {
		query = query.Where("u.DeleteAt = 0")
	}

	if options.IncludeBotAccounts {
		if options.ExcludeRegularUsers {
			query = query.Join("Bots ON u.Id = Bots.UserId")
		}
	} else {
		query = query.LeftJoin("Bots ON u.Id = Bots.UserId").Where("Bots.UserId IS NULL")
		if options.ExcludeRegularUsers {
			// Currently this doesn't make sense because it will always return 0
			return int64(0), model.NewAppError("SqlUserStore.Count", "store.sql_user.count.app_error", nil, "", http.StatusInternalServerError)
		}
	}

	if options.BranchId != "" {
		query = query.LeftJoin("BranchMembers AS tm ON u.Id = tm.UserId").Where("tm.BranchId = ? AND tm.DeleteAt = 0", options.BranchId)
	}
	query = applyViewRestrictionsFilter(query, options.ViewRestrictions, false)

	if us.DriverName() == model.DATABASE_DRIVER_POSTGRES {
		query = query.PlaceholderFormat(sq.Dollar)
	}

	queryString, args, err := query.ToSql()
	if err != nil {
		return int64(0), model.NewAppError("SqlUserStore.Get", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	count, err := us.GetReplica().SelectInt(queryString, args...)
	if err != nil {
		return int64(0), model.NewAppError("SqlUserStore.Count", "store.sql_user.get_total_users_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return count, nil
}

func (us SqlUserStore) AnalyticsActiveCount(timePeriod int64, options model.UserCountOptions) (int64, *model.AppError) {

	time := model.GetMillis() - timePeriod
	query := us.getQueryBuilder().Select("COUNT(*)").From("Status AS s").Where("LastActivityAt > :Time", map[string]interface{}{"Time": time})

	if !options.IncludeBotAccounts {
		query = query.LeftJoin("Bots ON s.UserId = Bots.UserId").Where("Bots.UserId IS NULL")
	}

	if !options.IncludeDeleted {
		query = query.LeftJoin("Users ON s.UserId = Users.Id").Where("Users.DeleteAt = 0")
	}

	queryStr, args, err := query.ToSql()

	if err != nil {
		return 0, model.NewAppError("SqlUserStore.Get", "store.sql_user.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	v, err := us.GetReplica().SelectInt(queryStr, args...)
	if err != nil {
		return 0, model.NewAppError("SqlUserStore.AnalyticsDailyActiveUsers", "store.sql_user.analytics_daily_active_users.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return v, nil
}

func (us SqlUserStore) AnalyticsGetInactiveUsersCount() (int64, *model.AppError) {
	count, err := us.GetReplica().SelectInt("SELECT COUNT(Id) FROM Users WHERE DeleteAt > 0")
	if err != nil {
		return int64(0), model.NewAppError("SqlUserStore.AnalyticsGetInactiveUsersCount", "store.sql_user.analytics_get_inactive_users_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return count, nil
}

func (us SqlUserStore) AnalyticsGetSystemAdminCount() (int64, *model.AppError) {
	count, err := us.GetReplica().SelectInt("SELECT count(*) FROM Users WHERE Roles LIKE :Roles and DeleteAt = 0", map[string]interface{}{"Roles": "%system_admin%"})
	if err != nil {
		return int64(0), model.NewAppError("SqlUserStore.AnalyticsGetSystemAdminCount", "store.sql_user.analytics_get_system_admin_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return count, nil
}

func (us SqlUserStore) ClearAllCustomRoleAssignments() *model.AppError {
	builtInRoles := model.MakeDefaultRoles()
	lastUserId := strings.Repeat("0", 26)

	for {
		var transaction *gorp.Transaction
		var err error

		if transaction, err = us.GetMaster().Begin(); err != nil {
			return model.NewAppError("SqlUserStore.ClearAllCustomRoleAssignments", "store.sql_user.clear_all_custom_role_assignments.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
		defer finalizeTransaction(transaction)

		var users []*model.User
		if _, err := transaction.Select(&users, "SELECT * from Users WHERE Id > :Id ORDER BY Id LIMIT 1000", map[string]interface{}{"Id": lastUserId}); err != nil {
			return model.NewAppError("SqlUserStore.ClearAllCustomRoleAssignments", "store.sql_user.clear_all_custom_role_assignments.select.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		if len(users) == 0 {
			break
		}

		for _, user := range users {
			lastUserId = user.Id

			var newRoles []string

			for _, role := range strings.Fields(user.Roles) {
				for name := range builtInRoles {
					if name == role {
						newRoles = append(newRoles, role)
						break
					}
				}
			}

			newRolesString := strings.Join(newRoles, " ")
			if newRolesString != user.Roles {
				if _, err := transaction.Exec("UPDATE Users SET Roles = :Roles WHERE Id = :Id", map[string]interface{}{"Roles": newRolesString, "Id": user.Id}); err != nil {
					return model.NewAppError("SqlUserStore.ClearAllCustomRoleAssignments", "store.sql_user.clear_all_custom_role_assignments.update.app_error", nil, err.Error(), http.StatusInternalServerError)
				}
			}
		}

		if err := transaction.Commit(); err != nil {
			return model.NewAppError("SqlUserStore.ClearAllCustomRoleAssignments", "store.sql_user.clear_all_custom_role_assignments.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
	}

	return nil
}

func (us SqlUserStore) InferSystemInstallDate() (int64, *model.AppError) {
	createAt, err := us.GetReplica().SelectInt("SELECT CreateAt FROM Users WHERE CreateAt IS NOT NULL ORDER BY CreateAt ASC LIMIT 1")
	if err != nil {
		return 0, model.NewAppError("SqlUserStore.GetSystemInstallDate", "store.sql_user.get_system_install_date.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return createAt, nil
}

func (us SqlUserStore) GetUnreadCount(userId string) (int64, *model.AppError) {
	query := `
		SELECT SUM(CASE WHEN c.Type = 'D' THEN (c.TotalMsgCount - cm.MsgCount) ELSE cm.MentionCount END)
		FROM Classes c
		INNER JOIN ClassMembers cm
			ON cm.ClassId = c.Id
			AND cm.UserId = :UserId
			AND c.DeleteAt = 0
	`
	count, err := us.GetReplica().SelectInt(query, map[string]interface{}{"UserId": userId})
	if err != nil {
		return count, model.NewAppError("SqlUserStore.GetMentionCount", "store.sql_user.get_unread_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return count, nil
}

func (us SqlUserStore) GetUsersBatchForIndexing(startTime, endTime int64, limit int) ([]*model.UserForIndexing, *model.AppError) {
	var users []*model.User
	usersQuery, args, _ := us.usersQuery.
		Where(sq.GtOrEq{"u.CreateAt": startTime}).
		Where(sq.Lt{"u.CreateAt": endTime}).
		OrderBy("u.CreateAt").
		Limit(uint64(limit)).
		ToSql()
	_, err := us.GetSearchReplica().Select(&users, usersQuery, args...)
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetUsersBatchForIndexing", "store.sql_user.get_users_batch_for_indexing.get_users.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	userIds := []string{}
	for _, user := range users {
		userIds = append(userIds, user.Id)
	}

	var classMembers []*model.ClassMember
	classMembersQuery, args, _ := us.getQueryBuilder().
		Select(`
				cm.ClassId,
				cm.UserId,
				cm.Roles,
				cm.LastViewedAt,
				cm.MsgCount,
				cm.MentionCount,
				cm.NotifyProps,
				cm.LastUpdateAt,
				cm.SchemeUser,
				cm.SchemeAdmin,
				(cm.SchemeGuest IS NOT NULL AND cm.SchemeGuest) as SchemeGuest
			`).
		From("ClassMembers cm").
		Join("Classes c ON cm.ClassId = c.Id").
		Where(sq.Eq{"c.Type": "O", "cm.UserId": userIds}).
		ToSql()
	_, err = us.GetSearchReplica().Select(&classMembers, classMembersQuery, args...)
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetUsersBatchForIndexing", "store.sql_user.get_users_batch_for_indexing.get_class_members.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var branchMembers []*model.BranchMember
	branchMembersQuery, args, _ := us.getQueryBuilder().
		Select("BranchId, UserId, Roles, DeleteAt, (SchemeGuest IS NOT NULL AND SchemeGuest) as SchemeGuest, SchemeUser, SchemeAdmin").
		From("BranchMembers").
		Where(sq.Eq{"UserId": userIds, "DeleteAt": 0}).
		ToSql()
	_, err = us.GetSearchReplica().Select(&branchMembers, branchMembersQuery, args...)
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.GetUsersBatchForIndexing", "store.sql_user.get_users_batch_for_indexing.get_branch_members.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	userMap := map[string]*model.UserForIndexing{}
	for _, user := range users {
		userMap[user.Id] = &model.UserForIndexing{
			Id:          user.Id,
			Username:    user.Username,
			Nickname:    user.Nickname,
			FirstName:   user.FirstName,
			LastName:    user.LastName,
			CreateAt:    user.CreateAt,
			DeleteAt:    user.DeleteAt,
			BranchesIds: []string{},
			ClassesIds:  []string{},
		}
	}

	for _, c := range classMembers {
		if userMap[c.UserId] != nil {
			userMap[c.UserId].ClassesIds = append(userMap[c.UserId].ClassesIds, c.ClassId)
		}
	}
	for _, t := range branchMembers {
		if userMap[t.UserId] != nil {
			userMap[t.UserId].BranchesIds = append(userMap[t.UserId].BranchesIds, t.BranchId)
		}
	}

	usersForIndexing := []*model.UserForIndexing{}
	for _, user := range userMap {
		usersForIndexing = append(usersForIndexing, user)
	}
	sort.Slice(usersForIndexing, func(i, j int) bool {
		return usersForIndexing[i].CreateAt < usersForIndexing[j].CreateAt
	})

	return usersForIndexing, nil
}

func applyViewRestrictionsFilter(query sq.SelectBuilder, restrictions *model.ViewUsersRestrictions, distinct bool) sq.SelectBuilder {
	if restrictions == nil {
		return query
	}

	// If you have no access to branches or classes, return and empty result.
	if restrictions.Branches != nil && len(restrictions.Branches) == 0 && restrictions.Classes != nil && len(restrictions.Classes) == 0 {
		return query.Where("1 = 0")
	}

	branches := make([]interface{}, len(restrictions.Branches))
	for i, v := range restrictions.Branches {
		branches[i] = v
	}
	classes := make([]interface{}, len(restrictions.Classes))
	for i, v := range restrictions.Classes {
		classes[i] = v
	}
	resultQuery := query
	if restrictions.Branches != nil && len(restrictions.Branches) > 0 {
		resultQuery = resultQuery.Join(fmt.Sprintf("BranchMembers rtm ON ( rtm.UserId = u.Id AND rtm.DeleteAt = 0 AND rtm.BranchId IN (%s))", sq.Placeholders(len(branches))), branches...)
	}
	if restrictions.Classes != nil && len(restrictions.Classes) > 0 {
		resultQuery = resultQuery.Join(fmt.Sprintf("ClassMembers rcm ON ( rcm.UserId = u.Id AND rcm.ClassId IN (%s))", sq.Placeholders(len(classes))), classes...)
	}

	if distinct {
		return resultQuery.Distinct()
	}

	return resultQuery
}
