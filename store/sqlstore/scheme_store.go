// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/mattermost/gorp"

	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

type SqlSchemeStore struct {
	SqlStore
}

func newSqlSchemeStore(sqlStore SqlStore) store.SchemeStore {
	s := &SqlSchemeStore{sqlStore}

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(model.Scheme{}, "Schemes").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("Name").SetMaxSize(model.SCHEME_NAME_MAX_LENGTH).SetUnique(true)
		table.ColMap("DisplayName").SetMaxSize(model.SCHEME_DISPLAY_NAME_MAX_LENGTH)
		table.ColMap("Description").SetMaxSize(model.SCHEME_DESCRIPTION_MAX_LENGTH)
		table.ColMap("Scope").SetMaxSize(32)
		table.ColMap("DefaultBranchAdminRole").SetMaxSize(64)
		table.ColMap("DefaultBranchUserRole").SetMaxSize(64)
		table.ColMap("DefaultClassAdminRole").SetMaxSize(64)
		table.ColMap("DefaultClassUserRole").SetMaxSize(64)
	}

	return s
}

func (s SqlSchemeStore) createIndexesIfNotExists() {
	s.CreateIndexIfNotExists("idx_schemes_class_user_role", "Schemes", "DefaultClassUserRole")
	s.CreateIndexIfNotExists("idx_schemes_class_admin_role", "Schemes", "DefaultClassAdminRole")
}

func (s *SqlSchemeStore) Save(scheme *model.Scheme) (*model.Scheme, *model.AppError) {
	if len(scheme.Id) == 0 {
		transaction, err := s.GetMaster().Begin()
		if err != nil {
			return nil, model.NewAppError("SqlSchemeStore.SaveScheme", "store.sql_scheme.save.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
		defer finalizeTransaction(transaction)

		newScheme, appErr := s.createScheme(scheme, transaction)
		if appErr != nil {
			return nil, appErr
		}
		if err := transaction.Commit(); err != nil {
			return nil, model.NewAppError("SqlSchemeStore.SchemeSave", "store.sql_scheme.save_scheme.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
		return newScheme, nil
	}

	if !scheme.IsValid() {
		return nil, model.NewAppError("SqlSchemeStore.Save", "store.sql_scheme.save.invalid_scheme.app_error", nil, "schemeId="+scheme.Id, http.StatusBadRequest)
	}

	scheme.UpdateAt = model.GetMillis()

	rowsChanged, err := s.GetMaster().Update(scheme)
	if err != nil {
		return nil, model.NewAppError("SqlSchemeStore.Save", "store.sql_scheme.save.update.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	if rowsChanged != 1 {
		return nil, model.NewAppError("SqlSchemeStore.Save", "store.sql_scheme.save.update.app_error", nil, "no record to update", http.StatusInternalServerError)
	}

	return scheme, nil
}

func (s *SqlSchemeStore) createScheme(scheme *model.Scheme, transaction *gorp.Transaction) (*model.Scheme, *model.AppError) {
	// Fetch the default system scheme roles to populate default permissions.
	defaultRoleNames := []string{model.BRANCH_ADMIN_ROLE_ID, model.BRANCH_USER_ROLE_ID, model.CLASS_ADMIN_ROLE_ID, model.CLASS_USER_ROLE_ID}
	defaultRoles := make(map[string]*model.Role)
	roles, err := s.SqlStore.Role().GetByNames(defaultRoleNames)
	if err != nil {
		return nil, err
	}

	for _, role := range roles {
		switch role.Name {
		case model.BRANCH_ADMIN_ROLE_ID:
			defaultRoles[model.BRANCH_ADMIN_ROLE_ID] = role
		case model.BRANCH_USER_ROLE_ID:
			defaultRoles[model.BRANCH_USER_ROLE_ID] = role
		case model.CLASS_ADMIN_ROLE_ID:
			defaultRoles[model.CLASS_ADMIN_ROLE_ID] = role
		case model.CLASS_USER_ROLE_ID:
			defaultRoles[model.CLASS_USER_ROLE_ID] = role
		}
	}

	if len(defaultRoles) != 6 {
		return nil, model.NewAppError("SqlSchemeStore.SaveScheme", "store.sql_scheme.save.retrieve_default_scheme_roles.app_error", nil, "", http.StatusInternalServerError)
	}

	// Create the appropriate default roles for the scheme.
	if scheme.Scope == model.SCHEME_SCOPE_BRANCH {
		// Branch Admin Role
		branchAdminRole := &model.Role{
			Name:          model.NewId(),
			DisplayName:   fmt.Sprintf("Branch Admin Role for Scheme %s", scheme.Name),
			Permissions:   defaultRoles[model.BRANCH_ADMIN_ROLE_ID].Permissions,
			SchemeManaged: true,
		}

		savedRole, err := s.SqlStore.Role().(*SqlRoleStore).createRole(branchAdminRole, transaction)
		if err != nil {
			return nil, err
		}
		scheme.DefaultBranchAdminRole = savedRole.Name

		// Branch User Role
		branchUserRole := &model.Role{
			Name:          model.NewId(),
			DisplayName:   fmt.Sprintf("Branch User Role for Scheme %s", scheme.Name),
			Permissions:   defaultRoles[model.BRANCH_USER_ROLE_ID].Permissions,
			SchemeManaged: true,
		}

		savedRole, err = s.SqlStore.Role().(*SqlRoleStore).createRole(branchUserRole, transaction)
		if err != nil {
			return nil, err
		}
		scheme.DefaultBranchUserRole = savedRole.Name

	}

	if scheme.Scope == model.SCHEME_SCOPE_BRANCH || scheme.Scope == model.SCHEME_SCOPE_CLASS {
		// Class Admin Role
		classAdminRole := &model.Role{
			Name:          model.NewId(),
			DisplayName:   fmt.Sprintf("Class Admin Role for Scheme %s", scheme.Name),
			Permissions:   defaultRoles[model.CLASS_ADMIN_ROLE_ID].Permissions,
			SchemeManaged: true,
		}

		if scheme.Scope == model.SCHEME_SCOPE_CLASS {
			classAdminRole.Permissions = []string{}
		}

		savedRole, err := s.SqlStore.Role().(*SqlRoleStore).createRole(classAdminRole, transaction)
		if err != nil {
			return nil, err
		}
		scheme.DefaultClassAdminRole = savedRole.Name

		// Class User Role
		classUserRole := &model.Role{
			Name:          model.NewId(),
			DisplayName:   fmt.Sprintf("Class User Role for Scheme %s", scheme.Name),
			Permissions:   defaultRoles[model.CLASS_USER_ROLE_ID].Permissions,
			SchemeManaged: true,
		}

		if scheme.Scope == model.SCHEME_SCOPE_CLASS {
			classUserRole.Permissions = filterModerated(classUserRole.Permissions)
		}

		savedRole, err = s.SqlStore.Role().(*SqlRoleStore).createRole(classUserRole, transaction)
		if err != nil {
			return nil, err
		}
		scheme.DefaultClassUserRole = savedRole.Name

	}

	scheme.Id = model.NewId()
	if len(scheme.Name) == 0 {
		scheme.Name = model.NewId()
	}
	scheme.CreateAt = model.GetMillis()
	scheme.UpdateAt = scheme.CreateAt

	// Validate the scheme
	if !scheme.IsValidForCreate() {
		return nil, model.NewAppError("SqlSchemeStore.Save", "store.sql_scheme.save.invalid_scheme.app_error", nil, "", http.StatusBadRequest)
	}

	if err := transaction.Insert(scheme); err != nil {
		return nil, model.NewAppError("SqlSchemeStore.Save", "store.sql_scheme.save.insert.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return scheme, nil
}

func filterModerated(permissions []string) []string {
	filteredPermissions := []string{}
	for _, perm := range permissions {
		if _, ok := model.CLASS_MODERATED_PERMISSIONS_MAP[perm]; ok {
			filteredPermissions = append(filteredPermissions, perm)
		}
	}
	return filteredPermissions
}

func (s *SqlSchemeStore) Get(schemeId string) (*model.Scheme, *model.AppError) {
	var scheme model.Scheme
	if err := s.GetReplica().SelectOne(&scheme, "SELECT * from Schemes WHERE Id = :Id", map[string]interface{}{"Id": schemeId}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlSchemeStore.Get", "store.sql_scheme.get.app_error", nil, "Id="+schemeId+", "+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlSchemeStore.Get", "store.sql_scheme.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return &scheme, nil
}

func (s *SqlSchemeStore) GetByName(schemeName string) (*model.Scheme, *model.AppError) {
	var scheme model.Scheme

	if err := s.GetReplica().SelectOne(&scheme, "SELECT * from Schemes WHERE Name = :Name", map[string]interface{}{"Name": schemeName}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlSchemeStore.GetByName", "store.sql_scheme.get.app_error", nil, "Name="+schemeName+", "+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlSchemeStore.GetByName", "store.sql_scheme.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return &scheme, nil
}

func (s *SqlSchemeStore) Delete(schemeId string) (*model.Scheme, *model.AppError) {
	// Get the scheme
	var scheme model.Scheme
	if err := s.GetReplica().SelectOne(&scheme, "SELECT * from Schemes WHERE Id = :Id", map[string]interface{}{"Id": schemeId}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlSchemeStore.Delete", "store.sql_scheme.get.app_error", nil, "Id="+schemeId+", "+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlSchemeStore.Delete", "store.sql_scheme.get.app_error", nil, "Id="+schemeId+", "+err.Error(), http.StatusInternalServerError)
	}

	// Update any branches or classes using this scheme to the default scheme.
	if scheme.Scope == model.SCHEME_SCOPE_BRANCH {
		if _, err := s.GetMaster().Exec("UPDATE Branches SET SchemeId = '' WHERE SchemeId = :SchemeId", map[string]interface{}{"SchemeId": schemeId}); err != nil {
			return nil, model.NewAppError("SqlSchemeStore.Delete", "store.sql_scheme.reset_branches.app_error", nil, "Id="+schemeId+", "+err.Error(), http.StatusInternalServerError)
		}
	} else if scheme.Scope == model.SCHEME_SCOPE_CLASS {
		if _, err := s.GetMaster().Exec("UPDATE Classes SET SchemeId = '' WHERE SchemeId = :SchemeId", map[string]interface{}{"SchemeId": schemeId}); err != nil {
			return nil, model.NewAppError("SqlSchemeStore.Delete", "store.sql_scheme.reset_classes.app_error", nil, "Id="+schemeId+", "+err.Error(), http.StatusInternalServerError)
		}

		// Blow away the class caches.
		s.Class().ClearCaches()
	}

	// Delete the roles belonging to the scheme.
	roleNames := []string{scheme.DefaultClassUserRole, scheme.DefaultClassAdminRole}
	if scheme.Scope == model.SCHEME_SCOPE_BRANCH {
		roleNames = append(roleNames, scheme.DefaultBranchUserRole, scheme.DefaultBranchAdminRole)
	}

	var inQueryList []string
	queryArgs := make(map[string]interface{})
	for i, roleId := range roleNames {
		inQueryList = append(inQueryList, fmt.Sprintf(":RoleName%v", i))
		queryArgs[fmt.Sprintf("RoleName%v", i)] = roleId
	}
	inQuery := strings.Join(inQueryList, ", ")

	time := model.GetMillis()
	queryArgs["UpdateAt"] = time
	queryArgs["DeleteAt"] = time

	if _, err := s.GetMaster().Exec("UPDATE Roles SET UpdateAt = :UpdateAt, DeleteAt = :DeleteAt WHERE Name IN ("+inQuery+")", queryArgs); err != nil {
		return nil, model.NewAppError("SqlSchemeStore.Delete", "store.sql_scheme.delete.role_update.app_error", nil, "Id="+schemeId+", "+err.Error(), http.StatusInternalServerError)
	}

	// Delete the scheme itself.
	scheme.UpdateAt = time
	scheme.DeleteAt = time

	rowsChanged, err := s.GetMaster().Update(&scheme)
	if err != nil {
		return nil, model.NewAppError("SqlSchemeStore.Delete", "store.sql_scheme.delete.update.app_error", nil, "Id="+schemeId+", "+err.Error(), http.StatusInternalServerError)
	}
	if rowsChanged != 1 {
		return nil, model.NewAppError("SqlSchemeStore.Delete", "store.sql_scheme.delete.update.app_error", nil, "no record to update", http.StatusInternalServerError)
	}
	return &scheme, nil
}

func (s *SqlSchemeStore) GetAllPage(scope string, offset int, limit int) ([]*model.Scheme, *model.AppError) {
	var schemes []*model.Scheme

	scopeClause := ""
	if len(scope) > 0 {
		scopeClause = " AND Scope=:Scope "
	}

	if _, err := s.GetReplica().Select(&schemes, "SELECT * from Schemes WHERE DeleteAt = 0 "+scopeClause+" ORDER BY CreateAt DESC LIMIT :Limit OFFSET :Offset", map[string]interface{}{"Limit": limit, "Offset": offset, "Scope": scope}); err != nil {
		return nil, model.NewAppError("SqlSchemeStore.Get", "store.sql_scheme.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return schemes, nil
}

func (s *SqlSchemeStore) PermanentDeleteAll() *model.AppError {
	if _, err := s.GetMaster().Exec("DELETE from Schemes"); err != nil {
		return model.NewAppError("SqlSchemeStore.PermanentDeleteAll", "store.sql_scheme.permanent_delete_all.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s *SqlSchemeStore) CountByScope(scope string) (int64, *model.AppError) {
	count, err := s.GetReplica().SelectInt("SELECT count(*) FROM Schemes WHERE Scope = :Scope AND DeleteAt = 0", map[string]interface{}{"Scope": scope})
	if err != nil {
		return int64(0), model.NewAppError("SqlSchemeStore.CountByScope", "store.select_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return count, nil
}

func (s *SqlSchemeStore) CountWithoutPermission(schemeScope, permissionID string, roleScope model.RoleScope, roleType model.RoleType) (int64, *model.AppError) {
	joinCol := fmt.Sprintf("Default%s%sRole", roleScope, roleType)
	query := fmt.Sprintf(`
		SELECT
			count(*)
		FROM Schemes
			JOIN Roles ON Roles.Name = Schemes.%s
		WHERE
			Schemes.DeleteAt = 0 AND
			Schemes.Scope = '%s' AND
			Roles.Permissions NOT LIKE '%%%s%%'
	`, joinCol, schemeScope, permissionID)
	count, err := s.GetReplica().SelectInt(query)
	if err != nil {
		return int64(0), model.NewAppError("SqlSchemeStore.CountWithoutPermission", "store.select_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return count, nil
}
