// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/mattermost/gorp"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/store"
)

type SqlRoleStore struct {
	SqlStore
}

type Role struct {
	Id            string
	Name          string
	DisplayName   string
	Description   string
	CreateAt      int64
	UpdateAt      int64
	DeleteAt      int64
	Permissions   string
	SchemeManaged bool
	BuiltIn       bool
}

type classRolesPermissions struct {
	UserRoleName                 string
	AdminRoleName                string
	HigherScopedUserPermissions  string
	HigherScopedAdminPermissions string
}

func NewRoleFromModel(role *model.Role) *Role {
	permissionsMap := make(map[string]bool)
	permissions := ""

	for _, permission := range role.Permissions {
		if !permissionsMap[permission] {
			permissions += fmt.Sprintf(" %v", permission)
			permissionsMap[permission] = true
		}
	}

	return &Role{
		Id:            role.Id,
		Name:          role.Name,
		DisplayName:   role.DisplayName,
		Description:   role.Description,
		CreateAt:      role.CreateAt,
		UpdateAt:      role.UpdateAt,
		DeleteAt:      role.DeleteAt,
		Permissions:   permissions,
		SchemeManaged: role.SchemeManaged,
		BuiltIn:       role.BuiltIn,
	}
}

func (role Role) ToModel() *model.Role {
	return &model.Role{
		Id:            role.Id,
		Name:          role.Name,
		DisplayName:   role.DisplayName,
		Description:   role.Description,
		CreateAt:      role.CreateAt,
		UpdateAt:      role.UpdateAt,
		DeleteAt:      role.DeleteAt,
		Permissions:   strings.Fields(role.Permissions),
		SchemeManaged: role.SchemeManaged,
		BuiltIn:       role.BuiltIn,
	}
}

func newSqlRoleStore(sqlStore SqlStore) store.RoleStore {
	s := &SqlRoleStore{sqlStore}

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(Role{}, "Roles").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("Name").SetMaxSize(64).SetUnique(true)
		table.ColMap("DisplayName").SetMaxSize(128)
		table.ColMap("Description").SetMaxSize(1024)
		table.ColMap("Permissions").SetMaxSize(4096)
	}
	return s
}

func (s *SqlRoleStore) Save(role *model.Role) (*model.Role, *model.AppError) {
	// Check the role is valid before proceeding.
	if !role.IsValidWithoutId() {
		return nil, model.NewAppError("SqlRoleStore.Save", "store.sql_role.save.invalid_role.app_error", nil, "", http.StatusBadRequest)
	}

	if len(role.Id) == 0 {
		transaction, err := s.GetMaster().Begin()
		if err != nil {
			return nil, model.NewAppError("SqlRoleStore.RoleSave", "store.sql_role.save.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
		defer finalizeTransaction(transaction)
		createdRole, appErr := s.createRole(role, transaction)
		if appErr != nil {
			transaction.Rollback()
			return nil, appErr
		} else if err := transaction.Commit(); err != nil {
			return nil, model.NewAppError("SqlRoleStore.RoleSave", "store.sql_role.save_role.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
		return createdRole, nil
	}

	dbRole := NewRoleFromModel(role)
	dbRole.UpdateAt = model.GetMillis()
	if rowsChanged, err := s.GetMaster().Update(dbRole); err != nil {
		return nil, model.NewAppError("SqlRoleStore.Save", "store.sql_role.save.update.app_error", nil, err.Error(), http.StatusInternalServerError)
	} else if rowsChanged != 1 {
		return nil, model.NewAppError("SqlRoleStore.Save", "store.sql_role.save.update.app_error", nil, "no record to update", http.StatusInternalServerError)
	}

	return dbRole.ToModel(), nil
}

func (s *SqlRoleStore) createRole(role *model.Role, transaction *gorp.Transaction) (*model.Role, *model.AppError) {
	// Check the role is valid before proceeding.
	if !role.IsValidWithoutId() {
		return nil, model.NewAppError("SqlRoleStore.Save", "store.sql_role.save.invalid_role.app_error", nil, "", http.StatusBadRequest)
	}

	dbRole := NewRoleFromModel(role)

	dbRole.Id = model.NewId()
	dbRole.CreateAt = model.GetMillis()
	dbRole.UpdateAt = dbRole.CreateAt

	if err := transaction.Insert(dbRole); err != nil {
		return nil, model.NewAppError("SqlRoleStore.Save", "store.sql_role.save.insert.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return dbRole.ToModel(), nil
}

func (s *SqlRoleStore) Get(roleId string) (*model.Role, *model.AppError) {
	var dbRole Role

	if err := s.GetReplica().SelectOne(&dbRole, "SELECT * from Roles WHERE Id = :Id", map[string]interface{}{"Id": roleId}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlRoleStore.Get", "store.sql_role.get.app_error", nil, "Id="+roleId+", "+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlRoleStore.Get", "store.sql_role.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return dbRole.ToModel(), nil
}

func (s *SqlRoleStore) GetAll() ([]*model.Role, *model.AppError) {
	var dbRoles []Role

	if _, err := s.GetReplica().Select(&dbRoles, "SELECT * from Roles", map[string]interface{}{}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlRoleStore.GetAll", "store.sql_role.get_all.app_error", nil, err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlRoleStore.GetAll", "store.sql_role.get_all.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var roles []*model.Role
	for _, dbRole := range dbRoles {
		roles = append(roles, dbRole.ToModel())
	}
	return roles, nil
}

func (s *SqlRoleStore) GetByName(name string) (*model.Role, *model.AppError) {
	var dbRole Role

	if err := s.GetReplica().SelectOne(&dbRole, "SELECT * from Roles WHERE Name = :Name", map[string]interface{}{"Name": name}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlRoleStore.GetByName", "store.sql_role.get_by_name.app_error", nil, "name="+name+",err="+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlRoleStore.GetByName", "store.sql_role.get_by_name.app_error", nil, "name="+name+",err="+err.Error(), http.StatusInternalServerError)
	}

	return dbRole.ToModel(), nil
}

func (s *SqlRoleStore) GetByNames(names []string) ([]*model.Role, *model.AppError) {
	var dbRoles []*Role

	if len(names) == 0 {
		return []*model.Role{}, nil
	}

	var searchPlaceholders []string
	var parameters = map[string]interface{}{}
	for i, value := range names {
		searchPlaceholders = append(searchPlaceholders, fmt.Sprintf(":Name%d", i))
		parameters[fmt.Sprintf("Name%d", i)] = value
	}

	searchTerm := "Name IN (" + strings.Join(searchPlaceholders, ", ") + ")"

	if _, err := s.GetReplica().Select(&dbRoles, "SELECT * from Roles WHERE "+searchTerm, parameters); err != nil {
		return nil, model.NewAppError("SqlRoleStore.GetByNames", "store.sql_role.get_by_names.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var roles []*model.Role
	for _, dbRole := range dbRoles {
		roles = append(roles, dbRole.ToModel())
	}

	return roles, nil
}

func (s *SqlRoleStore) Delete(roleId string) (*model.Role, *model.AppError) {
	// Get the role.
	var role *Role
	if err := s.GetReplica().SelectOne(&role, "SELECT * from Roles WHERE Id = :Id", map[string]interface{}{"Id": roleId}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlRoleStore.Delete", "store.sql_role.get.app_error", nil, "Id="+roleId+", "+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlRoleStore.Delete", "store.sql_role.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	time := model.GetMillis()
	role.DeleteAt = time
	role.UpdateAt = time

	if rowsChanged, err := s.GetMaster().Update(role); err != nil {
		return nil, model.NewAppError("SqlRoleStore.Delete", "store.sql_role.delete.update.app_error", nil, err.Error(), http.StatusInternalServerError)
	} else if rowsChanged != 1 {
		return nil, model.NewAppError("SqlRoleStore.Delete", "store.sql_role.delete.update.app_error", nil, "no record to update", http.StatusInternalServerError)
	}
	return role.ToModel(), nil
}

func (s *SqlRoleStore) PermanentDeleteAll() *model.AppError {
	if _, err := s.GetMaster().Exec("DELETE FROM Roles"); err != nil {
		return model.NewAppError("SqlRoleStore.PermanentDeleteAll", "store.sql_role.permanent_delete_all.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s *SqlRoleStore) classHigherScopedPermissionsQuery(roleNames []string) string {
	sqlTmpl := `
		SELECT
			RoleSchemes.DefaultClassUserRole AS UserRoleName,
			RoleSchemes.DefaultClassAdminRole AS AdminRoleName,
			UserRoles.Permissions AS HigherScopedUserPermissions,
			AdminRoles.Permissions AS HigherScopedAdminPermissions
		FROM
			Schemes AS RoleSchemes
			JOIN Classes ON Classes.SchemeId = RoleSchemes.Id
			JOIN Branches ON Branches.Id = Classes.BranchId
			JOIN Schemes ON Schemes.Id = Branches.SchemeId
			JOIN Roles AS UserRoles ON UserRoles.Name = Schemes.DefaultClassUserRole
			JOIN Roles AS AdminRoles ON AdminRoles.Name = Schemes.DefaultClassAdminRole
		WHERE
			RoleSchemes.DefaultClassUserRole IN ('%[1]s')
			OR RoleSchemes.DefaultClassAdminRole IN ('%[1]s')
		UNION
		SELECT
			Schemes.DefaultClassUserRole AS UserRoleName,
			Schemes.DefaultClassAdminRole AS AdminRoleName,
			UserRoles.Permissions AS HigherScopedUserPermissions,
			AdminRoles.Permissions AS HigherScopedAdminPermissions
		FROM
			Schemes
			JOIN Classes ON Classes.SchemeId = Schemes.Id
			JOIN Branches ON Branches.Id = Classes.BranchId
			JOIN Roles AS UserRoles ON UserRoles.Name = '%[3]s'
			JOIN Roles AS AdminRoles ON AdminRoles.Name = '%[4]s'
		WHERE
			(Schemes.DefaultClassUserRole IN ('%[1]s')
			OR Schemes.DefaultClassAdminRole IN ('%[1]s'))
		AND (Branches.SchemeId = ''
			OR Branches.SchemeId IS NULL)
	`

	// The below three class role names are referenced by their name value because there is no system scheme
	// record that ships with Mattermost, otherwise the system scheme would be referenced by name and the class
	// roles would be referenced by their column names.
	return fmt.Sprintf(
		sqlTmpl,
		strings.Join(roleNames, "', '"),
		model.CLASS_USER_ROLE_ID,
		model.CLASS_ADMIN_ROLE_ID,
	)
}

func (s *SqlRoleStore) ClassHigherScopedPermissions(roleNames []string) (map[string]*model.RolePermissions, *model.AppError) {
	sql := s.classHigherScopedPermissionsQuery(roleNames)

	var rolesPermissions []*classRolesPermissions
	if _, err := s.GetReplica().Select(&rolesPermissions, sql); err != nil {
		return nil, model.NewAppError("SqlRoleStore.HigherScopedPermissions", "store.sql_role.get_by_names.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	roleNameHigherScopedPermissions := map[string]*model.RolePermissions{}

	for _, rp := range rolesPermissions {
		roleNameHigherScopedPermissions[rp.UserRoleName] = &model.RolePermissions{RoleID: model.CLASS_USER_ROLE_ID, Permissions: strings.Split(rp.HigherScopedUserPermissions, " ")}
		roleNameHigherScopedPermissions[rp.AdminRoleName] = &model.RolePermissions{RoleID: model.CLASS_ADMIN_ROLE_ID, Permissions: strings.Split(rp.HigherScopedAdminPermissions, " ")}
	}

	return roleNameHigherScopedPermissions, nil
}

func (s *SqlRoleStore) AllClassSchemeRoles() ([]*model.Role, *model.AppError) {
	query := s.getQueryBuilder().
		Select("Roles.*").
		From("Schemes").
		Join("Roles ON Schemes.DefaultClassUserRole = Roles.Name OR Schemes.DefaultClassAdminRole = Roles.Name").
		Where(sq.Eq{"Schemes.Scope": model.SCHEME_SCOPE_CLASS}).
		Where(sq.Eq{"Roles.DeleteAt": 0}).
		Where(sq.Eq{"Schemes.DeleteAt": 0})

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlRoleStore.AllClassSchemeManagedRoles", "store.sql.build_query.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var dbRoles []*Role
	if _, err = s.GetReplica().Select(&dbRoles, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlRoleStore.AllClassSchemeManagedRoles", "store.sql_role.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var roles []*model.Role
	for _, dbRole := range dbRoles {
		roles = append(roles, dbRole.ToModel())
	}

	return roles, nil
}

// ClassRolesUnderBranchRole finds all of the class-scheme roles under the branch of the given branch-scheme role.
func (s *SqlRoleStore) ClassRolesUnderBranchRole(roleName string) ([]*model.Role, *model.AppError) {
	query := s.getQueryBuilder().
		Select("ClassSchemeRoles.*").
		From("Roles AS HigherScopedRoles").
		Join("Schemes AS HigherScopedSchemes ON (HigherScopedRoles.Name = HigherScopedSchemes.DefaultClassUserRole OR HigherScopedRoles.Name = HigherScopedSchemes.DefaultClassAdminRole)").
		Join("Branches ON Branches.SchemeId = HigherScopedSchemes.Id").
		Join("Classes ON Classes.BranchId = Branches.Id").
		Join("Schemes AS ClassSchemes ON Classes.SchemeId = ClassSchemes.Id").
		Join("Roles AS ClassSchemeRoles ON (ClassSchemeRoles.Name = ClassSchemes.DefaultClassUserRole OR ClassSchemeRoles.Name = ClassSchemes.DefaultClassAdminRole)").
		Where(sq.Eq{"HigherScopedSchemes.Scope": model.SCHEME_SCOPE_BRANCH}).
		Where(sq.Eq{"HigherScopedRoles.Name": roleName}).
		Where(sq.Eq{"HigherScopedRoles.DeleteAt": 0}).
		Where(sq.Eq{"HigherScopedSchemes.DeleteAt": 0}).
		Where(sq.Eq{"Branches.DeleteAt": 0}).
		Where(sq.Eq{"Classes.DeleteAt": 0}).
		Where(sq.Eq{"ClassSchemes.DeleteAt": 0}).
		Where(sq.Eq{"ClassSchemeRoles.DeleteAt": 0})

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlRoleStore.ClassRolesUnderBranchRole", "store.sql.build_query.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var dbRoles []*Role
	if _, err = s.GetReplica().Select(&dbRoles, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlRoleStore.ClassRolesUnderBranchRole", "store.sql_role.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var roles []*model.Role
	for _, dbRole := range dbRoles {
		roles = append(roles, dbRole.ToModel())
	}

	return roles, nil
}
