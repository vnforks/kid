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
	"github.com/vnforks/kid/v5/utils"
)

const (
	BRANCH_MEMBER_EXISTS_ERROR = "store.sql_branch.save_member.exists.app_error"
)

type SqlBranchStore struct {
	SqlStore
}

type branchMember struct {
	BranchId    string
	UserId      string
	Roles       string
	DeleteAt    int64
	SchemeUser  sql.NullBool
	SchemeAdmin sql.NullBool
}

func NewBranchMemberFromModel(tm *model.BranchMember) *branchMember {
	return &branchMember{
		BranchId:    tm.BranchId,
		UserId:      tm.UserId,
		Roles:       tm.ExplicitRoles,
		DeleteAt:    tm.DeleteAt,
		SchemeUser:  sql.NullBool{Valid: true, Bool: tm.SchemeUser},
		SchemeAdmin: sql.NullBool{Valid: true, Bool: tm.SchemeAdmin},
	}
}

type branchMemberWithSchemeRoles struct {
	BranchId                     string
	UserId                       string
	Roles                        string
	DeleteAt                     int64
	SchemeUser                   sql.NullBool
	SchemeAdmin                  sql.NullBool
	BranchSchemeDefaultUserRole  sql.NullString
	BranchSchemeDefaultAdminRole sql.NullString
}

type branchMemberWithSchemeRolesList []branchMemberWithSchemeRoles

func branchMemberSliceColumns() []string {
	return []string{"BranchId", "UserId", "Roles", "DeleteAt", "SchemeUser", "SchemeAdmin"}
}

func branchMemberToSlice(member *model.BranchMember) []interface{} {
	resultSlice := []interface{}{}
	resultSlice = append(resultSlice, member.BranchId)
	resultSlice = append(resultSlice, member.UserId)
	resultSlice = append(resultSlice, member.ExplicitRoles)
	resultSlice = append(resultSlice, member.DeleteAt)
	resultSlice = append(resultSlice, member.SchemeUser)
	resultSlice = append(resultSlice, member.SchemeAdmin)
	return resultSlice
}

type rolesInfo struct {
	roles         []string
	explicitRoles []string
	schemeUser    bool
	schemeAdmin   bool
}

func getBranchRoles(schemeUser, schemeAdmin bool, defaultBranchUserRole, defaultBranchAdminRole string, roles []string) rolesInfo {
	result := rolesInfo{
		roles:         []string{},
		explicitRoles: []string{},
		schemeUser:    schemeUser,
		schemeAdmin:   schemeAdmin,
	}
	// Identify any scheme derived roles that are in "Roles" field due to not yet being migrated, and exclude
	// them from ExplicitRoles field.
	for _, role := range roles {
		switch role {
		case model.BRANCH_USER_ROLE_ID:
			result.schemeUser = true
		case model.BRANCH_ADMIN_ROLE_ID:
			result.schemeAdmin = true
		default:
			result.explicitRoles = append(result.explicitRoles, role)
			result.roles = append(result.roles, role)
		}
	}

	// Add any scheme derived roles that are not in the Roles field due to being Implicit from the Scheme, and add
	// them to the Roles field for backwards compatibility reasons.
	var schemeImpliedRoles []string
	if result.schemeUser {
		if defaultBranchUserRole != "" {
			schemeImpliedRoles = append(schemeImpliedRoles, defaultBranchUserRole)
		} else {
			schemeImpliedRoles = append(schemeImpliedRoles, model.BRANCH_USER_ROLE_ID)
		}
	}
	if result.schemeAdmin {
		if defaultBranchAdminRole != "" {
			schemeImpliedRoles = append(schemeImpliedRoles, defaultBranchAdminRole)
		} else {
			schemeImpliedRoles = append(schemeImpliedRoles, model.BRANCH_ADMIN_ROLE_ID)
		}
	}
	for _, impliedRole := range schemeImpliedRoles {
		alreadyThere := false
		for _, role := range result.roles {
			if role == impliedRole {
				alreadyThere = true
			}
		}
		if !alreadyThere {
			result.roles = append(result.roles, impliedRole)
		}
	}
	return result
}

func (db branchMemberWithSchemeRoles) ToModel() *model.BranchMember {
	// Identify any scheme derived roles that are in "Roles" field due to not yet being migrated, and exclude
	// them from ExplicitRoles field.
	schemeUser := db.SchemeUser.Valid && db.SchemeUser.Bool
	schemeAdmin := db.SchemeAdmin.Valid && db.SchemeAdmin.Bool

	defaultBranchUserRole := ""
	if db.BranchSchemeDefaultUserRole.Valid {
		defaultBranchUserRole = db.BranchSchemeDefaultUserRole.String
	}

	defaultBranchAdminRole := ""
	if db.BranchSchemeDefaultAdminRole.Valid {
		defaultBranchAdminRole = db.BranchSchemeDefaultAdminRole.String
	}

	rolesResult := getBranchRoles(schemeUser, schemeAdmin, defaultBranchUserRole, defaultBranchAdminRole, strings.Fields(db.Roles))

	tm := &model.BranchMember{
		BranchId:      db.BranchId,
		UserId:        db.UserId,
		Roles:         strings.Join(rolesResult.roles, " "),
		DeleteAt:      db.DeleteAt,
		SchemeUser:    rolesResult.schemeUser,
		SchemeAdmin:   rolesResult.schemeAdmin,
		ExplicitRoles: strings.Join(rolesResult.explicitRoles, " "),
	}
	return tm
}

func (db branchMemberWithSchemeRolesList) ToModel() []*model.BranchMember {
	tms := make([]*model.BranchMember, 0)

	for _, tm := range db {
		tms = append(tms, tm.ToModel())
	}

	return tms
}

func newSqlBranchStore(sqlStore SqlStore) store.BranchStore {
	s := &SqlBranchStore{
		sqlStore,
	}

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(model.Branch{}, "Branches").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("DisplayName").SetMaxSize(64)
		table.ColMap("Name").SetMaxSize(64).SetUnique(true)
		table.ColMap("Description").SetMaxSize(255)
		table.ColMap("Email").SetMaxSize(128)
		table.ColMap("SchoolId").SetMaxSize(32)

		tablem := db.AddTableWithName(branchMember{}, "BranchMembers").SetKeys(false, "BranchId", "UserId")
		tablem.ColMap("BranchId").SetMaxSize(26)
		tablem.ColMap("UserId").SetMaxSize(26)
		tablem.ColMap("Roles").SetMaxSize(64)
	}

	return s
}

func (s SqlBranchStore) createIndexesIfNotExists() {
	s.CreateIndexIfNotExists("idx_branches_name", "Branches", "Name")
	s.RemoveIndexIfExists("idx_branches_description", "Branches")
	s.CreateIndexIfNotExists("idx_branches_school_id", "Branches", "InviteId")
	s.CreateIndexIfNotExists("idx_branches_update_at", "Branches", "UpdateAt")
	s.CreateIndexIfNotExists("idx_branches_create_at", "Branches", "CreateAt")
	s.CreateIndexIfNotExists("idx_branches_delete_at", "Branches", "DeleteAt")
	s.CreateIndexIfNotExists("idx_branches_scheme_id", "Branches", "SchemeId")

	s.CreateIndexIfNotExists("idx_branchmembers_branch_id", "BranchMembers", "BranchId")
	s.CreateIndexIfNotExists("idx_branchmembers_user_id", "BranchMembers", "UserId")
	s.CreateIndexIfNotExists("idx_branchmembers_delete_at", "BranchMembers", "DeleteAt")
}

// Save adds the branch to the database if a branch with the same name does not already
// exist in the database. It returns the branch added if the operation is successful.
func (s SqlBranchStore) Save(branch *model.Branch) (*model.Branch, *model.AppError) {
	if len(branch.Id) > 0 {
		return nil, model.NewAppError("SqlBranchStore.Save",
			"store.sql_branch.save.existing.app_error", nil, "id="+branch.Id, http.StatusBadRequest)
	}

	branch.PreSave()

	if err := branch.IsValid(); err != nil {
		return nil, err
	}

	if err := s.GetMaster().Insert(branch); err != nil {
		if IsUniqueConstraintError(err, []string{"Name", "branches_name_key"}) {
			return nil, model.NewAppError("SqlBranchStore.Save", "store.sql_branch.save.domain_exists.app_error", nil, "id="+branch.Id+", "+err.Error(), http.StatusBadRequest)
		}
		return nil, model.NewAppError("SqlBranchStore.Save", "store.sql_branch.save.app_error", nil, "id="+branch.Id+", "+err.Error(), http.StatusInternalServerError)
	}
	return branch, nil
}

// Update updates the details of the branch passed as the parameter using the branch Id
// if the branch exists in the database.
// It returns the updated branch if the operation is successful.
func (s SqlBranchStore) Update(branch *model.Branch) (*model.Branch, *model.AppError) {

	branch.PreUpdate()

	if err := branch.IsValid(); err != nil {
		return nil, err
	}

	oldResult, err := s.GetMaster().Get(model.Branch{}, branch.Id)
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.Update", "store.sql_branch.update.finding.app_error", nil, "id="+branch.Id+", "+err.Error(), http.StatusInternalServerError)

	}

	if oldResult == nil {
		return nil, model.NewAppError("SqlBranchStore.Update", "store.sql_branch.update.find.app_error", nil, "id="+branch.Id, http.StatusBadRequest)
	}

	oldBranch := oldResult.(*model.Branch)
	branch.CreateAt = oldBranch.CreateAt
	branch.UpdateAt = model.GetMillis()

	count, err := s.GetMaster().Update(branch)
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.Update", "store.sql_branch.update.updating.app_error", nil, "id="+branch.Id+", "+err.Error(), http.StatusInternalServerError)
	}
	if count != 1 {
		return nil, model.NewAppError("SqlBranchStore.Update", "store.sql_branch.update.app_error", nil, "id="+branch.Id, http.StatusInternalServerError)
	}

	return branch, nil
}

func (s SqlBranchStore) Get(id string) (*model.Branch, *model.AppError) {
	obj, err := s.GetReplica().Get(model.Branch{}, id)
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.Get", "store.sql_branch.get.finding.app_error", nil, "id="+id+", "+err.Error(), http.StatusInternalServerError)
	}
	if obj == nil {
		return nil, model.NewAppError("SqlBranchStore.Get", "store.sql_branch.get.find.app_error", nil, "id="+id, http.StatusNotFound)
	}

	return obj.(*model.Branch), nil
}

func (s SqlBranchStore) GetBySchoolId(schoolId string) (*model.Branch, *model.AppError) {
	branch := model.Branch{}

	err := s.GetReplica().SelectOne(&branch, "SELECT * FROM Branches WHERE SchoolId = :SchoolId", map[string]interface{}{"SchoolId": schoolId})
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetBySchoolId", "store.sql_branch.get_by_invite_id.finding.app_error", nil, "schoolId="+schoolId+", "+err.Error(), http.StatusNotFound)
	}

	if len(schoolId) == 0 || branch.SchoolId != schoolId {
		return nil, model.NewAppError("SqlBranchStore.GetBySchoolId", "store.sql_branch.get_by_invite_id.find.app_error", nil, "schoolId="+schoolId, http.StatusNotFound)
	}
	return &branch, nil
}

func (s SqlBranchStore) GetByName(name string) (*model.Branch, *model.AppError) {

	branch := model.Branch{}

	err := s.GetReplica().SelectOne(&branch, "SELECT * FROM Branches WHERE Name = :Name", map[string]interface{}{"Name": name})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlBranchStore.GetByName", "store.sql_branch.get_by_name.missing.app_error", nil, "name="+name+","+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlBranchStore.GetByName", "store.sql_branch.get_by_name.app_error", nil, "name="+name+", "+err.Error(), http.StatusInternalServerError)
	}
	return &branch, nil
}

func (s SqlBranchStore) GetByNames(names []string) ([]*model.Branch, *model.AppError) {
	uniqueNames := utils.RemoveDuplicatesFromStringArray(names)

	query := s.getQueryBuilder().
		Select("*").
		From("Branches").
		Where(sq.Eq{"Name": uniqueNames})

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetByNames", "store.sql_branch.get_by_names.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	branches := []*model.Branch{}
	_, err = s.GetReplica().Select(&branches, queryString, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlBranchStore.GetByNames", "store.sql_branch.get_by_names.missing.app_error", nil, err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlBranchStore.GetByNames", "store.sql_branch.get_by_names.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	if len(branches) != len(uniqueNames) {
		return nil, model.NewAppError("SqlBranchStore.GetByNames", "store.sql_branch.get_by_names.missing.app_error", nil, "", http.StatusNotFound)
	}
	return branches, nil
}

func (s SqlBranchStore) GetAll() ([]*model.Branch, *model.AppError) {
	var branches []*model.Branch

	_, err := s.GetReplica().Select(&branches, "SELECT * FROM Branches ORDER BY DisplayName")
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetAllBranches", "store.sql_branch.get_all.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return branches, nil
}

func (s SqlBranchStore) GetAllPage(offset int, limit int) ([]*model.Branch, *model.AppError) {
	var branches []*model.Branch

	if _, err := s.GetReplica().Select(&branches,
		`SELECT
			*
		FROM
			Branches
		ORDER BY
			DisplayName
		LIMIT
			:Limit
		OFFSET
			:Offset`, map[string]interface{}{"Offset": offset, "Limit": limit}); err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetAllBranches",
			"store.sql_branch.get_all.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return branches, nil
}

func (s SqlBranchStore) GetBranchesByUserId(userId string) ([]*model.Branch, *model.AppError) {
	var branches []*model.Branch
	if _, err := s.GetReplica().Select(&branches, "SELECT Branches.* FROM Branches, BranchMembers WHERE BranchMembers.BranchId = Branches.Id AND BranchMembers.UserId = :UserId AND BranchMembers.DeleteAt = 0 AND Branches.DeleteAt = 0", map[string]interface{}{"UserId": userId}); err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetBranchesByUserId", "store.sql_branch.get_all.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return branches, nil
}

func (s SqlBranchStore) PermanentDelete(branchId string) *model.AppError {
	if _, err := s.GetMaster().Exec("DELETE FROM Branches WHERE Id = :BranchId", map[string]interface{}{"BranchId": branchId}); err != nil {
		return model.NewAppError("SqlBranchStore.Delete", "store.sql_branch.permanent_delete.app_error", nil, "branchId="+branchId+", "+err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (s SqlBranchStore) AnalyticsBranchCount(includeDeleted bool) (int64, *model.AppError) {
	query := s.getQueryBuilder().Select("COUNT(*) FROM Branches")
	if !includeDeleted {
		query = query.Where(sq.Eq{"DeleteAt": 0})
	}

	queryString, args, err := query.ToSql()
	if err != nil {
		return 0, model.NewAppError("SqlBranchStore.AnalyticsBranchCount", "store.sql_branch.analytics_branch_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	c, err := s.GetReplica().SelectInt(queryString, args...)

	if err != nil {
		return int64(0), model.NewAppError("SqlBranchStore.AnalyticsBranchCount", "store.sql_branch.analytics_branch_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return c, nil
}

func (s SqlBranchStore) getBranchMembersWithSchemeSelectQuery() sq.SelectBuilder {
	return s.getQueryBuilder().
		Select(
			"BranchMembers.*",
			"BranchScheme.DefaultBranchUserRole BranchSchemeDefaultUserRole",
			"BranchScheme.DefaultBranchAdminRole BranchSchemeDefaultAdminRole",
		).
		From("BranchMembers").
		LeftJoin("Branches ON BranchMembers.BranchId = Branches.Id").
		LeftJoin("Schemes BranchScheme ON Branches.SchemeId = BranchScheme.Id")
}

func (s SqlBranchStore) SaveMultipleMembers(members []*model.BranchMember, maxUsersPerBranch int) ([]*model.BranchMember, *model.AppError) {
	newBranchMembers := map[string]int{}
	users := map[string]bool{}
	for _, member := range members {
		newBranchMembers[member.BranchId] = 0
	}

	for _, member := range members {
		newBranchMembers[member.BranchId]++
		users[member.UserId] = true

		if err := member.IsValid(); err != nil {
			return nil, err
		}
	}

	branches := []string{}
	for branch := range newBranchMembers {
		branches = append(branches, branch)
	}

	defaultBranchRolesByBranch := map[string]struct {
		Id    string
		User  sql.NullString
		Admin sql.NullString
	}{}

	queryRoles := s.getQueryBuilder().
		Select(
			"Branches.Id as Id",
			"BranchScheme.DefaultBranchUserRole as User",
			"BranchScheme.DefaultBranchAdminRole as Admin",
		).
		From("Branches").
		LeftJoin("Schemes BranchScheme ON Branches.SchemeId = BranchScheme.Id").
		Where(sq.Eq{"Branches.Id": branches})

	sqlRolesQuery, argsRoles, err := queryRoles.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.member_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	var defaultBranchesRoles []struct {
		Id    string
		User  sql.NullString
		Admin sql.NullString
	}
	_, err = s.GetMaster().Select(&defaultBranchesRoles, sqlRolesQuery, argsRoles...)
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.member_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, defaultRoles := range defaultBranchesRoles {
		defaultBranchRolesByBranch[defaultRoles.Id] = defaultRoles
	}

	if maxUsersPerBranch >= 0 {
		queryCount := s.getQueryBuilder().
			Select(
				"COUNT(0) as Count, BranchMembers.BranchId as BranchId",
			).
			From("BranchMembers").
			Join("Users ON BranchMembers.UserId = Users.Id").
			Where(sq.Eq{"BranchMembers.BranchId": branches}).
			Where(sq.Eq{"BranchMembers.DeleteAt": 0}).
			Where(sq.Eq{"Users.DeleteAt": 0}).
			GroupBy("BranchMembers.BranchId")

		sqlCountQuery, argsCount, errCount := queryCount.ToSql()
		if errCount != nil {
			return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.member_count.app_error", nil, errCount.Error(), http.StatusInternalServerError)
		}

		var counters []struct {
			Count    int    `db:"Count"`
			BranchId string `db:"BranchId"`
		}

		_, err = s.GetMaster().Select(&counters, sqlCountQuery, argsCount...)
		if err != nil {
			return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.member_count.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		for branchId, newMembers := range newBranchMembers {
			existingMembers := 0
			for _, counter := range counters {
				if counter.BranchId == branchId {
					existingMembers = counter.Count
				}
			}
			if existingMembers+newMembers > maxUsersPerBranch {
				return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.max_accounts.app_error", nil, "", http.StatusBadRequest)
			}
		}
	}

	query := s.getQueryBuilder().Insert("BranchMembers").Columns(branchMemberSliceColumns()...)
	for _, member := range members {
		query = query.Values(branchMemberToSlice(member)...)
	}

	sql, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.SaveMember", "store.sql_branch.save_member.save.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	if _, err := s.GetMaster().Exec(sql, args...); err != nil {
		if IsUniqueConstraintError(err, []string{"BranchId", "branchmembers_pkey", "PRIMARY"}) {
			return nil, model.NewAppError("SqlBranchStore.SaveMember", BRANCH_MEMBER_EXISTS_ERROR, nil, err.Error(), http.StatusBadRequest)
		}
		return nil, model.NewAppError("SqlBranchStore.SaveMember", "store.sql_branch.save_member.save.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	newMembers := []*model.BranchMember{}
	for _, member := range members {
		s.InvalidateAllBranchIdsForUser(member.UserId)
		defaultBranchUserRole := defaultBranchRolesByBranch[member.BranchId].User.String
		defaultBranchAdminRole := defaultBranchRolesByBranch[member.BranchId].Admin.String
		rolesResult := getBranchRoles(member.SchemeUser, member.SchemeAdmin, defaultBranchUserRole, defaultBranchAdminRole, strings.Fields(member.ExplicitRoles))
		newMember := *member
		newMember.SchemeUser = rolesResult.schemeUser
		newMember.SchemeAdmin = rolesResult.schemeAdmin
		newMember.Roles = strings.Join(rolesResult.roles, " ")
		newMember.ExplicitRoles = strings.Join(rolesResult.explicitRoles, " ")
		newMembers = append(newMembers, &newMember)
	}

	return newMembers, nil
}

func (s SqlBranchStore) SaveMember(member *model.BranchMember, maxUsersPerBranch int) (*model.BranchMember, *model.AppError) {
	members, err := s.SaveMultipleMembers([]*model.BranchMember{member}, maxUsersPerBranch)
	if err != nil {
		return nil, err
	}
	return members[0], nil
}

func (s SqlBranchStore) UpdateMultipleMembers(members []*model.BranchMember) ([]*model.BranchMember, *model.AppError) {
	branches := []string{}
	for _, member := range members {
		member.PreUpdate()

		if err := member.IsValid(); err != nil {
			return nil, err
		}

		if _, err := s.GetMaster().Update(NewBranchMemberFromModel(member)); err != nil {
			return nil, model.NewAppError("SqlBranchStore.UpdateMember", "store.sql_branch.save_member.save.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
		branches = append(branches, member.BranchId)
	}

	query := s.getQueryBuilder().
		Select(
			"Branches.Id as Id",
			"BranchScheme.DefaultBranchUserRole as User",
			"BranchScheme.DefaultBranchAdminRole as Admin",
		).
		From("Branches").
		LeftJoin("Schemes BranchScheme ON Branches.SchemeId = BranchScheme.Id").
		Where(sq.Eq{"Branches.Id": branches})

	sqlQuery, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.member_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	var defaultBranchesRoles []struct {
		Id    string
		User  sql.NullString
		Admin sql.NullString
	}
	_, err = s.GetMaster().Select(&defaultBranchesRoles, sqlQuery, args...)
	if err != nil {
		return nil, model.NewAppError("SqlUserStore.Save", "store.sql_user.save.member_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	defaultBranchRolesByBranch := map[string]struct {
		Id    string
		User  sql.NullString
		Admin sql.NullString
	}{}
	for _, defaultRoles := range defaultBranchesRoles {
		defaultBranchRolesByBranch[defaultRoles.Id] = defaultRoles
	}

	updatedMembers := []*model.BranchMember{}
	for _, member := range members {
		s.InvalidateAllBranchIdsForUser(member.UserId)
		defaultBranchUserRole := defaultBranchRolesByBranch[member.BranchId].User.String
		defaultBranchAdminRole := defaultBranchRolesByBranch[member.BranchId].Admin.String
		rolesResult := getBranchRoles(member.SchemeUser, member.SchemeAdmin, defaultBranchUserRole, defaultBranchAdminRole, strings.Fields(member.ExplicitRoles))
		updatedMember := *member
		updatedMember.SchemeUser = rolesResult.schemeUser
		updatedMember.SchemeAdmin = rolesResult.schemeAdmin
		updatedMember.Roles = strings.Join(rolesResult.roles, " ")
		updatedMember.ExplicitRoles = strings.Join(rolesResult.explicitRoles, " ")
		updatedMembers = append(updatedMembers, &updatedMember)
	}

	return updatedMembers, nil
}

func (s SqlBranchStore) UpdateMember(member *model.BranchMember) (*model.BranchMember, *model.AppError) {
	members, err := s.UpdateMultipleMembers([]*model.BranchMember{member})
	if err != nil {
		return nil, err
	}
	return members[0], nil
}

func (s SqlBranchStore) GetMember(branchId string, userId string) (*model.BranchMember, *model.AppError) {
	query := s.getBranchMembersWithSchemeSelectQuery().
		Where(sq.Eq{"BranchMembers.BranchId": branchId}).
		Where(sq.Eq{"BranchMembers.UserId": userId})

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetMember", "store.sql_branch.get_member.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var dbMember branchMemberWithSchemeRoles
	err = s.GetReplica().SelectOne(&dbMember, queryString, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlBranchStore.GetMember", "store.sql_branch.get_member.missing.app_error", nil, "branchId="+branchId+" userId="+userId+" "+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlBranchStore.GetMember", "store.sql_branch.get_member.app_error", nil, "branchId="+branchId+" userId="+userId+" "+err.Error(), http.StatusInternalServerError)
	}

	return dbMember.ToModel(), nil
}

func (s SqlBranchStore) GetMembers(branchId string, offset int, limit int, branchMembersGetOptions *model.BranchMembersGetOptions) ([]*model.BranchMember, *model.AppError) {
	query := s.getBranchMembersWithSchemeSelectQuery().
		Where(sq.Eq{"BranchMembers.BranchId": branchId}).
		Where(sq.Eq{"BranchMembers.DeleteAt": 0}).
		Limit(uint64(limit)).
		Offset(uint64(offset))

	if branchMembersGetOptions == nil || branchMembersGetOptions.Sort == "" {
		query = query.OrderBy("UserId")
	}

	if branchMembersGetOptions != nil {
		if branchMembersGetOptions.Sort == model.USERNAME || branchMembersGetOptions.ExcludeDeletedUsers {
			query = query.LeftJoin("Users ON BranchMembers.UserId = Users.Id")
		}

		if branchMembersGetOptions.ExcludeDeletedUsers {
			query = query.Where(sq.Eq{"Users.DeleteAt": 0})
		}

		if branchMembersGetOptions.Sort == model.USERNAME {
			query = query.OrderBy(model.USERNAME)
		}

		query = applyBranchMemberViewRestrictionsFilter(query, branchId, branchMembersGetOptions.ViewRestrictions)
	}

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetMembers", "store.sql_branch.get_members.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var dbMembers branchMemberWithSchemeRolesList
	_, err = s.GetReplica().Select(&dbMembers, queryString, args...)
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetMembers", "store.sql_branch.get_members.app_error", nil, "branchId="+branchId+" "+err.Error(), http.StatusInternalServerError)
	}

	return dbMembers.ToModel(), nil
}

func (s SqlBranchStore) GetTotalMemberCount(branchId string, restrictions *model.ViewUsersRestrictions) (int64, *model.AppError) {
	query := s.getQueryBuilder().
		Select("count(DISTINCT BranchMembers.UserId)").
		From("BranchMembers, Users").
		Where("BranchMembers.DeleteAt = 0").
		Where("BranchMembers.UserId = Users.Id").
		Where(sq.Eq{"BranchMembers.BranchId": branchId})

	query = applyBranchMemberViewRestrictionsFilterForStats(query, branchId, restrictions)
	queryString, args, err := query.ToSql()
	if err != nil {
		return int64(0), model.NewAppError("SqlBranchStore.GetTotalMemberCount", "store.sql_branch.get_member_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	count, err := s.GetReplica().SelectInt(queryString, args...)
	if err != nil {
		return int64(0), model.NewAppError("SqlBranchStore.GetTotalMemberCount", "store.sql_branch.get_member_count.app_error", nil, "branchId="+branchId+" "+err.Error(), http.StatusInternalServerError)
	}
	return count, nil
}

func (s SqlBranchStore) GetActiveMemberCount(branchId string, restrictions *model.ViewUsersRestrictions) (int64, *model.AppError) {
	query := s.getQueryBuilder().
		Select("count(DISTINCT BranchMembers.UserId)").
		From("BranchMembers, Users").
		Where("BranchMembers.DeleteAt = 0").
		Where("BranchMembers.UserId = Users.Id").
		Where("Users.DeleteAt = 0").
		Where(sq.Eq{"BranchMembers.BranchId": branchId})

	query = applyBranchMemberViewRestrictionsFilterForStats(query, branchId, restrictions)
	queryString, args, err := query.ToSql()
	if err != nil {
		return 0, model.NewAppError("SqlBranchStore.GetActiveMemberCount", "store.sql_branch.get_active_member_count.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	count, err := s.GetReplica().SelectInt(queryString, args...)
	if err != nil {
		return 0, model.NewAppError("SqlBranchStore.GetActiveMemberCount", "store.sql_branch.get_active_member_count.app_error", nil, "branchId="+branchId+" "+err.Error(), http.StatusInternalServerError)
	}

	return count, nil
}

func (s SqlBranchStore) GetMembersByIds(branchId string, userIds []string, restrictions *model.ViewUsersRestrictions) ([]*model.BranchMember, *model.AppError) {
	if len(userIds) == 0 {
		return nil, model.NewAppError("SqlBranchStore.GetMembersByIds", "store.sql_branch.get_members_by_ids.app_error", nil, "Invalid list of user ids", http.StatusInternalServerError)
	}

	query := s.getBranchMembersWithSchemeSelectQuery().
		Where(sq.Eq{"BranchMembers.BranchId": branchId}).
		Where(sq.Eq{"BranchMembers.UserId": userIds}).
		Where(sq.Eq{"BranchMembers.DeleteAt": 0})

	query = applyBranchMemberViewRestrictionsFilter(query, branchId, restrictions)

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetMembersByIds", "store.sql_branch.get_members_by_ids.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var dbMembers branchMemberWithSchemeRolesList
	if _, err := s.GetReplica().Select(&dbMembers, queryString, args...); err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetMembersByIds", "store.sql_branch.get_members_by_ids.app_error", nil, "branchId="+branchId+" "+err.Error(), http.StatusInternalServerError)
	}
	return dbMembers.ToModel(), nil
}

func (s SqlBranchStore) GetBranchesForUser(userId string) ([]*model.BranchMember, *model.AppError) {
	query := s.getBranchMembersWithSchemeSelectQuery().
		Where(sq.Eq{"BranchMembers.UserId": userId})

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetMembers", "store.sql_branch.get_members.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var dbMembers branchMemberWithSchemeRolesList
	_, err = s.GetReplica().Select(&dbMembers, queryString, args...)
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetMembers", "store.sql_branch.get_members.app_error", nil, "userId="+userId+" "+err.Error(), http.StatusInternalServerError)
	}

	return dbMembers.ToModel(), nil
}

func (s SqlBranchStore) GetBranchesForUserWithPagination(userId string, page, perPage int) ([]*model.BranchMember, *model.AppError) {
	query := s.getBranchMembersWithSchemeSelectQuery().
		Where(sq.Eq{"BranchMembers.UserId": userId}).
		Limit(uint64(perPage)).
		Offset(uint64(page * perPage))

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetBranchesForUserWithPagination", "store.sql_branch.get_members.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var dbMembers branchMemberWithSchemeRolesList
	_, err = s.GetReplica().Select(&dbMembers, queryString, args...)
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetBranchesForUserWithPagination", "store.sql_branch.get_members.app_error", nil, "userId="+userId+" "+err.Error(), http.StatusInternalServerError)
	}

	return dbMembers.ToModel(), nil
}

func (s SqlBranchStore) RemoveMembers(branchId string, userIds []string) *model.AppError {
	query := s.getQueryBuilder().
		Delete("BranchMembers").
		Where(sq.Eq{"BranchId": branchId}).
		Where(sq.Eq{"UserId": userIds})

	sql, args, err := query.ToSql()
	if err != nil {
		return model.NewAppError("SqlBranchStore.RemoveMembers", "store.sql_branch.remove_member.app_error", nil, "branch_id="+branchId+", "+err.Error(), http.StatusInternalServerError)
	}
	_, err = s.GetMaster().Exec(sql, args...)
	if err != nil {
		return model.NewAppError("SqlBranchStore.RemoveMembers", "store.sql_branch.remove_member.app_error", nil, "branch_id="+branchId+", "+err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (s SqlBranchStore) RemoveMember(branchId string, userId string) *model.AppError {
	return s.RemoveMembers(branchId, []string{userId})
}

func (s SqlBranchStore) RemoveAllMembersByBranch(branchId string) *model.AppError {
	_, err := s.GetMaster().Exec("DELETE FROM BranchMembers WHERE BranchId = :BranchId", map[string]interface{}{"BranchId": branchId})
	if err != nil {
		return model.NewAppError("SqlBranchStore.RemoveMember", "store.sql_branch.remove_member.app_error", nil, "branch_id="+branchId+", "+err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (s SqlBranchStore) RemoveAllMembersByUser(userId string) *model.AppError {
	_, err := s.GetMaster().Exec("DELETE FROM BranchMembers WHERE UserId = :UserId", map[string]interface{}{"UserId": userId})
	if err != nil {
		return model.NewAppError("SqlBranchStore.RemoveMember", "store.sql_branch.remove_member.app_error", nil, "user_id="+userId+", "+err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (s SqlBranchStore) UpdateLastBranchIconUpdate(branchId string, curTime int64) *model.AppError {
	if _, err := s.GetMaster().Exec("UPDATE Branches SET LastBranchIconUpdate = :Time, UpdateAt = :Time WHERE Id = :branchId", map[string]interface{}{"Time": curTime, "branchId": branchId}); err != nil {
		return model.NewAppError("SqlBranchStore.UpdateLastBranchIconUpdate", "store.sql_branch.update_last_branch_icon_update.app_error", nil, "branch_id="+branchId, http.StatusInternalServerError)
	}
	return nil
}

func (s SqlBranchStore) GetBranchesByScheme(schemeId string, offset int, limit int) ([]*model.Branch, *model.AppError) {
	var branches []*model.Branch
	_, err := s.GetReplica().Select(&branches, "SELECT * FROM Branches WHERE SchemeId = :SchemeId ORDER BY DisplayName LIMIT :Limit OFFSET :Offset", map[string]interface{}{"SchemeId": schemeId, "Offset": offset, "Limit": limit})
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetBranchesByScheme", "store.sql_branch.get_by_scheme.app_error", nil, "schemeId="+schemeId+" "+err.Error(), http.StatusInternalServerError)
	}
	return branches, nil
}

// This function does the Advanced Permissions Phase 2 migration for BranchMember objects. It performs the migration
// in batches as a single transaction per batch to ensure consistency but to also minimise execution time to avoid
// causing unnecessary table locks. **THIS FUNCTION SHOULD NOT BE USED FOR ANY OTHER PURPOSE.** Executing this function
// *after* the new Schemes functionality has been used on an installation will have unintended consequences.
func (s SqlBranchStore) MigrateBranchMembers(fromBranchId string, fromUserId string) (map[string]string, *model.AppError) {
	var transaction *gorp.Transaction
	var err error

	if transaction, err = s.GetMaster().Begin(); err != nil {
		return nil, model.NewAppError("SqlBranchStore.MigrateBranchMembers", "store.sql_branch.migrate_branch_members.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	var branchMembers []branchMember
	if _, err := transaction.Select(&branchMembers, "SELECT * from BranchMembers WHERE (BranchId, UserId) > (:FromBranchId, :FromUserId) ORDER BY BranchId, UserId LIMIT 100", map[string]interface{}{"FromBranchId": fromBranchId, "FromUserId": fromUserId}); err != nil {
		return nil, model.NewAppError("SqlBranchStore.MigrateBranchMembers", "store.sql_branch.migrate_branch_members.select.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	if len(branchMembers) == 0 {
		// No more branch members in query result means that the migration has finished.
		return nil, nil
	}

	for i := range branchMembers {
		member := branchMembers[i]
		roles := strings.Fields(member.Roles)
		var newRoles []string
		if !member.SchemeAdmin.Valid {
			member.SchemeAdmin = sql.NullBool{Bool: false, Valid: true}
		}
		if !member.SchemeUser.Valid {
			member.SchemeUser = sql.NullBool{Bool: false, Valid: true}
		}
		for _, role := range roles {
			if role == model.BRANCH_ADMIN_ROLE_ID {
				member.SchemeAdmin = sql.NullBool{Bool: true, Valid: true}
			} else if role == model.BRANCH_USER_ROLE_ID {
				member.SchemeUser = sql.NullBool{Bool: true, Valid: true}
			} else {
				newRoles = append(newRoles, role)
			}
		}
		member.Roles = strings.Join(newRoles, " ")

		if _, err := transaction.Update(&member); err != nil {
			return nil, model.NewAppError("SqlBranchStore.MigrateBranchMembers", "store.sql_branch.migrate_branch_members.update.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

	}

	if err := transaction.Commit(); err != nil {
		return nil, model.NewAppError("SqlBranchStore.MigrateBranchMembers", "store.sql_branch.migrate_branch_members.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	data := make(map[string]string)
	data["BranchId"] = branchMembers[len(branchMembers)-1].BranchId
	data["UserId"] = branchMembers[len(branchMembers)-1].UserId

	return data, nil
}

func (s SqlBranchStore) ResetAllBranchSchemes() *model.AppError {
	if _, err := s.GetMaster().Exec("UPDATE Branches SET SchemeId=''"); err != nil {
		return model.NewAppError("SqlBranchStore.ResetAllBranchSchemes", "store.sql_branch.reset_all_branch_schemes.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (s SqlBranchStore) ClearCaches() {}

func (s SqlBranchStore) InvalidateAllBranchIdsForUser(userId string) {}

func (s SqlBranchStore) ClearAllCustomRoleAssignments() *model.AppError {

	builtInRoles := model.MakeDefaultRoles()
	lastUserId := strings.Repeat("0", 26)
	lastBranchId := strings.Repeat("0", 26)

	for {
		var transaction *gorp.Transaction
		var err error

		if transaction, err = s.GetMaster().Begin(); err != nil {
			return model.NewAppError("SqlBranchStore.ClearAllCustomRoleAssignments", "store.sql_branch.clear_all_custom_role_assignments.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
		defer finalizeTransaction(transaction)

		var branchMembers []*branchMember
		if _, err := transaction.Select(&branchMembers, "SELECT * from BranchMembers WHERE (BranchId, UserId) > (:BranchId, :UserId) ORDER BY BranchId, UserId LIMIT 1000", map[string]interface{}{"BranchId": lastBranchId, "UserId": lastUserId}); err != nil {
			return model.NewAppError("SqlBranchStore.ClearAllCustomRoleAssignments", "store.sql_branch.clear_all_custom_role_assignments.select.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		if len(branchMembers) == 0 {
			break
		}

		for _, member := range branchMembers {
			lastUserId = member.UserId
			lastBranchId = member.BranchId

			var newRoles []string

			for _, role := range strings.Fields(member.Roles) {
				for name := range builtInRoles {
					if name == role {
						newRoles = append(newRoles, role)
						break
					}
				}
			}

			newRolesString := strings.Join(newRoles, " ")
			if newRolesString != member.Roles {
				if _, err := transaction.Exec("UPDATE BranchMembers SET Roles = :Roles WHERE UserId = :UserId AND BranchId = :BranchId", map[string]interface{}{"Roles": newRolesString, "BranchId": member.BranchId, "UserId": member.UserId}); err != nil {
					return model.NewAppError("SqlBranchStore.ClearAllCustomRoleAssignments", "store.sql_branch.clear_all_custom_role_assignments.update.app_error", nil, err.Error(), http.StatusInternalServerError)
				}
			}
		}

		if err := transaction.Commit(); err != nil {
			return model.NewAppError("SqlBranchStore.ClearAllCustomRoleAssignments", "store.sql_branch.clear_all_custom_role_assignments.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
	}
	return nil
}

func (s SqlBranchStore) AnalyticsGetBranchCountForScheme(schemeId string) (int64, *model.AppError) {
	count, err := s.GetReplica().SelectInt("SELECT count(*) FROM Branches WHERE SchemeId = :SchemeId AND DeleteAt = 0", map[string]interface{}{"SchemeId": schemeId})
	if err != nil {
		return 0, model.NewAppError("SqlBranchStore.AnalyticsGetBranchCountForScheme", "store.sql_branch.analytics_get_branch_count_for_scheme.app_error", nil, "schemeId="+schemeId+" "+err.Error(), http.StatusInternalServerError)
	}

	return count, nil
}

func (s SqlBranchStore) GetAllForExportAfter(limit int, afterId string) ([]*model.BranchForExport, *model.AppError) {
	var data []*model.BranchForExport
	if _, err := s.GetReplica().Select(&data, `
		SELECT
			Branches.*,
			Schemes.Name as SchemeName
		FROM
			Branches
		LEFT JOIN
			Schemes ON Branches.SchemeId = Schemes.Id
		WHERE
			Branches.Id > :AfterId
		ORDER BY
			Id
		LIMIT
			:Limit`,
		map[string]interface{}{"AfterId": afterId, "Limit": limit}); err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetAllBranches", "store.sql_branch.get_all.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return data, nil
}

// GetUserBranchIds get the branch ids to which the user belongs to. allowFromCache parameter does not have any effect in this Store
func (s SqlBranchStore) GetUserBranchIds(userID string, allowFromCache bool) ([]string, *model.AppError) {
	var branchIds []string
	_, err := s.GetReplica().Select(&branchIds,
		`SELECT
			BranchId
		FROM
			BranchMembers
		INNER JOIN
			Branches ON BranchMembers.BranchId = Branches.Id
		WHERE
			BranchMembers.UserId = :UserId
			AND BranchMembers.DeleteAt = 0
			AND Branches.DeleteAt = 0`,
		map[string]interface{}{"UserId": userID})
	if err != nil {
		return []string{}, model.NewAppError("SqlBranchStore.GetUserBranchIds", "store.sql_branch.get_user_branch_ids.app_error", nil, "userID="+userID+" "+err.Error(), http.StatusInternalServerError)
	}

	return branchIds, nil
}

func (s SqlBranchStore) GetBranchMembersForExport(userId string) ([]*model.BranchMemberForExport, *model.AppError) {
	var members []*model.BranchMemberForExport
	_, err := s.GetReplica().Select(&members, `
		SELECT
			BranchMembers.BranchId,
			BranchMembers.UserId,
			BranchMembers.Roles,
			BranchMembers.DeleteAt,
			BranchMembers.SchemeUser,
			BranchMembers.SchemeAdmin,
			Branches.Name as BranchName
		FROM
			BranchMembers
		INNER JOIN
			Branches ON BranchMembers.BranchId = Branches.Id
		WHERE
			BranchMembers.UserId = :UserId
			AND Branches.DeleteAt = 0`,
		map[string]interface{}{"UserId": userId})
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.GetBranchMembersForExport", "store.sql_branch.get_members.app_error", nil, "userId="+userId+" "+err.Error(), http.StatusInternalServerError)
	}
	return members, nil
}

func (s SqlBranchStore) UserBelongsToBranches(userId string, branchIds []string) (bool, *model.AppError) {
	idQuery := sq.Eq{
		"UserId":   userId,
		"BranchId": branchIds,
		"DeleteAt": 0,
	}

	query, params, err := s.getQueryBuilder().Select("Count(*)").From("BranchMembers").Where(idQuery).ToSql()
	if err != nil {
		return false, model.NewAppError("SqlBranchStore.UserBelongsToBranches", "store.sql_branch.user_belongs_to_branches.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	c, err := s.GetReplica().SelectInt(query, params...)
	if err != nil {
		return false, model.NewAppError("SqlBranchStore.UserBelongsToBranches", "store.sql_branch.user_belongs_to_branches.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return c > 0, nil
}

func (s SqlBranchStore) UpdateMembersRole(branchID string, userIDs []string) *model.AppError {
	sql := fmt.Sprintf(`
		UPDATE
			BranchMembers
		SET
			SchemeAdmin = CASE WHEN UserId IN ('%s') THEN
				TRUE
			ELSE
				FALSE
			END
		WHERE
			BranchId = :BranchId
			AND DeleteAt = 0`, strings.Join(userIDs, "', '"))

	if _, err := s.GetMaster().Exec(sql, map[string]interface{}{"BranchId": branchID}); err != nil {
		return model.NewAppError("SqlBranchStore.UpdateMembersRole", "store.update_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func applyBranchMemberViewRestrictionsFilter(query sq.SelectBuilder, branchId string, restrictions *model.ViewUsersRestrictions) sq.SelectBuilder {
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

	resultQuery := query.Join("Users ru ON (BranchMembers.UserId = ru.Id)")
	if restrictions.Branches != nil && len(restrictions.Branches) > 0 {
		resultQuery = resultQuery.Join(fmt.Sprintf("BranchMembers rtm ON ( rtm.UserId = ru.Id AND rtm.DeleteAt = 0 AND rtm.BranchId IN (%s))", sq.Placeholders(len(branches))), branches...)
	}
	if restrictions.Classes != nil && len(restrictions.Classes) > 0 {
		resultQuery = resultQuery.Join(fmt.Sprintf("ClassMembers rcm ON ( rcm.UserId = ru.Id AND rcm.ClassId IN (%s))", sq.Placeholders(len(classes))), classes...)
	}

	return resultQuery.Distinct()
}

func applyBranchMemberViewRestrictionsFilterForStats(query sq.SelectBuilder, branchId string, restrictions *model.ViewUsersRestrictions) sq.SelectBuilder {
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
		resultQuery = resultQuery.Join(fmt.Sprintf("BranchMembers rtm ON ( rtm.UserId = Users.Id AND rtm.DeleteAt = 0 AND rtm.BranchId IN (%s))", sq.Placeholders(len(branches))), branches...)
	}
	if restrictions.Classes != nil && len(restrictions.Classes) > 0 {
		resultQuery = resultQuery.Join(fmt.Sprintf("ClassMembers rcm ON ( rcm.UserId = Users.Id AND rcm.ClassId IN (%s))", sq.Placeholders(len(classes))), classes...)
	}

	return resultQuery
}
