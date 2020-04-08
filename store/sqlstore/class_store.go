// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package sqlstore

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/mattermost/gorp"

	sq "github.com/Masterminds/squirrel"
	"github.com/vnforks/kid/v5/einterfaces"
	"github.com/vnforks/kid/v5/mlog"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/services/cache/lru"
	"github.com/vnforks/kid/v5/store"
)

const (
	ALL_CLASS_MEMBERS_FOR_USER_CACHE_SIZE = model.SESSION_CACHE_SIZE
	ALL_CLASS_MEMBERS_FOR_USER_CACHE_SEC  = 900 // 15 mins

	ALL_CLASS_MEMBERS_NOTIFY_PROPS_FOR_CLASS_CACHE_SIZE = model.SESSION_CACHE_SIZE
	ALL_CLASS_MEMBERS_NOTIFY_PROPS_FOR_CLASS_CACHE_SEC  = 1800 // 30 mins

	CLASS_CACHE_SEC = 900 // 15 mins
)

type SqlClassStore struct {
	SqlStore
	metrics einterfaces.MetricsInterface
}

type classMember struct {
	ClassId      string
	UserId       string
	Roles        string
	NotifyProps  model.StringMap
	LastUpdateAt int64
	SchemeUser   sql.NullBool
	SchemeAdmin  sql.NullBool
}

func NewClassMemberFromModel(cm *model.ClassMember) *classMember {
	return &classMember{
		ClassId:      cm.ClassId,
		UserId:       cm.UserId,
		Roles:        cm.ExplicitRoles,
		NotifyProps:  cm.NotifyProps,
		LastUpdateAt: cm.LastUpdateAt,
		SchemeUser:   sql.NullBool{Valid: true, Bool: cm.SchemeUser},
		SchemeAdmin:  sql.NullBool{Valid: true, Bool: cm.SchemeAdmin},
	}
}

type classMemberWithSchemeRoles struct {
	ClassId                      string
	UserId                       string
	Roles                        string
	NotifyProps                  model.StringMap
	LastUpdateAt                 int64
	SchemeUser                   sql.NullBool
	SchemeAdmin                  sql.NullBool
	BranchSchemeDefaultUserRole  sql.NullString
	BranchSchemeDefaultAdminRole sql.NullString
	ClassSchemeDefaultUserRole   sql.NullString
	ClassSchemeDefaultAdminRole  sql.NullString
}

func classMemberSliceColumns() []string {
	return []string{"ClassId", "UserId", "Roles", "NotifyProps", "LastUpdateAt", "SchemeUser", "SchemeAdmin"}
}

func classMemberToSlice(member *model.ClassMember) []interface{} {
	resultSlice := []interface{}{}
	resultSlice = append(resultSlice, member.ClassId)
	resultSlice = append(resultSlice, member.UserId)
	resultSlice = append(resultSlice, member.ExplicitRoles)
	resultSlice = append(resultSlice, model.MapToJson(member.NotifyProps))
	resultSlice = append(resultSlice, member.LastUpdateAt)
	resultSlice = append(resultSlice, member.SchemeUser)
	resultSlice = append(resultSlice, member.SchemeAdmin)
	return resultSlice
}

type classMemberWithSchemeRolesList []classMemberWithSchemeRoles

func getClassRoles(schemeUser, schemeAdmin bool, defaultBranchUserRole, defaultBranchAdminRole, defaultClassUserRole, defaultClassAdminRole string, roles []string) rolesInfo {
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
		case model.CLASS_USER_ROLE_ID:
			result.schemeUser = true
		case model.CLASS_ADMIN_ROLE_ID:
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
		if defaultClassUserRole != "" {
			schemeImpliedRoles = append(schemeImpliedRoles, defaultClassUserRole)
		} else {
			schemeImpliedRoles = append(schemeImpliedRoles, model.CLASS_USER_ROLE_ID)
		}
	}
	if result.schemeAdmin {
		if defaultClassAdminRole != "" {
			schemeImpliedRoles = append(schemeImpliedRoles, defaultClassAdminRole)
		} else {
			schemeImpliedRoles = append(schemeImpliedRoles, model.CLASS_ADMIN_ROLE_ID)
		}
	}
	for _, impliedRole := range schemeImpliedRoles {
		alreadyThere := false
		for _, role := range result.roles {
			if role == impliedRole {
				alreadyThere = true
				break
			}
		}
		if !alreadyThere {
			result.roles = append(result.roles, impliedRole)
		}
	}
	return result
}

func (db classMemberWithSchemeRoles) ToModel() *model.ClassMember {
	// Identify any system-wide scheme derived roles that are in "Roles" field due to not yet being migrated,
	// and exclude them from ExplicitRoles field.
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

	defaultClassUserRole := ""
	if db.ClassSchemeDefaultUserRole.Valid {
		defaultClassUserRole = db.ClassSchemeDefaultUserRole.String
	}

	defaultClassAdminRole := ""
	if db.ClassSchemeDefaultAdminRole.Valid {
		defaultClassAdminRole = db.ClassSchemeDefaultAdminRole.String
	}

	rolesResult := getClassRoles(
		schemeUser, schemeAdmin,
		defaultBranchUserRole, defaultBranchAdminRole,
		defaultClassUserRole, defaultClassAdminRole,
		strings.Fields(db.Roles),
	)
	return &model.ClassMember{
		ClassId:       db.ClassId,
		UserId:        db.UserId,
		Roles:         strings.Join(rolesResult.roles, " "),
		NotifyProps:   db.NotifyProps,
		LastUpdateAt:  db.LastUpdateAt,
		SchemeAdmin:   rolesResult.schemeAdmin,
		SchemeUser:    rolesResult.schemeUser,
		ExplicitRoles: strings.Join(rolesResult.explicitRoles, " "),
	}
}

func (db classMemberWithSchemeRolesList) ToModel() *model.ClassMembers {
	cms := model.ClassMembers{}

	for _, cm := range db {
		cms = append(cms, *cm.ToModel())
	}

	return &cms
}

type allClassMember struct {
	ClassId                      string
	Roles                        string
	SchemeUser                   sql.NullBool
	SchemeAdmin                  sql.NullBool
	BranchSchemeDefaultUserRole  sql.NullString
	BranchSchemeDefaultAdminRole sql.NullString
	ClassSchemeDefaultUserRole   sql.NullString
	ClassSchemeDefaultAdminRole  sql.NullString
}

type allClassMembers []allClassMember

func (db allClassMember) Process() (string, string) {
	roles := strings.Fields(db.Roles)

	// Add any scheme derived roles that are not in the Roles field due to being Implicit from the Scheme, and add
	// them to the Roles field for backwards compatibility reasons.
	var schemeImpliedRoles []string

	if db.SchemeUser.Valid && db.SchemeUser.Bool {
		if db.ClassSchemeDefaultUserRole.Valid && db.ClassSchemeDefaultUserRole.String != "" {
			schemeImpliedRoles = append(schemeImpliedRoles, db.ClassSchemeDefaultUserRole.String)
		} else {
			schemeImpliedRoles = append(schemeImpliedRoles, model.CLASS_USER_ROLE_ID)
		}
	}
	if db.SchemeAdmin.Valid && db.SchemeAdmin.Bool {
		if db.ClassSchemeDefaultAdminRole.Valid && db.ClassSchemeDefaultAdminRole.String != "" {
			schemeImpliedRoles = append(schemeImpliedRoles, db.ClassSchemeDefaultAdminRole.String)
		} else {
			schemeImpliedRoles = append(schemeImpliedRoles, model.CLASS_ADMIN_ROLE_ID)
		}
	}
	for _, impliedRole := range schemeImpliedRoles {
		alreadyThere := false
		for _, role := range roles {
			if role == impliedRole {
				alreadyThere = true
			}
		}
		if !alreadyThere {
			roles = append(roles, impliedRole)
		}
	}

	return db.ClassId, strings.Join(roles, " ")
}

func (db allClassMembers) ToMapStringString() map[string]string {
	result := make(map[string]string)

	for _, item := range db {
		key, value := item.Process()
		result[key] = value
	}

	return result
}

var allClassMembersForUserCache = lru.New(ALL_CLASS_MEMBERS_FOR_USER_CACHE_SIZE)
var allClassMembersNotifyPropsForClassCache = lru.New(ALL_CLASS_MEMBERS_NOTIFY_PROPS_FOR_CLASS_CACHE_SIZE)
var classByNameCache = lru.New(model.CLASS_CACHE_SIZE)

func (s SqlClassStore) ClearCaches() {
	allClassMembersForUserCache.Purge()
	allClassMembersNotifyPropsForClassCache.Purge()
	classByNameCache.Purge()

	if s.metrics != nil {
		s.metrics.IncrementMemCacheInvalidationCounter("All Class Members for User - Purge")
		s.metrics.IncrementMemCacheInvalidationCounter("All Class Members Notify Props for Class - Purge")
		s.metrics.IncrementMemCacheInvalidationCounter("Class By Name - Purge")
	}
}

func newSqlClassStore(sqlStore SqlStore, metrics einterfaces.MetricsInterface) store.ClassStore {
	s := &SqlClassStore{
		SqlStore: sqlStore,
		metrics:  metrics,
	}

	for _, db := range sqlStore.GetAllConns() {
		table := db.AddTableWithName(model.Class{}, "Classes").SetKeys(false, "Id")
		table.ColMap("Id").SetMaxSize(26)
		table.ColMap("BranchId").SetMaxSize(26)
		table.ColMap("DisplayName").SetMaxSize(64)
		table.ColMap("Name").SetMaxSize(64)
		table.SetUniqueTogether("Name", "BranchId")
		table.ColMap("Header").SetMaxSize(1024)
		table.ColMap("Purpose").SetMaxSize(250)
		table.ColMap("CreatorId").SetMaxSize(26)
		table.ColMap("SchemeId").SetMaxSize(26)

		tablem := db.AddTableWithName(classMember{}, "ClassMembers").SetKeys(false, "ClassId", "UserId")
		tablem.ColMap("ClassId").SetMaxSize(26)
		tablem.ColMap("UserId").SetMaxSize(26)
		tablem.ColMap("Roles").SetMaxSize(64)
		tablem.ColMap("NotifyProps").SetMaxSize(2000)

	}

	return s
}

func (s SqlClassStore) createIndexesIfNotExists() {
	s.CreateIndexIfNotExists("idx_classes_branch_id", "Classes", "BranchId")
	s.CreateIndexIfNotExists("idx_classes_name", "Classes", "Name")
	s.CreateIndexIfNotExists("idx_classes_update_at", "Classes", "UpdateAt")
	s.CreateIndexIfNotExists("idx_classes_create_at", "Classes", "CreateAt")
	s.CreateIndexIfNotExists("idx_classes_delete_at", "Classes", "DeleteAt")

	if s.DriverName() == model.DATABASE_DRIVER_POSTGRES {
		s.CreateIndexIfNotExists("idx_classes_name_lower", "Classes", "lower(Name)")
		s.CreateIndexIfNotExists("idx_classes_displayname_lower", "Classes", "lower(DisplayName)")
	}

	s.CreateIndexIfNotExists("idx_classmembers_class_id", "ClassMembers", "ClassId")
	s.CreateIndexIfNotExists("idx_classmembers_user_id", "ClassMembers", "UserId")

	s.CreateFullTextIndexIfNotExists("idx_class_search_txt", "Classes", "Name, DisplayName, Purpose")

	s.CreateIndexIfNotExists("idx_classes_scheme_id", "Classes", "SchemeId")
}

// Save writes the (non-direct) class class to the database.
func (s SqlClassStore) Save(class *model.Class, maxClassesPerBranch int64) (*model.Class, *model.AppError) {

	if class.DeleteAt != 0 {
		return nil, model.NewAppError("SqlClassStore.Save", "store.sql_class.save.archived_class.app_error", nil, "", http.StatusBadRequest)
	}

	transaction, err := s.GetMaster().Begin()
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.Save", "store.sql_class.save.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	newClass, appErr := s.saveClassT(transaction, class, maxClassesPerBranch)
	if appErr != nil {
		return newClass, appErr
	}

	if err := transaction.Commit(); err != nil {
		return nil, model.NewAppError("SqlClassStore.Save", "store.sql_class.save.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return newClass, nil
}

func (s SqlClassStore) CreateDirectClass(user *model.User, otherUser *model.User) (*model.Class, *model.AppError) {
	class := new(model.Class)

	class.DisplayName = ""
	class.Name = model.GetDMNameFromIds(otherUser.Id, user.Id)

	class.Header = ""

	cm1 := &model.ClassMember{
		UserId:      user.Id,
		NotifyProps: model.GetDefaultClassNotifyProps(),
	}
	cm2 := &model.ClassMember{
		UserId:      otherUser.Id,
		NotifyProps: model.GetDefaultClassNotifyProps(),
	}

	return s.SaveDirectClass(class, cm1, cm2)
}

func (s SqlClassStore) SaveDirectClass(directclass *model.Class, member1 *model.ClassMember, member2 *model.ClassMember) (*model.Class, *model.AppError) {
	if directclass.DeleteAt != 0 {
		return nil, model.NewAppError("SqlClassStore.Save", "store.sql_class.save.archived_class.app_error", nil, "", http.StatusBadRequest)
	}
	transaction, err := s.GetMaster().Begin()
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.SaveDirectClass", "store.sql_class.save_direct_class.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	directclass.BranchId = ""
	newClass, appErr := s.saveClassT(transaction, directclass, 0)
	if appErr != nil {
		return newClass, appErr
	}

	// Members need new class ID
	member1.ClassId = newClass.Id
	member2.ClassId = newClass.Id

	var memberSaveErr *model.AppError
	if member1.UserId != member2.UserId {
		_, memberSaveErr = s.saveMultipleMembersT(transaction, []*model.ClassMember{member1, member2})
	} else {
		_, memberSaveErr = s.saveMemberT(transaction, member2)
	}

	if memberSaveErr != nil {
		return nil, model.NewAppError("SqlClassStore.SaveDirectClass", "store.sql_class.save_direct_class.add_members.app_error", nil, memberSaveErr.Error(), http.StatusInternalServerError)
	}

	if err := transaction.Commit(); err != nil {
		return nil, model.NewAppError("SqlClassStore.SaveDirectClass", "store.sql_class.save_direct_class.commit.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return newClass, nil

}

func (s SqlClassStore) saveClassT(transaction *gorp.Transaction, class *model.Class, maxClassesPerBranch int64) (*model.Class, *model.AppError) {
	if len(class.Id) > 0 {
		return nil, model.NewAppError("SqlClassStore.Save", "store.sql_class.save_class.existing.app_error", nil, "id="+class.Id, http.StatusBadRequest)
	}

	class.PreSave()
	if err := class.IsValid(); err != nil {
		return nil, err
	}

	if maxClassesPerBranch >= 0 {
		if count, err := transaction.SelectInt("SELECT COUNT(0) FROM Classes WHERE BranchId = :BranchId AND DeleteAt = 0 ", map[string]interface{}{"BranchId": class.BranchId}); err != nil {
			return nil, model.NewAppError("SqlClassStore.Save", "store.sql_class.save_class.current_count.app_error", nil, "branchId="+class.BranchId+", "+err.Error(), http.StatusInternalServerError)
		} else if count >= maxClassesPerBranch {
			return nil, model.NewAppError("SqlClassStore.Save", "store.sql_class.save_class.limit.app_error", nil, "branchId="+class.BranchId, http.StatusBadRequest)
		}
	}

	if err := transaction.Insert(class); err != nil {
		if IsUniqueConstraintError(err, []string{"Name", "classes_name_branchid_key"}) {
			dupClass := model.Class{}
			s.GetMaster().SelectOne(&dupClass, "SELECT * FROM Classes WHERE BranchId = :BranchId AND Name = :Name", map[string]interface{}{"BranchId": class.BranchId, "Name": class.Name})
			return &dupClass, model.NewAppError("SqlClassStore.Save", store.CLASS_EXISTS_ERROR, nil, "id="+class.Id+", "+err.Error(), http.StatusBadRequest)
		}
		return nil, model.NewAppError("SqlClassStore.Save", "store.sql_class.save_class.save.app_error", nil, "id="+class.Id+", "+err.Error(), http.StatusInternalServerError)
	}
	return class, nil
}

// Update writes the updated class to the database.
func (s SqlClassStore) Update(class *model.Class) (*model.Class, *model.AppError) {
	transaction, err := s.GetMaster().Begin()
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.Update", "store.sql_class.update.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	updatedClass, appErr := s.updateClassT(transaction, class)
	if appErr != nil {
		return nil, appErr
	}

	if err := transaction.Commit(); err != nil {
		return nil, model.NewAppError("SqlClassStore.Update", "store.sql_class.update.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return updatedClass, nil
}

func (s SqlClassStore) updateClassT(transaction *gorp.Transaction, class *model.Class) (*model.Class, *model.AppError) {
	class.PreUpdate()

	if class.DeleteAt != 0 {
		return nil, model.NewAppError("SqlClassStore.Update", "store.sql_class.update.archived_class.app_error", nil, "", http.StatusBadRequest)
	}

	if err := class.IsValid(); err != nil {
		return nil, err
	}

	count, err := transaction.Update(class)
	if err != nil {
		if IsUniqueConstraintError(err, []string{"Name", "classes_name_branchid_key"}) {
			dupClass := model.Class{}
			s.GetReplica().SelectOne(&dupClass, "SELECT * FROM Classes WHERE BranchId = :BranchId AND Name= :Name AND DeleteAt > 0", map[string]interface{}{"BranchId": class.BranchId, "Name": class.Name})
			if dupClass.DeleteAt > 0 {
				return nil, model.NewAppError("SqlClassStore.Update", "store.sql_class.update.previously.app_error", nil, "id="+class.Id+", "+err.Error(), http.StatusBadRequest)
			}
			return nil, model.NewAppError("SqlClassStore.Update", "store.sql_class.update.exists.app_error", nil, "id="+class.Id+", "+err.Error(), http.StatusBadRequest)
		}
		return nil, model.NewAppError("SqlClassStore.Update", "store.sql_class.update.updating.app_error", nil, "id="+class.Id+", "+err.Error(), http.StatusInternalServerError)
	}

	if count != 1 {
		return nil, model.NewAppError("SqlClassStore.Update", "store.sql_class.update.app_error", nil, "id="+class.Id, http.StatusInternalServerError)
	}

	return class, nil
}

func (s SqlClassStore) InvalidateClass(id string) {
}

func (s SqlClassStore) InvalidateClassByName(branchId, name string) {
	classByNameCache.Remove(branchId + name)
	if s.metrics != nil {
		s.metrics.IncrementMemCacheInvalidationCounter("Class by Name - Remove by BranchId and Name")
	}
}

func (s SqlClassStore) Get(id string, allowFromCache bool) (*model.Class, *model.AppError) {
	return s.get(id, false, allowFromCache)
}
func (s SqlClassStore) GetFromMaster(id string) (*model.Class, *model.AppError) {
	return s.get(id, true, false)
}

func (s SqlClassStore) get(id string, master bool, allowFromCache bool) (*model.Class, *model.AppError) {
	var db *gorp.DbMap

	if master {
		db = s.GetMaster()
	} else {
		db = s.GetReplica()
	}

	obj, err := db.Get(model.Class{}, id)
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.Get", "store.sql_class.get.find.app_error", nil, "id="+id+", "+err.Error(), http.StatusInternalServerError)
	}

	if obj == nil {
		return nil, model.NewAppError("SqlClassStore.Get", "store.sql_class.get.existing.app_error", nil, "id="+id, http.StatusNotFound)
	}

	ch := obj.(*model.Class)
	return ch, nil
}

// Delete records the given deleted timestamp to the class in question.
func (s SqlClassStore) Delete(classId string, time int64) *model.AppError {
	return s.SetDeleteAt(classId, time, time)
}

// Restore reverts a previous deleted timestamp from the class in question.
func (s SqlClassStore) Restore(classId string, time int64) *model.AppError {
	return s.SetDeleteAt(classId, 0, time)
}

// SetDeleteAt records the given deleted and updated timestamp to the class in question.
func (s SqlClassStore) SetDeleteAt(classId string, deleteAt, updateAt int64) *model.AppError {
	defer s.InvalidateClass(classId)

	transaction, err := s.GetMaster().Begin()
	if err != nil {
		return model.NewAppError("SqlClassStore.SetDeleteAt", "store.sql_class.set_delete_at.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	appErr := s.setDeleteAtT(transaction, classId, deleteAt, updateAt)
	if appErr != nil {
		return appErr
	}

	if err := transaction.Commit(); err != nil {
		return model.NewAppError("SqlClassStore.SetDeleteAt", "store.sql_class.set_delete_at.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s SqlClassStore) setDeleteAtT(transaction *gorp.Transaction, classId string, deleteAt, updateAt int64) *model.AppError {
	_, err := transaction.Exec("Update Classes SET DeleteAt = :DeleteAt, UpdateAt = :UpdateAt WHERE Id = :ClassId", map[string]interface{}{"DeleteAt": deleteAt, "UpdateAt": updateAt, "ClassId": classId})
	if err != nil {
		return model.NewAppError("SqlClassStore.Delete", "store.sql_class.delete.class.app_error", nil, "id="+classId+", err="+err.Error(), http.StatusInternalServerError)
	}

	return nil
}

// PermanentDeleteByBranch removes all classes for the given branch from the database.
func (s SqlClassStore) PermanentDeleteByBranch(branchId string) *model.AppError {
	transaction, err := s.GetMaster().Begin()
	if err != nil {
		return model.NewAppError("SqlClassStore.PermanentDeleteByBranch", "store.sql_class.permanent_delete_by_branch.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	if err := s.permanentDeleteByBranchtT(transaction, branchId); err != nil {
		return err
	}

	if err := transaction.Commit(); err != nil {
		return model.NewAppError("SqlClassStore.PermanentDeleteByBranch", "store.sql_class.permanent_delete_by_branch.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s SqlClassStore) permanentDeleteByBranchtT(transaction *gorp.Transaction, branchId string) *model.AppError {
	if _, err := transaction.Exec("DELETE FROM Classes WHERE BranchId = :BranchId", map[string]interface{}{"BranchId": branchId}); err != nil {
		return model.NewAppError("SqlClassStore.PermanentDeleteByBranch", "store.sql_class.permanent_delete_by_branch.app_error", nil, "branchId="+branchId+", "+err.Error(), http.StatusInternalServerError)
	}

	return nil
}

// PermanentDelete removes the given class from the database.
func (s SqlClassStore) PermanentDelete(classId string) *model.AppError {
	transaction, err := s.GetMaster().Begin()
	if err != nil {
		return model.NewAppError("SqlClassStore.PermanentDelete", "store.sql_class.permanent_delete.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	if err := s.permanentDeleteT(transaction, classId); err != nil {
		return err
	}

	if err := transaction.Commit(); err != nil {
		return model.NewAppError("SqlClassStore.PermanentDelete", "store.sql_class.permanent_delete.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s SqlClassStore) permanentDeleteT(transaction *gorp.Transaction, classId string) *model.AppError {
	if _, err := transaction.Exec("DELETE FROM Classes WHERE Id = :ClassId", map[string]interface{}{"ClassId": classId}); err != nil {
		return model.NewAppError("SqlClassStore.PermanentDelete", "store.sql_class.permanent_delete.app_error", nil, "class_id="+classId+", "+err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s SqlClassStore) PermanentDeleteMembersByClass(classId string) *model.AppError {
	_, err := s.GetMaster().Exec("DELETE FROM ClassMembers WHERE ClassId = :ClassId", map[string]interface{}{"ClassId": classId})
	if err != nil {
		return model.NewAppError("SqlClassStore.RemoveAllMembersByClass", "store.sql_class.remove_member.app_error", nil, "class_id="+classId+", "+err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s SqlClassStore) GetClasses(branchId string, userId string, includeDeleted bool) (*model.ClassList, *model.AppError) {
	query := "SELECT Classes.* FROM Classes, ClassMembers WHERE Id = ClassId AND UserId = :UserId AND DeleteAt = 0 AND (BranchId = :BranchId OR BranchId = '') ORDER BY DisplayName"
	if includeDeleted {
		query = "SELECT Classes.* FROM Classes, ClassMembers WHERE Id = ClassId AND UserId = :UserId AND (BranchId = :BranchId OR BranchId = '') ORDER BY DisplayName"
	}
	classes := &model.ClassList{}
	_, err := s.GetReplica().Select(classes, query, map[string]interface{}{"BranchId": branchId, "UserId": userId})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetClasses", "store.sql_class.get_classes.get.app_error", nil, "branchId="+branchId+", userId="+userId+", err="+err.Error(), http.StatusInternalServerError)
	}

	if len(*classes) == 0 {
		return nil, model.NewAppError("SqlClassStore.GetClasses", "store.sql_class.get_classes.not_found.app_error", nil, "branchId="+branchId+", userId="+userId, http.StatusBadRequest)
	}

	return classes, nil
}

func (s SqlClassStore) GetAllClasses(offset, limit int, opts store.ClassSearchOpts) (*model.ClassListWithBranchData, *model.AppError) {
	query := s.getAllClassesQuery(opts, false)

	query = query.OrderBy("c.DisplayName, Branches.DisplayName").Limit(uint64(limit)).Offset(uint64(offset))

	queryString, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetAllClasses", "store.sql.build_query.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	data := &model.ClassListWithBranchData{}
	_, err = s.GetReplica().Select(data, queryString, args...)

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetAllClasses", "store.sql_class.get_all_classes.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return data, nil
}

func (s SqlClassStore) GetAllClassesCount(opts store.ClassSearchOpts) (int64, *model.AppError) {
	query := s.getAllClassesQuery(opts, true)

	queryString, args, err := query.ToSql()
	if err != nil {
		return 0, model.NewAppError("SqlClassStore.GetAllClassesCount", "store.sql.build_query.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	count, err := s.GetReplica().SelectInt(queryString, args...)
	if err != nil {
		return 0, model.NewAppError("SqlClassStore.GetAllClassesCount", "store.sql_class.get_all_classes.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return count, nil
}

func (s SqlClassStore) getAllClassesQuery(opts store.ClassSearchOpts, forCount bool) sq.SelectBuilder {
	var selectStr string
	if forCount {
		selectStr = "count(c.Id)"
	} else {
		selectStr = "c.*, Branches.DisplayName AS BranchDisplayName, Branches.Name AS BranchName, Branches.UpdateAt AS BranchUpdateAt"
	}

	query := s.getQueryBuilder().
		Select(selectStr).
		From("Classes AS c")

	if !forCount {
		query = query.Join("Branches ON Branches.Id = c.BranchId")
	}

	if !opts.IncludeDeleted {
		query = query.Where(sq.Eq{"c.DeleteAt": int(0)})
	}

	if len(opts.ExcludeClassNames) > 0 {
		query = query.Where(sq.NotEq{"c.Name": opts.ExcludeClassNames})
	}

	return query
}

func (s SqlClassStore) GetMoreClasses(branchId string, userId string, offset int, limit int) (*model.ClassList, *model.AppError) {
	classes := &model.ClassList{}
	_, err := s.GetReplica().Select(classes, `
		SELECT
			c.*
		FROM
			Classes c
		WHERE
			c.BranchId = :BranchId
		AND c.DeleteAt = 0
		ORDER BY
			c.DisplayName
		LIMIT :Limit
		OFFSET :Offset
		`, map[string]interface{}{
		"BranchId": branchId,
		"UserId":   userId,
		"Limit":    limit,
		"Offset":   offset,
	})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetMoreClasses", "store.sql_class.get_more_classes.get.app_error", nil, "branchId="+branchId+", userId="+userId+", err="+err.Error(), http.StatusInternalServerError)
	}

	return classes, nil
}

func (s SqlClassStore) GetPublicClassesForBranch(branchId string, offset int, limit int) (*model.ClassList, *model.AppError) {
	classes := &model.ClassList{}
	_, err := s.GetReplica().Select(classes, `
		SELECT
			c.*
		FROM
			Classes c
		WHERE
			c.BranchId = :BranchId
		AND c.DeleteAt = 0
		ORDER BY c.DisplayName
		LIMIT :Limit
		OFFSET :Offset
		`, map[string]interface{}{
		"BranchId": branchId,
		"Limit":    limit,
		"Offset":   offset,
	})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetPublicClassesForBranch", "store.sql_class.get_public_classes.get.app_error", nil, "branchId="+branchId+", err="+err.Error(), http.StatusInternalServerError)
	}

	return classes, nil
}

type classIdWithCountAndUpdateAt struct {
	Id            string
	TotalMsgCount int64
	UpdateAt      int64
}

func (s SqlClassStore) GetBranchClasses(branchId string) (*model.ClassList, *model.AppError) {
	data := &model.ClassList{}
	_, err := s.GetReplica().Select(data, "SELECT * FROM Classes WHERE BranchId = :BranchId ORDER BY DisplayName", map[string]interface{}{"BranchId": branchId})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetBranchClasses", "store.sql_class.get_classes.get.app_error", nil, "branchId="+branchId+",  err="+err.Error(), http.StatusInternalServerError)
	}

	if len(*data) == 0 {
		return nil, model.NewAppError("SqlClassStore.GetBranchClasses", "store.sql_class.get_classes.not_found.app_error", nil, "branchId="+branchId, http.StatusNotFound)
	}

	return data, nil
}

func (s SqlClassStore) GetByName(branchId string, name string, allowFromCache bool) (*model.Class, *model.AppError) {
	return s.getByName(branchId, name, false, allowFromCache)
}

func (s SqlClassStore) GetByNames(branchId string, names []string, allowFromCache bool) ([]*model.Class, *model.AppError) {
	var classes []*model.Class

	if allowFromCache {
		var misses []string
		visited := make(map[string]struct{})
		for _, name := range names {
			if _, ok := visited[name]; ok {
				continue
			}
			visited[name] = struct{}{}
			if cacheItem, ok := classByNameCache.Get(branchId + name); ok {
				classes = append(classes, cacheItem.(*model.Class))
			} else {
				misses = append(misses, name)
			}
		}
		names = misses
	}

	if len(names) > 0 {
		props := map[string]interface{}{}
		var namePlaceholders []string
		for _, name := range names {
			key := fmt.Sprintf("Name%v", len(namePlaceholders))
			props[key] = name
			namePlaceholders = append(namePlaceholders, ":"+key)
		}

		var query string
		if branchId == "" {
			query = `SELECT * FROM Classes WHERE Name IN (` + strings.Join(namePlaceholders, ", ") + `) AND DeleteAt = 0`
		} else {
			props["BranchId"] = branchId
			query = `SELECT * FROM Classes WHERE Name IN (` + strings.Join(namePlaceholders, ", ") + `) AND BranchId = :BranchId AND DeleteAt = 0`
		}

		var dbClasses []*model.Class
		if _, err := s.GetReplica().Select(&dbClasses, query, props); err != nil && err != sql.ErrNoRows {
			return nil, model.NewAppError("SqlClassStore.GetByName", "store.sql_class.get_by_name.existing.app_error", nil, "branchId="+branchId+", "+err.Error(), http.StatusInternalServerError)
		}
		for _, class := range dbClasses {
			classByNameCache.AddWithExpiresInSecs(branchId+class.Name, class, CLASS_CACHE_SEC)
			classes = append(classes, class)
		}
		// Not all classes are in cache. Increment aggregate miss counter.
		if s.metrics != nil {
			s.metrics.IncrementMemCacheMissCounter("Class By Name - Aggregate")
		}
	} else {
		// All of the class names are in cache. Increment aggregate hit counter.
		if s.metrics != nil {
			s.metrics.IncrementMemCacheHitCounter("Class By Name - Aggregate")
		}
	}

	return classes, nil
}

func (s SqlClassStore) GetByNameIncludeDeleted(branchId string, name string, allowFromCache bool) (*model.Class, *model.AppError) {
	return s.getByName(branchId, name, true, allowFromCache)
}

func (s SqlClassStore) getByName(branchId string, name string, includeDeleted bool, allowFromCache bool) (*model.Class, *model.AppError) {
	var query string
	if includeDeleted {
		query = "SELECT * FROM Classes WHERE (BranchId = :BranchId OR BranchId = '') AND Name = :Name"
	} else {
		query = "SELECT * FROM Classes WHERE (BranchId = :BranchId OR BranchId = '') AND Name = :Name AND DeleteAt = 0"
	}
	class := model.Class{}

	if allowFromCache {
		if cacheItem, ok := classByNameCache.Get(branchId + name); ok {
			if s.metrics != nil {
				s.metrics.IncrementMemCacheHitCounter("Class By Name")
			}
			return cacheItem.(*model.Class), nil
		}
		if s.metrics != nil {
			s.metrics.IncrementMemCacheMissCounter("Class By Name")
		}
	}

	if err := s.GetReplica().SelectOne(&class, query, map[string]interface{}{"BranchId": branchId, "Name": name}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlClassStore.GetByName", store.MISSING_CLASS_ERROR, nil, "branchId="+branchId+", "+"name="+name+"", http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlClassStore.GetByName", "store.sql_class.get_by_name.existing.app_error", nil, "branchId="+branchId+", "+"name="+name+", "+err.Error(), http.StatusInternalServerError)
	}

	classByNameCache.AddWithExpiresInSecs(branchId+name, &class, CLASS_CACHE_SEC)
	return &class, nil
}

func (s SqlClassStore) GetDeletedByName(branchId string, name string) (*model.Class, *model.AppError) {
	class := model.Class{}

	if err := s.GetReplica().SelectOne(&class, "SELECT * FROM Classes WHERE (BranchId = :BranchId OR BranchId = '') AND Name = :Name AND DeleteAt != 0", map[string]interface{}{"BranchId": branchId, "Name": name}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlClassStore.GetDeletedByName", "store.sql_class.get_deleted_by_name.missing.app_error", nil, "branchId="+branchId+", "+"name="+name+", "+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlClassStore.GetDeletedByName", "store.sql_class.get_deleted_by_name.existing.app_error", nil, "branchId="+branchId+", "+"name="+name+", "+err.Error(), http.StatusInternalServerError)
	}

	return &class, nil
}

func (s SqlClassStore) GetDeleted(branchId string, offset int, limit int, userId string) (*model.ClassList, *model.AppError) {
	classes := &model.ClassList{}

	query := `
		SELECT * FROM Classes
		WHERE (BranchId = :BranchId OR BranchId = '')
		AND DeleteAt != 0
		UNION
			SELECT * FROM Classes
			WHERE (BranchId = :BranchId OR BranchId = '')
			AND DeleteAt != 0
			AND Id IN (SELECT ClassId FROM ClassMembers WHERE UserId = :UserId)
		ORDER BY DisplayName LIMIT :Limit OFFSET :Offset
	`

	if _, err := s.GetReplica().Select(classes, query, map[string]interface{}{"BranchId": branchId, "Limit": limit, "Offset": offset, "UserId": userId}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlClassStore.GetDeleted", "store.sql_class.get_deleted.missing.app_error", nil, "branchId="+branchId+", "+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlClassStore.GetDeleted", "store.sql_class.get_deleted.existing.app_error", nil, "branchId="+branchId+", "+err.Error(), http.StatusInternalServerError)
	}

	return classes, nil
}

var CLASS_MEMBERS_WITH_SCHEME_SELECT_QUERY = `
	SELECT
		ClassMembers.*,
		BranchScheme.DefaultClassUserRole BranchSchemeDefaultUserRole,
		BranchScheme.DefaultClassAdminRole BranchSchemeDefaultAdminRole,
		ClassScheme.DefaultClassUserRole ClassSchemeDefaultUserRole,
		ClassScheme.DefaultClassAdminRole ClassSchemeDefaultAdminRole
	FROM
		ClassMembers
	INNER JOIN
		Classes ON ClassMembers.ClassId = Classes.Id
	LEFT JOIN
		Schemes ClassScheme ON Classes.SchemeId = ClassScheme.Id
	LEFT JOIN
		Branches ON Classes.BranchId = Branches.Id
	LEFT JOIN
		Schemes BranchScheme ON Branches.SchemeId = BranchScheme.Id
`

func (s SqlClassStore) SaveMultipleMembers(members []*model.ClassMember) ([]*model.ClassMember, *model.AppError) {
	for _, member := range members {
		defer s.InvalidateAllClassMembersForUser(member.UserId)
	}

	transaction, err := s.GetMaster().Begin()
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.SaveMember", "store.sql_class.save_member.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	newMembers, appErr := s.saveMultipleMembersT(transaction, members)
	if appErr != nil {
		return nil, appErr
	}

	if err := transaction.Commit(); err != nil {
		return nil, model.NewAppError("SqlClassStore.SaveMember", "store.sql_class.save_member.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return newMembers, nil
}

func (s SqlClassStore) SaveMember(member *model.ClassMember) (*model.ClassMember, *model.AppError) {
	newMembers, appErr := s.SaveMultipleMembers([]*model.ClassMember{member})
	if appErr != nil {
		return nil, appErr
	}
	return newMembers[0], nil
}

func (s SqlClassStore) saveMultipleMembersT(transaction *gorp.Transaction, members []*model.ClassMember) ([]*model.ClassMember, *model.AppError) {
	newClassMembers := map[string]int{}
	users := map[string]bool{}
	for _, member := range members {
		if val, ok := newClassMembers[member.ClassId]; val < 1 || !ok {
			newClassMembers[member.ClassId] = 1
		} else {
			newClassMembers[member.ClassId]++
		}
		users[member.UserId] = true

		member.PreSave()
		if err := member.IsValid(); err != nil {
			return nil, err
		}
	}

	classes := []string{}
	for class := range newClassMembers {
		classes = append(classes, class)
	}

	defaultClassRolesByClass := map[string]struct {
		Id    string
		User  sql.NullString
		Admin sql.NullString
	}{}

	classRolesQuery := s.getQueryBuilder().
		Select(
			"Classes.Id as Id",
			"ClassScheme.DefaultClassUserRole as User",
			"ClassScheme.DefaultClassAdminRole as Admin",
		).
		From("Classes").
		LeftJoin("Schemes ClassScheme ON Classes.SchemeId = ClassScheme.Id").
		Where(sq.Eq{"Classes.Id": classes})

	classRolesSql, classRolesArgs, err := classRolesQuery.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.SaveMultipleMembers", "store.sql_class.save_multimple_members.class_roles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var defaultClassesRoles []struct {
		Id    string
		User  sql.NullString
		Admin sql.NullString
	}
	_, err = s.GetMaster().Select(&defaultClassesRoles, classRolesSql, classRolesArgs...)
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.SaveMultipleMembers", "store.sql_class.save_multimple_members.class_roles_query.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, defaultRoles := range defaultClassesRoles {
		defaultClassRolesByClass[defaultRoles.Id] = defaultRoles
	}

	defaultBranchRolesByClass := map[string]struct {
		Id    string
		User  sql.NullString
		Admin sql.NullString
	}{}

	branchRolesQuery := s.getQueryBuilder().
		Select(
			"Classes.Id as Id",
			"BranchScheme.DefaultClassUserRole as User",
			"BranchScheme.DefaultClassAdminRole as Admin",
		).
		From("Classes").
		LeftJoin("Branches ON Branches.Id = Classes.BranchId").
		LeftJoin("Schemes BranchScheme ON Branches.SchemeId = BranchScheme.Id").
		Where(sq.Eq{"Classes.Id": classes})

	branchRolesSql, branchRolesArgs, err := branchRolesQuery.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.SaveMultipleMembers", "store.sql_class.save_multimple_members.branch_roles.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	var defaultBranchesRoles []struct {
		Id    string
		User  sql.NullString
		Admin sql.NullString
	}
	_, err = s.GetMaster().Select(&defaultBranchesRoles, branchRolesSql, branchRolesArgs...)
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.SaveMultipleMembers", "store.sql_class.save_multimple_members.branch_roles_query.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	for _, defaultRoles := range defaultBranchesRoles {
		defaultBranchRolesByClass[defaultRoles.Id] = defaultRoles
	}

	query := s.getQueryBuilder().Insert("ClassMembers").Columns(classMemberSliceColumns()...)
	for _, member := range members {
		query = query.Values(classMemberToSlice(member)...)
	}

	sql, args, err := query.ToSql()
	if err != nil {
		return nil, model.NewAppError("SqlBranchStore.SaveMember", "store.sql_class.save_member.save.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	if _, err := s.GetMaster().Exec(sql, args...); err != nil {
		if IsUniqueConstraintError(err, []string{"ClassId", "classmembers_pkey", "PRIMARY"}) {
			return nil, model.NewAppError("SqlBranchStore.SaveMember", "store.sql_class.save_member.exists.app_error", nil, err.Error(), http.StatusBadRequest)
		}
		return nil, model.NewAppError("SqlBranchStore.SaveMember", "store.sql_class.save_member.save.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	newMembers := []*model.ClassMember{}
	for _, member := range members {
		defaultBranchUserRole := defaultBranchRolesByClass[member.ClassId].User.String
		defaultBranchAdminRole := defaultBranchRolesByClass[member.ClassId].Admin.String
		defaultClassUserRole := defaultClassRolesByClass[member.ClassId].User.String
		defaultClassAdminRole := defaultClassRolesByClass[member.ClassId].Admin.String
		rolesResult := getClassRoles(
			member.SchemeUser, member.SchemeAdmin,
			defaultBranchUserRole, defaultBranchAdminRole,
			defaultClassUserRole, defaultClassAdminRole,
			strings.Fields(member.ExplicitRoles),
		)
		newMember := *member
		newMember.SchemeUser = rolesResult.schemeUser
		newMember.SchemeAdmin = rolesResult.schemeAdmin
		newMember.Roles = strings.Join(rolesResult.roles, " ")
		newMember.ExplicitRoles = strings.Join(rolesResult.explicitRoles, " ")
		newMembers = append(newMembers, &newMember)
	}
	return newMembers, nil
}

func (s SqlClassStore) saveMemberT(transaction *gorp.Transaction, member *model.ClassMember) (*model.ClassMember, *model.AppError) {
	members, err := s.saveMultipleMembersT(transaction, []*model.ClassMember{member})
	if err != nil {
		return nil, err
	}
	return members[0], nil
}

func (s SqlClassStore) UpdateMultipleMembers(members []*model.ClassMember) ([]*model.ClassMember, *model.AppError) {
	for _, member := range members {
		member.PreUpdate()

		if err := member.IsValid(); err != nil {
			return nil, err
		}
	}

	var transaction *gorp.Transaction
	var err error

	if transaction, err = s.GetMaster().Begin(); err != nil {
		return nil, model.NewAppError("SqlClassStore.MigrateClassMembers", "store.sql_class.migrate_class_members.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	updatedMembers := []*model.ClassMember{}
	for _, member := range members {
		if _, err := transaction.Update(NewClassMemberFromModel(member)); err != nil {
			return nil, model.NewAppError("SqlClassStore.UpdateMember", "store.sql_class.update_member.app_error", nil, "class_id="+member.ClassId+", "+"user_id="+member.UserId+", "+err.Error(), http.StatusInternalServerError)
		}

		// TODO: Get this out of the transaction when is possible
		var dbMember classMemberWithSchemeRoles
		if err := transaction.SelectOne(&dbMember, CLASS_MEMBERS_WITH_SCHEME_SELECT_QUERY+"WHERE ClassMembers.ClassId = :ClassId AND ClassMembers.UserId = :UserId", map[string]interface{}{"ClassId": member.ClassId, "UserId": member.UserId}); err != nil {
			if err == sql.ErrNoRows {
				return nil, model.NewAppError("SqlClassStore.GetMember", store.MISSING_CLASS_MEMBER_ERROR, nil, "class_id="+member.ClassId+"user_id="+member.UserId+","+err.Error(), http.StatusNotFound)
			}
			return nil, model.NewAppError("SqlClassStore.GetMember", "store.sql_class.get_member.app_error", nil, "class_id="+member.ClassId+"user_id="+member.UserId+","+err.Error(), http.StatusInternalServerError)
		}
		updatedMembers = append(updatedMembers, dbMember.ToModel())
	}

	if err := transaction.Commit(); err != nil {
		return nil, model.NewAppError("SqlClassStore.MigrateClassMembers", "store.sql_class.migrate_class_members.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return updatedMembers, nil
}

func (s SqlClassStore) UpdateMember(member *model.ClassMember) (*model.ClassMember, *model.AppError) {
	updatedMembers, err := s.UpdateMultipleMembers([]*model.ClassMember{member})
	if err != nil {
		return nil, err
	}
	return updatedMembers[0], nil
}

func (s SqlClassStore) GetMembers(classId string, offset, limit int) (*model.ClassMembers, *model.AppError) {
	var dbMembers classMemberWithSchemeRolesList
	_, err := s.GetReplica().Select(&dbMembers, CLASS_MEMBERS_WITH_SCHEME_SELECT_QUERY+"WHERE ClassId = :ClassId LIMIT :Limit OFFSET :Offset", map[string]interface{}{"ClassId": classId, "Limit": limit, "Offset": offset})
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetMembers", "store.sql_class.get_members.app_error", nil, "class_id="+classId+","+err.Error(), http.StatusInternalServerError)
	}

	return dbMembers.ToModel(), nil
}

func (s SqlClassStore) GetClassMembersTimezones(classId string) ([]model.StringMap, *model.AppError) {
	var dbMembersTimezone []model.StringMap
	_, err := s.GetReplica().Select(&dbMembersTimezone, `
		SELECT
			Users.Timezone
		FROM
			ClassMembers
		LEFT JOIN
			Users  ON ClassMembers.UserId = Id
		WHERE ClassId = :ClassId
	`, map[string]interface{}{"ClassId": classId})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetClassMembersTimezones", "store.sql_class.get_members.app_error", nil, "class_id="+classId+","+err.Error(), http.StatusInternalServerError)
	}

	return dbMembersTimezone, nil
}

func (s SqlClassStore) GetMember(classId string, userId string) (*model.ClassMember, *model.AppError) {
	var dbMember classMemberWithSchemeRoles

	if err := s.GetReplica().SelectOne(&dbMember, CLASS_MEMBERS_WITH_SCHEME_SELECT_QUERY+"WHERE ClassMembers.ClassId = :ClassId AND ClassMembers.UserId = :UserId", map[string]interface{}{"ClassId": classId, "UserId": userId}); err != nil {
		if err == sql.ErrNoRows {
			return nil, model.NewAppError("SqlClassStore.GetMember", store.MISSING_CLASS_MEMBER_ERROR, nil, "class_id="+classId+"user_id="+userId+","+err.Error(), http.StatusNotFound)
		}
		return nil, model.NewAppError("SqlClassStore.GetMember", "store.sql_class.get_member.app_error", nil, "class_id="+classId+"user_id="+userId+","+err.Error(), http.StatusInternalServerError)
	}

	return dbMember.ToModel(), nil
}

func (s SqlClassStore) InvalidateAllClassMembersForUser(userId string) {
	allClassMembersForUserCache.Remove(userId)
	allClassMembersForUserCache.Remove(userId + "_deleted")
	if s.metrics != nil {
		s.metrics.IncrementMemCacheInvalidationCounter("All Class Members for User - Remove by UserId")
	}
}

func (s SqlClassStore) IsUserInClassUseCache(userId string, classId string) bool {
	if cacheItem, ok := allClassMembersForUserCache.Get(userId); ok {
		if s.metrics != nil {
			s.metrics.IncrementMemCacheHitCounter("All Class Members for User")
		}
		ids := cacheItem.(map[string]string)
		if _, ok := ids[classId]; ok {
			return true
		}
		return false
	}

	if s.metrics != nil {
		s.metrics.IncrementMemCacheMissCounter("All Class Members for User")
	}

	ids, err := s.GetAllClassMembersForUser(userId, true, false)
	if err != nil {
		mlog.Error("Error getting all class members for user", mlog.Err(err))
		return false
	}

	if _, ok := ids[classId]; ok {
		return true
	}

	return false
}

func (s SqlClassStore) GetMemberForPost(postId string, userId string) (*model.ClassMember, *model.AppError) {
	var dbMember classMemberWithSchemeRoles
	query := `
		SELECT
			ClassMembers.*,
			BranchScheme.DefaultClassUserRole BranchSchemeDefaultUserRole,
			BranchScheme.DefaultClassAdminRole BranchSchemeDefaultAdminRole,
			ClassScheme.DefaultClassUserRole ClassSchemeDefaultUserRole,
			ClassScheme.DefaultClassAdminRole ClassSchemeDefaultAdminRole
		FROM
			ClassMembers
		INNER JOIN
			Posts ON ClassMembers.ClassId = Posts.ClassId
		INNER JOIN
			Classes ON ClassMembers.ClassId = Classes.Id
		LEFT JOIN
			Schemes ClassScheme ON Classes.SchemeId = ClassScheme.Id
		LEFT JOIN
			Branches ON Classes.BranchId = Branches.Id
		LEFT JOIN
			Schemes BranchScheme ON Branches.SchemeId = BranchScheme.Id
		WHERE
			ClassMembers.UserId = :UserId
		AND
			Posts.Id = :PostId`
	if err := s.GetReplica().SelectOne(&dbMember, query, map[string]interface{}{"UserId": userId, "PostId": postId}); err != nil {
		return nil, model.NewAppError("SqlClassStore.GetMemberForPost", "store.sql_class.get_member_for_post.app_error", nil, "postId="+postId+", err="+err.Error(), http.StatusInternalServerError)
	}
	return dbMember.ToModel(), nil
}

func (s SqlClassStore) GetForPost(postId string) (*model.Class, *model.AppError) {
	class := &model.Class{}
	if err := s.GetReplica().SelectOne(
		class,
		`SELECT
			Classes.*
		FROM
		Classes,
			Posts
		WHERE
			Classes.Id = Posts.ClassId
			AND Posts.Id = :PostId`, map[string]interface{}{"PostId": postId}); err != nil {
		return nil, model.NewAppError("SqlClassStore.GetForPost", "store.sql_class.get_for_post.app_error", nil, "postId="+postId+", err="+err.Error(), http.StatusInternalServerError)

	}
	return class, nil
}

func (s SqlClassStore) GetAllClassMembersForUser(userId string, allowFromCache bool, includeDeleted bool) (map[string]string, *model.AppError) {
	cache_key := userId
	if includeDeleted {
		cache_key += "_deleted"
	}
	if allowFromCache {
		if cacheItem, ok := allClassMembersForUserCache.Get(cache_key); ok {
			if s.metrics != nil {
				s.metrics.IncrementMemCacheHitCounter("All Class Members for User")
			}
			ids := cacheItem.(map[string]string)
			return ids, nil
		}
	}

	if s.metrics != nil {
		s.metrics.IncrementMemCacheMissCounter("All Class Members for User")
	}

	var deletedClause string
	if !includeDeleted {
		deletedClause = "Classes.DeleteAt = 0 AND"
	}

	var data allClassMembers
	_, err := s.GetReplica().Select(&data, `
			SELECT
				ClassMembers.ClassId, ClassMembers.Roles,
				ClassMembers.SchemeUser, ClassMembers.SchemeAdmin,
				BranchScheme.DefaultClassUserRole BranchSchemeDefaultUserRole,
				BranchScheme.DefaultClassAdminRole BranchSchemeDefaultAdminRole,
				ClassScheme.DefaultClassUserRole ClassSchemeDefaultUserRole,
				ClassScheme.DefaultClassAdminRole ClassSchemeDefaultAdminRole
			FROM
				ClassMembers
			INNER JOIN
				Classes ON ClassMembers.ClassId = Classes.Id
			LEFT JOIN
				Schemes ClassScheme ON Classes.SchemeId = ClassScheme.Id
			LEFT JOIN
				Branches ON Classes.BranchId = Branches.Id
			LEFT JOIN
				Schemes BranchScheme ON Branches.SchemeId = BranchScheme.Id
			WHERE
				`+deletedClause+`
				ClassMembers.UserId = :UserId`, map[string]interface{}{"UserId": userId})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetAllClassMembersForUser", "store.sql_class.get_classes.get.app_error", nil, "userId="+userId+", err="+err.Error(), http.StatusInternalServerError)
	}

	ids := data.ToMapStringString()

	if allowFromCache {
		allClassMembersForUserCache.AddWithExpiresInSecs(cache_key, ids, ALL_CLASS_MEMBERS_FOR_USER_CACHE_SEC)
	}
	return ids, nil
}

func (s SqlClassStore) InvalidateCacheForClassMembersNotifyProps(classId string) {
	allClassMembersNotifyPropsForClassCache.Remove(classId)
	if s.metrics != nil {
		s.metrics.IncrementMemCacheInvalidationCounter("All Class Members Notify Props for Class - Remove by ClassId")
	}
}

type allClassMemberNotifyProps struct {
	UserId      string
	NotifyProps model.StringMap
}

func (s SqlClassStore) GetAllClassMembersNotifyPropsForClass(classId string, allowFromCache bool) (map[string]model.StringMap, *model.AppError) {
	if allowFromCache {
		if cacheItem, ok := allClassMembersNotifyPropsForClassCache.Get(classId); ok {
			if s.metrics != nil {
				s.metrics.IncrementMemCacheHitCounter("All Class Members Notify Props for Class")
			}
			return cacheItem.(map[string]model.StringMap), nil
		}
	}

	if s.metrics != nil {
		s.metrics.IncrementMemCacheMissCounter("All Class Members Notify Props for Class")
	}

	var data []allClassMemberNotifyProps
	_, err := s.GetReplica().Select(&data, `
		SELECT UserId, NotifyProps
		FROM ClassMembers
		WHERE ClassId = :ClassId`, map[string]interface{}{"ClassId": classId})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetAllClassMembersPropsForClass", "store.sql_class.get_members.app_error", nil, "classId="+classId+", err="+err.Error(), http.StatusInternalServerError)
	}

	props := make(map[string]model.StringMap)
	for i := range data {
		props[data[i].UserId] = data[i].NotifyProps
	}

	allClassMembersNotifyPropsForClassCache.AddWithExpiresInSecs(classId, props, ALL_CLASS_MEMBERS_NOTIFY_PROPS_FOR_CLASS_CACHE_SEC)

	return props, nil
}

func (s SqlClassStore) InvalidateMemberCount(classId string) {
}

func (s SqlClassStore) GetMemberCountFromCache(classId string) int64 {
	count, _ := s.GetMemberCount(classId, true)
	return count
}

func (s SqlClassStore) GetMemberCount(classId string, allowFromCache bool) (int64, *model.AppError) {
	count, err := s.GetReplica().SelectInt(`
		SELECT
			count(*)
		FROM
			ClassMembers,
			Users
		WHERE
			ClassMembers.UserId = Users.Id
			AND ClassMembers.ClassId = :ClassId
			AND Users.DeleteAt = 0`, map[string]interface{}{"ClassId": classId})
	if err != nil {
		return 0, model.NewAppError("SqlClassStore.GetMemberCount", "store.sql_class.get_member_count.app_error", nil, "class_id="+classId+", "+err.Error(), http.StatusInternalServerError)
	}

	return count, nil
}

func (s SqlClassStore) InvalidatePinnedPostCount(classId string) {
}
func (s SqlClassStore) InvalidateGuestCount(classId string) {
}

func (s SqlClassStore) RemoveMembers(classId string, userIds []string) *model.AppError {
	query := s.getQueryBuilder().
		Delete("ClassMembers").
		Where(sq.Eq{"ClassId": classId}).
		Where(sq.Eq{"UserId": userIds})
	sql, args, err := query.ToSql()
	if err != nil {
		return model.NewAppError("SqlClassStore.RemoveMember", "store.sql_class.remove_member.app_error", nil, "class_id="+classId+", "+err.Error(), http.StatusInternalServerError)
	}
	_, err = s.GetMaster().Exec(sql, args...)
	if err != nil {
		return model.NewAppError("SqlClassStore.RemoveMember", "store.sql_class.remove_member.app_error", nil, "class_id="+classId+", "+err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (s SqlClassStore) RemoveMember(classId string, userId string) *model.AppError {
	return s.RemoveMembers(classId, []string{userId})
}

func (s SqlClassStore) RemoveAllDeactivatedMembers(classId string) *model.AppError {
	query := `
		DELETE
		FROM
			ClassMembers
		WHERE
			UserId IN (
				SELECT
					Id
				FROM
					Users
				WHERE
					Users.DeleteAt != 0
			)
		AND
			ClassMembers.ClassId = :ClassId
	`

	_, err := s.GetMaster().Exec(query, map[string]interface{}{"ClassId": classId})
	if err != nil {
		return model.NewAppError("SqlClassStore.RemoveAllDeactivatedMembers", "store.sql_class.remove_all_deactivated_members.app_error", nil, "class_id="+classId+", "+err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (s SqlClassStore) PermanentDeleteMembersByUser(userId string) *model.AppError {
	if _, err := s.GetMaster().Exec("DELETE FROM ClassMembers WHERE UserId = :UserId", map[string]interface{}{"UserId": userId}); err != nil {
		return model.NewAppError("SqlClassStore.ClassPermanentDeleteMembersByUser", "store.sql_class.permanent_delete_members_by_user.app_error", nil, "user_id="+userId+", "+err.Error(), http.StatusInternalServerError)
	}
	return nil
}

func (s SqlClassStore) GetAll(branchId string) ([]*model.Class, *model.AppError) {
	var data []*model.Class
	_, err := s.GetReplica().Select(&data, "SELECT * FROM Classes WHERE BranchId = :BranchId ORDER BY Name", map[string]interface{}{"BranchId": branchId})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetAll", "store.sql_class.get_all.app_error", nil, "branchId="+branchId+", err="+err.Error(), http.StatusInternalServerError)
	}

	return data, nil
}

func (s SqlClassStore) GetClassesByIds(classIds []string, includeDeleted bool) ([]*model.Class, *model.AppError) {
	keys, params := MapStringsToQueryParams(classIds, "Class")
	query := `SELECT * FROM Classes WHERE Id IN ` + keys + ` ORDER BY Name`
	if !includeDeleted {
		query = `SELECT * FROM Classes WHERE DeleteAt=0 AND Id IN ` + keys + ` ORDER BY Name`
	}

	var classes []*model.Class
	_, err := s.GetReplica().Select(&classes, query, params)

	if err != nil {
		mlog.Error("Query error getting classes by ids", mlog.Err(err))
		return nil, model.NewAppError("SqlClassStore.GetClassesByIds", "store.sql_class.get_classes_by_ids.app_error", nil, "", http.StatusInternalServerError)
	}
	return classes, nil
}

func (s SqlClassStore) GetMembersForUser(branchId string, userId string) (*model.ClassMembers, *model.AppError) {
	var dbMembers classMemberWithSchemeRolesList
	_, err := s.GetReplica().Select(&dbMembers, CLASS_MEMBERS_WITH_SCHEME_SELECT_QUERY+"WHERE ClassMembers.UserId = :UserId AND (Branches.Id = :BranchId OR Branches.Id = '' OR Branches.Id IS NULL)", map[string]interface{}{"BranchId": branchId, "UserId": userId})
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetMembersForUser", "store.sql_class.get_members.app_error", nil, "branchId="+branchId+", userId="+userId+", err="+err.Error(), http.StatusInternalServerError)
	}

	return dbMembers.ToModel(), nil
}

func (s SqlClassStore) GetMembersForUserWithPagination(branchId, userId string, page, perPage int) (*model.ClassMembers, *model.AppError) {
	var dbMembers classMemberWithSchemeRolesList
	offset := page * perPage
	_, err := s.GetReplica().Select(&dbMembers, CLASS_MEMBERS_WITH_SCHEME_SELECT_QUERY+"WHERE ClassMembers.UserId = :UserId Limit :Limit Offset :Offset", map[string]interface{}{"BranchId": branchId, "UserId": userId, "Limit": perPage, "Offset": offset})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetMembersForUserWithPagination", "store.sql_class.get_members.app_error", nil, "branchId="+branchId+", userId="+userId+", err="+err.Error(), http.StatusInternalServerError)
	}

	return dbMembers.ToModel(), nil
}

func (s SqlClassStore) GetMembersByIds(classId string, userIds []string) (*model.ClassMembers, *model.AppError) {
	var dbMembers classMemberWithSchemeRolesList
	props := make(map[string]interface{})
	idQuery := ""

	for index, userId := range userIds {
		if len(idQuery) > 0 {
			idQuery += ", "
		}

		props["userId"+strconv.Itoa(index)] = userId
		idQuery += ":userId" + strconv.Itoa(index)
	}

	props["ClassId"] = classId

	if _, err := s.GetReplica().Select(&dbMembers, CLASS_MEMBERS_WITH_SCHEME_SELECT_QUERY+"WHERE ClassMembers.ClassId = :ClassId AND ClassMembers.UserId IN ("+idQuery+")", props); err != nil {
		return nil, model.NewAppError("SqlClassStore.GetMembersByIds", "store.sql_class.get_members_by_ids.app_error", nil, "classId="+classId+" "+err.Error(), http.StatusInternalServerError)
	}

	return dbMembers.ToModel(), nil
}

func (s SqlClassStore) GetClassesByScheme(schemeId string, offset int, limit int) (model.ClassList, *model.AppError) {
	var classes model.ClassList
	_, err := s.GetReplica().Select(&classes, "SELECT * FROM Classes WHERE SchemeId = :SchemeId ORDER BY DisplayName LIMIT :Limit OFFSET :Offset", map[string]interface{}{"SchemeId": schemeId, "Offset": offset, "Limit": limit})
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetClassesByScheme", "store.sql_class.get_by_scheme.app_error", nil, "schemeId="+schemeId+" "+err.Error(), http.StatusInternalServerError)
	}
	return classes, nil
}

// This function does the Advanced Permissions Phase 2 migration for ClassMember objects. It performs the migration
// in batches as a single transaction per batch to ensure consistency but to also minimise execution time to avoid
// causing unnecessary table locks. **THIS FUNCTION SHOULD NOT BE USED FOR ANY OTHER PURPOSE.** Executing this function
// *after* the new Schemes functionality has been used on an installation will have unintended consequences.
func (s SqlClassStore) MigrateClassMembers(fromClassId string, fromUserId string) (map[string]string, *model.AppError) {
	var transaction *gorp.Transaction
	var err error

	if transaction, err = s.GetMaster().Begin(); err != nil {
		return nil, model.NewAppError("SqlClassStore.MigrateClassMembers", "store.sql_class.migrate_class_members.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	var classMembers []classMember
	if _, err := transaction.Select(&classMembers, "SELECT * from ClassMembers WHERE (ClassId, UserId) > (:FromClassId, :FromUserId) ORDER BY ClassId, UserId LIMIT 100", map[string]interface{}{"FromClassId": fromClassId, "FromUserId": fromUserId}); err != nil {
		return nil, model.NewAppError("SqlClassStore.MigrateClassMembers", "store.sql_class.migrate_class_members.select.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	if len(classMembers) == 0 {
		// No more class members in query result means that the migration has finished.
		return nil, nil
	}

	for i := range classMembers {
		member := classMembers[i]
		roles := strings.Fields(member.Roles)
		var newRoles []string
		if !member.SchemeAdmin.Valid {
			member.SchemeAdmin = sql.NullBool{Bool: false, Valid: true}
		}
		if !member.SchemeUser.Valid {
			member.SchemeUser = sql.NullBool{Bool: false, Valid: true}
		}
		for _, role := range roles {
			if role == model.CLASS_ADMIN_ROLE_ID {
				member.SchemeAdmin = sql.NullBool{Bool: true, Valid: true}
			} else if role == model.CLASS_USER_ROLE_ID {
				member.SchemeUser = sql.NullBool{Bool: true, Valid: true}
			} else {
				newRoles = append(newRoles, role)
			}
		}
		member.Roles = strings.Join(newRoles, " ")

		if _, err := transaction.Update(&member); err != nil {
			return nil, model.NewAppError("SqlClassStore.MigrateClassMembers", "store.sql_class.migrate_class_members.update.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

	}

	if err := transaction.Commit(); err != nil {
		return nil, model.NewAppError("SqlClassStore.MigrateClassMembers", "store.sql_class.migrate_class_members.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	data := make(map[string]string)
	data["ClassId"] = classMembers[len(classMembers)-1].ClassId
	data["UserId"] = classMembers[len(classMembers)-1].UserId
	return data, nil
}

func (s SqlClassStore) ResetAllClassSchemes() *model.AppError {
	transaction, err := s.GetMaster().Begin()
	if err != nil {
		return model.NewAppError("SqlClassStore.ResetAllClassSchemes", "store.sql_class.reset_all_class_schemes.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	defer finalizeTransaction(transaction)

	resetErr := s.resetAllClassSchemesT(transaction)
	if resetErr != nil {
		return resetErr
	}

	if err := transaction.Commit(); err != nil {
		return model.NewAppError("SqlClassStore.ResetAllClassSchemes", "store.sql_class.reset_all_class_schemes.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s SqlClassStore) resetAllClassSchemesT(transaction *gorp.Transaction) *model.AppError {
	if _, err := transaction.Exec("UPDATE Classes SET SchemeId=''"); err != nil {
		return model.NewAppError("SqlClassStore.ResetAllClassSchemes", "store.sql_class.reset_all_class_schemes.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}

func (s SqlClassStore) ClearAllCustomRoleAssignments() *model.AppError {
	builtInRoles := model.MakeDefaultRoles()
	lastUserId := strings.Repeat("0", 26)
	lastClassId := strings.Repeat("0", 26)

	for {
		var transaction *gorp.Transaction
		var err error

		if transaction, err = s.GetMaster().Begin(); err != nil {
			return model.NewAppError("SqlClassStore.ClearAllCustomRoleAssignments", "store.sql_class.clear_all_custom_role_assignments.open_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		var classMembers []*classMember
		if _, err := transaction.Select(&classMembers, "SELECT * from ClassMembers WHERE (ClassId, UserId) > (:ClassId, :UserId) ORDER BY ClassId, UserId LIMIT 1000", map[string]interface{}{"ClassId": lastClassId, "UserId": lastUserId}); err != nil {
			finalizeTransaction(transaction)
			return model.NewAppError("SqlClassStore.ClearAllCustomRoleAssignments", "store.sql_class.clear_all_custom_role_assignments.select.app_error", nil, err.Error(), http.StatusInternalServerError)
		}

		if len(classMembers) == 0 {
			finalizeTransaction(transaction)
			break
		}

		for _, member := range classMembers {
			lastUserId = member.UserId
			lastClassId = member.ClassId

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
				if _, err := transaction.Exec("UPDATE ClassMembers SET Roles = :Roles WHERE UserId = :UserId AND ClassId = :ClassId", map[string]interface{}{"Roles": newRolesString, "ClassId": member.ClassId, "UserId": member.UserId}); err != nil {
					finalizeTransaction(transaction)
					return model.NewAppError("SqlClassStore.ClearAllCustomRoleAssignments", "store.sql_class.clear_all_custom_role_assignments.update.app_error", nil, err.Error(), http.StatusInternalServerError)
				}
			}
		}

		if err := transaction.Commit(); err != nil {
			finalizeTransaction(transaction)
			return model.NewAppError("SqlClassStore.ClearAllCustomRoleAssignments", "store.sql_class.clear_all_custom_role_assignments.commit_transaction.app_error", nil, err.Error(), http.StatusInternalServerError)
		}
	}

	return nil
}

func (s SqlClassStore) GetAllClassesForExportAfter(limit int, afterId string) ([]*model.ClassForExport, *model.AppError) {
	var classes []*model.ClassForExport
	if _, err := s.GetReplica().Select(&classes, `
		SELECT
			Classes.*,
			Branches.Name as BranchName,
			Schemes.Name as SchemeName
		FROM Classes
		INNER JOIN
			Branches ON Classes.BranchId = Branches.Id
		LEFT JOIN
			Schemes ON Classes.SchemeId = Schemes.Id
		WHERE
			Classes.Id > :AfterId
		ORDER BY
			Id
		LIMIT :Limit`,
		map[string]interface{}{"AfterId": afterId, "Limit": limit}); err != nil {
		return nil, model.NewAppError("SqlClassStore.GetAllClassesForExportAfter", "store.sql_class.get_all.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return classes, nil
}

func (s SqlClassStore) GetClassMembersForExport(userId string, branchId string) ([]*model.ClassMemberForExport, *model.AppError) {
	var members []*model.ClassMemberForExport
	_, err := s.GetReplica().Select(&members, `
		SELECT
			ClassMembers.ClassId,
			ClassMembers.UserId,
			ClassMembers.Roles,
			ClassMembers.NotifyProps,
			ClassMembers.LastUpdateAt,
			ClassMembers.SchemeUser,
			ClassMembers.SchemeAdmin,
			Classes.Name as ClassName
		FROM
			ClassMembers
		INNER JOIN
			Classes ON ClassMembers.ClassId = Classes.Id
		WHERE
			ClassMembers.UserId = :UserId
			AND Classes.BranchId = :BranchId
			AND Classes.DeleteAt = 0`,
		map[string]interface{}{"BranchId": branchId, "UserId": userId})

	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetClassMembersForExport", "store.sql_class.get_members.app_error", nil, "branchId="+branchId+", userId="+userId+", err="+err.Error(), http.StatusInternalServerError)
	}

	return members, nil
}

func (s SqlClassStore) GetClassesBatchForIndexing(startTime, endTime int64, limit int) ([]*model.Class, *model.AppError) {
	query :=
		`SELECT
			 *
		 FROM
			 Classes
		 WHERE
			 CreateAt >= :StartTime
		 AND
			 CreateAt < :EndTime
		 ORDER BY
			 CreateAt
		 LIMIT
			 :NumClasses`

	var classes []*model.Class
	_, err := s.GetSearchReplica().Select(&classes, query, map[string]interface{}{"StartTime": startTime, "EndTime": endTime, "NumClasses": limit})
	if err != nil {
		return nil, model.NewAppError("SqlClassStore.GetClassesBatchForIndexing", "store.sql_class.get_classes_batch_for_indexing.get.app_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return classes, nil
}

func (s SqlClassStore) UserBelongsToClasses(userId string, classIds []string) (bool, *model.AppError) {
	query := s.getQueryBuilder().
		Select("Count(*)").
		From("ClassMembers").
		Where(sq.And{
			sq.Eq{"UserId": userId},
			sq.Eq{"ClassId": classIds},
		})

	queryString, args, err := query.ToSql()
	if err != nil {
		return false, model.NewAppError("SqlClassStore.UserBelongsToClasses", "store.sql_class.user_belongs_to_classes.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	c, err := s.GetReplica().SelectInt(queryString, args...)
	if err != nil {
		return false, model.NewAppError("SqlClassStore.UserBelongsToClasses", "store.sql_class.user_belongs_to_classes.app_error", nil, err.Error(), http.StatusInternalServerError)
	}
	return c > 0, nil
}

func (s SqlClassStore) UpdateMembersRole(classID string, userIDs []string) *model.AppError {
	sql := fmt.Sprintf(`
		UPDATE
			ClassMembers
		SET
			SchemeAdmin = CASE WHEN UserId IN ('%s') THEN
				TRUE
			ELSE
				FALSE
			END
		WHERE
			ClassId = :ClassId
			`, strings.Join(userIDs, "', '"))

	if _, err := s.GetMaster().Exec(sql, map[string]interface{}{"ClassId": classID}); err != nil {
		return model.NewAppError("SqlClassStore.UpdateMembersRole", "store.update_error", nil, err.Error(), http.StatusInternalServerError)
	}

	return nil
}
