// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"net/http"

	"github.com/vnforks/kid/v5/model"
)

func (a *App) GetScheme(id string) (*model.Scheme, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	return a.Srv().Store.Scheme().Get(id)
}

func (a *App) GetSchemeByName(name string) (*model.Scheme, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	return a.Srv().Store.Scheme().GetByName(name)
}

func (a *App) GetSchemesPage(scope string, page int, perPage int) ([]*model.Scheme, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	return a.GetSchemes(scope, page*perPage, perPage)
}

func (a *App) GetSchemes(scope string, offset int, limit int) ([]*model.Scheme, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	return a.Srv().Store.Scheme().GetAllPage(scope, offset, limit)
}

func (a *App) CreateScheme(scheme *model.Scheme) (*model.Scheme, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	// Clear any user-provided values for trusted properties.
	scheme.DefaultBranchAdminRole = ""
	scheme.DefaultBranchUserRole = ""
	scheme.DefaultClassAdminRole = ""
	scheme.DefaultClassUserRole = ""
	scheme.CreateAt = 0
	scheme.UpdateAt = 0
	scheme.DeleteAt = 0

	return a.Srv().Store.Scheme().Save(scheme)
}

func (a *App) PatchScheme(scheme *model.Scheme, patch *model.SchemePatch) (*model.Scheme, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	scheme.Patch(patch)
	scheme, err := a.UpdateScheme(scheme)
	if err != nil {
		return nil, err
	}

	return scheme, err
}

func (a *App) UpdateScheme(scheme *model.Scheme) (*model.Scheme, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	return a.Srv().Store.Scheme().Save(scheme)
}

func (a *App) DeleteScheme(schemeId string) (*model.Scheme, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	return a.Srv().Store.Scheme().Delete(schemeId)
}

func (a *App) GetBranchesForSchemePage(scheme *model.Scheme, page int, perPage int) ([]*model.Branch, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	return a.GetBranchesForScheme(scheme, page*perPage, perPage)
}

func (a *App) GetBranchesForScheme(scheme *model.Scheme, offset int, limit int) ([]*model.Branch, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	branches, err := a.Srv().Store.Branch().GetBranchesByScheme(scheme.Id, offset, limit)
	if err != nil {
		return nil, err
	}
	return branches, nil
}

func (a *App) GetClassesForSchemePage(scheme *model.Scheme, page int, perPage int) (model.ClassList, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}

	return a.GetClassesForScheme(scheme, page*perPage, perPage)
}

func (a *App) GetClassesForScheme(scheme *model.Scheme, offset int, limit int) (model.ClassList, *model.AppError) {
	if err := a.IsPhase2MigrationCompleted(); err != nil {
		return nil, err
	}
	return a.Srv().Store.Class().GetClassesByScheme(scheme.Id, offset, limit)
}

func (a *App) IsPhase2MigrationCompleted() *model.AppError {
	if a.Srv().phase2PermissionsMigrationComplete {
		return nil
	}

	if _, err := a.Srv().Store.System().GetByName(model.MIGRATION_KEY_ADVANCED_PERMISSIONS_PHASE_2); err != nil {
		return model.NewAppError("App.IsPhase2MigrationCompleted", "app.schemes.is_phase_2_migration_completed.not_completed.app_error", nil, err.Error(), http.StatusNotImplemented)
	}

	a.Srv().phase2PermissionsMigrationComplete = true

	return nil
}

func (a *App) SchemesIterator(scope string, batchSize int) func() []*model.Scheme {
	offset := 0
	return func() []*model.Scheme {
		schemes, err := a.Srv().Store.Scheme().GetAllPage(scope, offset, batchSize)
		if err != nil {
			return []*model.Scheme{}
		}
		offset += batchSize
		return schemes
	}
}
