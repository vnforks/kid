// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package commands

import (
	"github.com/mattermost/viper"
	"github.com/spf13/cobra"
	"github.com/vnforks/kid/v5/app"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/utils"
)

func InitDBCommandContextCobra(command *cobra.Command) (*app.App, error) {
	config := viper.GetString("config")

	a, err := InitDBCommandContext(config)

	if err != nil {
		// Returning an error just prints the usage message, so actually panic
		panic(err)
	}

	a.DoAppMigrations()

	return a, nil
}

func InitDBCommandContext(configDSN string) (*app.App, error) {
	if err := utils.TranslationsPreInit(); err != nil {
		return nil, err
	}
	model.AppErrorInit(utils.T)

	s, err := app.NewServer(
		app.Config(configDSN, false),
		app.StartSearchEngine,
	)
	if err != nil {
		return nil, err
	}

	a := s.FakeApp()

	if model.BuildEnterpriseReady == "true" {
		a.LoadLicense()
	}

	return a, nil
}
