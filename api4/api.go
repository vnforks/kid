// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package api4

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/vnforks/kid/v5/app"
	"github.com/vnforks/kid/v5/model"
	"github.com/vnforks/kid/v5/services/configservice"
	"github.com/vnforks/kid/v5/web"

	_ "github.com/mattermost/go-i18n/i18n"
)

type Routes struct {
	Root    *mux.Router // ''
	ApiRoot *mux.Router // 'api/v4'

	Users          *mux.Router // 'api/v4/users'
	User           *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}'
	UserByUsername *mux.Router // 'api/v4/users/username/{username:[A-Za-z0-9_-\.]+}'
	UserByEmail    *mux.Router // 'api/v4/users/email/{email}'

	Branches             *mux.Router // 'api/v4/branches'
	BranchesForUser      *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/branches'
	Branch               *mux.Router // 'api/v4/branches/{branch_id:[A-Za-z0-9]+}'
	BranchForUser        *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/branches/{branch_id:[A-Za-z0-9]+}'
	BranchByName         *mux.Router // 'api/v4/branches/name/{branch_name:[A-Za-z0-9_-]+}'
	BranchMembers        *mux.Router // 'api/v4/branches/{branch_id:[A-Za-z0-9_-]+}/members'
	BranchMember         *mux.Router // 'api/v4/branches/{branch_id:[A-Za-z0-9_-]+}/members/{user_id:[A-Za-z0-9_-]+}'
	BranchMembersForUser *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/branches/members'

	Classes                  *mux.Router // 'api/v4/classes'
	Class                    *mux.Router // 'api/v4/classes/{class_id:[A-Za-z0-9]+}'
	ClassForUser             *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/classes/{class_id:[A-Za-z0-9]+}'
	ClassByName              *mux.Router // 'api/v4/branches/{branch_id:[A-Za-z0-9]+}/classes/name/{class_name:[A-Za-z0-9_-]+}'
	ClassByNameForBranchName *mux.Router // 'api/v4/branches/name/{branch_name:[A-Za-z0-9_-]+}/classes/name/{class_name:[A-Za-z0-9_-]+}'
	ClassesForBranch         *mux.Router // 'api/v4/branches/{branch_id:[A-Za-z0-9]+}/classes'
	ClassMembers             *mux.Router // 'api/v4/classes/{class_id:[A-Za-z0-9]+}/members'
	ClassMember              *mux.Router // 'api/v4/classes/{class_id:[A-Za-z0-9]+}/members/{user_id:[A-Za-z0-9]+}'
	ClassMembersForUser      *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/branches/{branch_id:[A-Za-z0-9]+}/classes/members'
	ClassModerations         *mux.Router // 'api/v4/classes/{class_id:[A-Za-z0-9]+}/moderations'

	Posts         *mux.Router // 'api/v4/posts'
	Post          *mux.Router // 'api/v4/posts/{post_id:[A-Za-z0-9]+}'
	PostsForClass *mux.Router // 'api/v4/classes/{class_id:[A-Za-z0-9]+}/posts'
	PostsForUser  *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/posts'
	PostForUser   *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/posts/{post_id:[A-Za-z0-9]+}'

	Files *mux.Router // 'api/v4/files'
	File  *mux.Router // 'api/v4/files/{file_id:[A-Za-z0-9]+}'

	Plugins *mux.Router // 'api/v4/plugins'
	Plugin  *mux.Router // 'api/v4/plugins/{plugin_id:[A-Za-z0-9_-]+}'

	PublicFile *mux.Router // 'files/{file_id:[A-Za-z0-9]+}/public'

	Commands *mux.Router // 'api/v4/commands'
	Command  *mux.Router // 'api/v4/commands/{command_id:[A-Za-z0-9]+}'

	Hooks         *mux.Router // 'api/v4/hooks'
	IncomingHooks *mux.Router // 'api/v4/hooks/incoming'
	IncomingHook  *mux.Router // 'api/v4/hooks/incoming/{hook_id:[A-Za-z0-9]+}'
	OutgoingHooks *mux.Router // 'api/v4/hooks/outgoing'
	OutgoingHook  *mux.Router // 'api/v4/hooks/outgoing/{hook_id:[A-Za-z0-9]+}'

	OAuth     *mux.Router // 'api/v4/oauth'
	OAuthApps *mux.Router // 'api/v4/oauth/apps'
	OAuthApp  *mux.Router // 'api/v4/oauth/apps/{app_id:[A-Za-z0-9]+}'

	OpenGraph *mux.Router // 'api/v4/opengraph'

	SAML       *mux.Router // 'api/v4/saml'
	Compliance *mux.Router // 'api/v4/compliance'
	Cluster    *mux.Router // 'api/v4/cluster'

	Image *mux.Router // 'api/v4/image'

	LDAP *mux.Router // 'api/v4/ldap'

	Elasticsearch *mux.Router // 'api/v4/elasticsearch'

	DataRetention *mux.Router // 'api/v4/data_retention'

	Brand *mux.Router // 'api/v4/brand'

	System *mux.Router // 'api/v4/system'

	Jobs *mux.Router // 'api/v4/jobs'

	Preferences *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/preferences'

	License *mux.Router // 'api/v4/license'

	Public *mux.Router // 'api/v4/public'

	Reactions *mux.Router // 'api/v4/reactions'

	Roles   *mux.Router // 'api/v4/roles'
	Schemes *mux.Router // 'api/v4/schemes'

	Emojis      *mux.Router // 'api/v4/emoji'
	Emoji       *mux.Router // 'api/v4/emoji/{emoji_id:[A-Za-z0-9]+}'
	EmojiByName *mux.Router // 'api/v4/emoji/name/{emoji_name:[A-Za-z0-9_-\.]+}'

	ReactionByNameForPostForUser *mux.Router // 'api/v4/users/{user_id:[A-Za-z0-9]+}/posts/{post_id:[A-Za-z0-9]+}/reactions/{emoji_name:[A-Za-z0-9_-+]+}'

	TermsOfService *mux.Router // 'api/v4/terms_of_service
	Groups         *mux.Router // 'api/v4/groups'
}

type API struct {
	ConfigService       configservice.ConfigService
	GetGlobalAppOptions app.AppOptionCreator
	BaseRoutes          *Routes
}

func Init(configservice configservice.ConfigService, globalOptionsFunc app.AppOptionCreator, root *mux.Router) *API {
	api := &API{
		ConfigService:       configservice,
		GetGlobalAppOptions: globalOptionsFunc,
		BaseRoutes:          &Routes{},
	}

	api.BaseRoutes.Root = root
	api.BaseRoutes.ApiRoot = root.PathPrefix(model.API_URL_SUFFIX).Subrouter()

	api.BaseRoutes.Users = api.BaseRoutes.ApiRoot.PathPrefix("/users").Subrouter()
	api.BaseRoutes.User = api.BaseRoutes.ApiRoot.PathPrefix("/users/{user_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.UserByUsername = api.BaseRoutes.Users.PathPrefix("/username/{username:[A-Za-z0-9\\_\\-\\.]+}").Subrouter()
	api.BaseRoutes.UserByEmail = api.BaseRoutes.Users.PathPrefix("/email/{email:.+}").Subrouter()

	api.BaseRoutes.Branches = api.BaseRoutes.ApiRoot.PathPrefix("/branches").Subrouter()
	api.BaseRoutes.BranchesForUser = api.BaseRoutes.User.PathPrefix("/branches").Subrouter()
	api.BaseRoutes.Branch = api.BaseRoutes.Branches.PathPrefix("/{branch_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.BranchForUser = api.BaseRoutes.BranchesForUser.PathPrefix("/{branch_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.BranchByName = api.BaseRoutes.Branches.PathPrefix("/name/{branch_name:[A-Za-z0-9_-]+}").Subrouter()
	api.BaseRoutes.BranchMembers = api.BaseRoutes.Branch.PathPrefix("/members").Subrouter()
	api.BaseRoutes.BranchMember = api.BaseRoutes.BranchMembers.PathPrefix("/{user_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.BranchMembersForUser = api.BaseRoutes.User.PathPrefix("/branches/members").Subrouter()

	api.BaseRoutes.Classes = api.BaseRoutes.ApiRoot.PathPrefix("/classes").Subrouter()
	api.BaseRoutes.Class = api.BaseRoutes.Classes.PathPrefix("/{class_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.ClassForUser = api.BaseRoutes.User.PathPrefix("/classes/{class_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.ClassByName = api.BaseRoutes.Branch.PathPrefix("/classes/name/{class_name:[A-Za-z0-9_-]+}").Subrouter()
	api.BaseRoutes.ClassByNameForBranchName = api.BaseRoutes.BranchByName.PathPrefix("/classes/name/{class_name:[A-Za-z0-9_-]+}").Subrouter()
	api.BaseRoutes.ClassesForBranch = api.BaseRoutes.Branch.PathPrefix("/classes").Subrouter()
	api.BaseRoutes.ClassMembers = api.BaseRoutes.Class.PathPrefix("/members").Subrouter()
	api.BaseRoutes.ClassMember = api.BaseRoutes.ClassMembers.PathPrefix("/{user_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.ClassMembersForUser = api.BaseRoutes.User.PathPrefix("/branches/{branch_id:[A-Za-z0-9]+}/classes/members").Subrouter()
	api.BaseRoutes.ClassModerations = api.BaseRoutes.Class.PathPrefix("/moderations").Subrouter()

	api.BaseRoutes.Posts = api.BaseRoutes.ApiRoot.PathPrefix("/posts").Subrouter()
	api.BaseRoutes.Post = api.BaseRoutes.Posts.PathPrefix("/{post_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.PostsForClass = api.BaseRoutes.Class.PathPrefix("/posts").Subrouter()
	api.BaseRoutes.PostsForUser = api.BaseRoutes.User.PathPrefix("/posts").Subrouter()
	api.BaseRoutes.PostForUser = api.BaseRoutes.PostsForUser.PathPrefix("/{post_id:[A-Za-z0-9]+}").Subrouter()

	api.BaseRoutes.Files = api.BaseRoutes.ApiRoot.PathPrefix("/files").Subrouter()
	api.BaseRoutes.File = api.BaseRoutes.Files.PathPrefix("/{file_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.PublicFile = api.BaseRoutes.Root.PathPrefix("/files/{file_id:[A-Za-z0-9]+}/public").Subrouter()

	api.BaseRoutes.Plugins = api.BaseRoutes.ApiRoot.PathPrefix("/plugins").Subrouter()
	api.BaseRoutes.Plugin = api.BaseRoutes.Plugins.PathPrefix("/{plugin_id:[A-Za-z0-9\\_\\-\\.]+}").Subrouter()

	api.BaseRoutes.Commands = api.BaseRoutes.ApiRoot.PathPrefix("/commands").Subrouter()
	api.BaseRoutes.Command = api.BaseRoutes.Commands.PathPrefix("/{command_id:[A-Za-z0-9]+}").Subrouter()

	api.BaseRoutes.Hooks = api.BaseRoutes.ApiRoot.PathPrefix("/hooks").Subrouter()
	api.BaseRoutes.IncomingHooks = api.BaseRoutes.Hooks.PathPrefix("/incoming").Subrouter()
	api.BaseRoutes.IncomingHook = api.BaseRoutes.IncomingHooks.PathPrefix("/{hook_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.OutgoingHooks = api.BaseRoutes.Hooks.PathPrefix("/outgoing").Subrouter()
	api.BaseRoutes.OutgoingHook = api.BaseRoutes.OutgoingHooks.PathPrefix("/{hook_id:[A-Za-z0-9]+}").Subrouter()

	api.BaseRoutes.SAML = api.BaseRoutes.ApiRoot.PathPrefix("/saml").Subrouter()

	api.BaseRoutes.OAuth = api.BaseRoutes.ApiRoot.PathPrefix("/oauth").Subrouter()
	api.BaseRoutes.OAuthApps = api.BaseRoutes.OAuth.PathPrefix("/apps").Subrouter()
	api.BaseRoutes.OAuthApp = api.BaseRoutes.OAuthApps.PathPrefix("/{app_id:[A-Za-z0-9]+}").Subrouter()

	api.BaseRoutes.Compliance = api.BaseRoutes.ApiRoot.PathPrefix("/compliance").Subrouter()
	api.BaseRoutes.Cluster = api.BaseRoutes.ApiRoot.PathPrefix("/cluster").Subrouter()
	api.BaseRoutes.LDAP = api.BaseRoutes.ApiRoot.PathPrefix("/ldap").Subrouter()
	api.BaseRoutes.Brand = api.BaseRoutes.ApiRoot.PathPrefix("/brand").Subrouter()
	api.BaseRoutes.System = api.BaseRoutes.ApiRoot.PathPrefix("/system").Subrouter()
	api.BaseRoutes.Preferences = api.BaseRoutes.User.PathPrefix("/preferences").Subrouter()
	api.BaseRoutes.License = api.BaseRoutes.ApiRoot.PathPrefix("/license").Subrouter()
	api.BaseRoutes.Public = api.BaseRoutes.ApiRoot.PathPrefix("/public").Subrouter()
	api.BaseRoutes.Reactions = api.BaseRoutes.ApiRoot.PathPrefix("/reactions").Subrouter()
	api.BaseRoutes.Jobs = api.BaseRoutes.ApiRoot.PathPrefix("/jobs").Subrouter()
	api.BaseRoutes.Elasticsearch = api.BaseRoutes.ApiRoot.PathPrefix("/elasticsearch").Subrouter()
	api.BaseRoutes.DataRetention = api.BaseRoutes.ApiRoot.PathPrefix("/data_retention").Subrouter()

	api.BaseRoutes.Emojis = api.BaseRoutes.ApiRoot.PathPrefix("/emoji").Subrouter()
	api.BaseRoutes.Emoji = api.BaseRoutes.ApiRoot.PathPrefix("/emoji/{emoji_id:[A-Za-z0-9]+}").Subrouter()
	api.BaseRoutes.EmojiByName = api.BaseRoutes.Emojis.PathPrefix("/name/{emoji_name:[A-Za-z0-9\\_\\-\\+]+}").Subrouter()

	api.BaseRoutes.ReactionByNameForPostForUser = api.BaseRoutes.PostForUser.PathPrefix("/reactions/{emoji_name:[A-Za-z0-9\\_\\-\\+]+}").Subrouter()

	api.BaseRoutes.OpenGraph = api.BaseRoutes.ApiRoot.PathPrefix("/opengraph").Subrouter()

	api.BaseRoutes.Roles = api.BaseRoutes.ApiRoot.PathPrefix("/roles").Subrouter()
	api.BaseRoutes.Schemes = api.BaseRoutes.ApiRoot.PathPrefix("/schemes").Subrouter()

	api.BaseRoutes.Image = api.BaseRoutes.ApiRoot.PathPrefix("/image").Subrouter()

	api.BaseRoutes.TermsOfService = api.BaseRoutes.ApiRoot.PathPrefix("/terms_of_service").Subrouter()
	api.BaseRoutes.Groups = api.BaseRoutes.ApiRoot.PathPrefix("/groups").Subrouter()

	api.InitUser()
	api.InitBranch()
	api.InitClass()
	api.InitFile()
	api.InitSystem()
	api.InitLicense()
	api.InitConfig()
	//api.InitWebhook()
	api.InitPreference()
	api.InitSaml()
	api.InitCompliance()
	api.InitCluster()
	api.InitLdap()
	api.InitElasticsearch()
	api.InitDataRetention()
	api.InitBrand()
	api.InitJob()
	api.InitCommand()
	api.InitStatus()
	api.InitWebSocket()
	api.InitEmoji()
	api.InitOAuth()
	api.InitReaction()
	api.InitOpenGraph()
	api.InitRole()
	api.InitScheme()
	api.InitImage()
	api.InitTermsOfService()

	root.Handle("/api/v4/{anything:.*}", http.HandlerFunc(api.Handle404))

	return api
}

func (api *API) Handle404(w http.ResponseWriter, r *http.Request) {
	web.Handle404(api.ConfigService, w, r)
}

var ReturnStatusOK = web.ReturnStatusOK
