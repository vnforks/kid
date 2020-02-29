package application.authz

default allow = false
allow {
    input.roles_grant_permission == true
    input.permission != "create_post"
}

allow {
    input.roles_grant_permission == true
    input.channel_id != "6d1n1h39ktrj8mzrhg6goby9mc"
}


# RolesGrantPermission bool     `json:"roles_grant_permission"`
# ChannelID            string   `json:"channel_id"`
# UserID               string   `json:"user_id"`
# Permission           string   `json:"permission"`
# Roles                []string `json:"roles"`