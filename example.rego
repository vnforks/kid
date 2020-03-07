package application.authz

default allow = false

allow {
    input.rbac_access_granted == true
    input.channel.name == "town-square"
    input.user.username != "sysadmin"
}

allow {
    input.rbac_access_granted == true
    input.user.username == "sysadmin"
}