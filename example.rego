package application.authz

default allow = false

# allow sysadmin to do everything
allow {
    input.rbac_access_granted == true
    input.user.username == "sysadmin"
}

# # not allowed to create posts outside of business hours.
# allow {
#     input.rbac_access_granted == true
#     input.permission.id != "create_post"
# }
# allow {
#     input.rbac_access_granted == true
#     input.permission.id == "create_post"
#     output := time.clock([time.now_ns(), "America/New_York"])
#     hour := output[0]
#     hour > 9
#     hour < 17
# }

allow {
    input.rbac_access_granted == true
    input.groups["developers"].members[input.user.id]
}