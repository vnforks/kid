package application.authz

default allow = false

# allow sysadmin to do everything
allow {
    input.rbac_access_granted == true
    input.user.username == "sysadmin"
}

# no access outside of 9am to 5pm
allow {
    input.rbac_access_granted == true
    now := time.now_ns()
    output := time.clock([now, "America/New_York"])
    hour := output[0]
    hour > 9
    hour < 17
}