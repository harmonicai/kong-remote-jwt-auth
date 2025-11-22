-- For testing only, delete before merging to master

local plugin_name = "remote-jwt-auth"
local package_name = "kong-plugin-" .. plugin_name
local package_version = "jw"
local rockspec_revision = "1"

local github_account_name = "harmonicai"
local github_repo_name = "kong-remote-jwt-auth"
-- Defines the git branch that will be checked out to build the plugin
local git_checkout = "joseph/jwt-plugin"
-- local git_checkout = package_version == "dev" and "master" or package_version

package = package_name
version = package_version .. "-" .. rockspec_revision
supported_platforms = { "linux", "macosx" }
source = {
    url = "git+https://github.com/" .. github_account_name .. "/" .. github_repo_name .. ".git",
    -- Remove the "v" prefix for local testing
    branch = git_checkout,
}

description = {
    summary = "Validate requests sent via Google's pub/sub push with JWT authentication.",
    homepage = "https://" .. github_account_name .. ".github.io/" .. github_repo_name,
    license = "0BSD",
}

dependencies = { "lua-resty-openssl", "lua-resty-http", "lua-cjson" }

build = {
    type = "builtin",
    modules = {
        ["kong.plugins." .. plugin_name .. ".handler"] = "kong/plugins/" .. plugin_name .. "/handler.lua",
        ["kong.plugins." .. plugin_name .. ".schema"] = "kong/plugins/" .. plugin_name .. "/schema.lua",
        ["kong.plugins." .. plugin_name .. ".cache"] = "kong/plugins/" .. plugin_name .. "/cache.lua",
        ["kong.plugins." .. plugin_name .. ".firebase"] = "kong/plugins/" .. plugin_name .. "/firebase.lua",
        ["kong.plugins." .. plugin_name .. ".cerberus"] = "kong/plugins/" .. plugin_name .. "/cerberus.lua",
    },
}
