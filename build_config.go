package main

// Build constants

const VERSION = "3.1.0"

const REPOSITORY_URL = "https://github.com/unmojang/drasl"
const SWAGGER_UI_URL = "https://doc.drasl.unmojang.org"

const LICENSE = "GPLv3"
const LICENSE_URL = "https://www.gnu.org/licenses/gpl-3.0.en.html"

const DEFAULT_DATA_DIRECTORY = "/usr/share/drasl"
const DEFAULT_STATE_DIRECTORY = "/var/lib/drasl"
const DEFAULT_CONFIG_DIRECTORY = "/etc/drasl"

func GetDefaultDataDirectory() string {
	return Getenv("DRASL_DEFAULT_DATA_DIRECTORY", DEFAULT_DATA_DIRECTORY)
}

func GetDefaultStateDirectory() string {
	return Getenv("DRASL_DEFAULT_STATE_DIRECTORY", DEFAULT_STATE_DIRECTORY)
}

func GetDefaultConfigDirectory() string {
	return Getenv("DRASL_DEFAULT_CONFIG_DIRECTORY", DEFAULT_CONFIG_DIRECTORY)
}
