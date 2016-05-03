# CloudShark Plugin for Wireshark
The CloudShark Plugin for Wireshark makes it seamless to move your 
capture files from Wireshark to a CloudShark appliance or 
<https://www.cloudshark.org>. Once installed, the plugin adds a new 
**CloudShark** submenu under the existing Wireshark **Tools** menu. 
Capture files are sent to the configured CloudShark appliance or 
<https://www.cloudshark.org> by selecting the upload option under the 
**Tools > CloudShark** menu. The plugin also works with tshark from the command-line.

## Requirements

The CloudShark plugin requires Wireshark version 1.4 or newer. The 
plugin uses Wireshark's Lua scripting interface and runs on all 
platforms supported by Wireshark, provided the Lua interface has been 
enabled. Systems must also contain a recent version of [curl](http://curl.haxx.se/).

## Installation

The plugin should be installed in your Wireshark plugin directory.

You can find your Wireshark plugin directory by opening Wireshark and
going to `Help > About Wireshark` and clicking on the `Folders` tab. 
The `Personal Plugins` directory should be used to install the
CloudShark Wireshark plugin to allow users to configure their own API
Tokens.

You can install the CloudShark Wireshark plugin by cloning this
repository into your plugins folder into a directory named `cloudshark`.

To do that on Unix-like systems, such as Linux, OS X, \*BSD, Solaris,
AIX, and HP-UX, from the command line:

1. If the path displayed as your `Personal Plugins` directory doesn't
exist, create it with `mkdir -p <path>`.
2. Change to that directory with `cd <path>`
3. Clone the repository with
```
git clone https://github.com/cloudshark/wireshark-plugin.git cloudshark
```

Alternatively you can download the [zip file](https://github.com/cloudshark/Wireshark-plugin/archive/master.zip)
and extract this into your Wireshark plugins folder.

After cloning the git repository or unzipping the archive you must copy the
default configuration, `cloudshark_init.default` to, `cloudshark_init.lua`.

**Running as root or admin:** If you are running Wireshark as root or 
admin, you may need to enable support for Lua scripts by modifying your 
/etc/Wireshark/init.lua script and setting the 
**runuser_scripts_when_superuser** field to true.

```bash
run_user_scripts_when_superuser = true
```

Rather than running as root or admin, try 
[enabling capture privileges](http://wiki.wireshark.org/CaptureSetup/CapturePrivileges)
for the user running Wireshark.

## Configuration

By default, the plugin is configured to work with
<https://www.cloudshark.org>.  You must modify the plugin configuration
file to work with your own CloudShark appliance.  The configuration file
is installed as `cloudshark_init.lua` in the `cloudshark` directory in
your Wireshark plugin directory.  The configuration file can be edited
right through Wireshark by selecting **Tools > CloudShark >
Preferences**.  This menu option will open the current configuration
file in a text window that you may edit.  After modifying the
configuration file, be sure to save it before closing the window.

If you are using <https://www.cloudshark.org> you will have to modify
the `CLOUDSHARK_API_KEY` to match your API token. This can be found by
logging into <https://www.cloudshark.org> and clicking on
`Preferences > API Tokens`.

The following configuration variables are defined. The configuration 
file is a Lua file that must conform to the Lua syntax. If a syntax 
error is created, Wireshark will raise a Lua exception during the next 
upload. The configuration is reloaded before every new upload.

```text
--[[
This is the configuration file for the CloudShark plugin.
Visit https://support.cloudshark.org for additional help.
--]]

-- To disable the CloudShark plugin,
-- set the CLOUDSHARK_ENABLE setting to "n".
CLOUDSHARK_ENABLE = "y"

-- URL:  The CloudShark appliance URL
CLOUDSHARK_URL = "https://www.cloudshark.org"

-- API:  The API token to use
CLOUDSHARK_API_KEY = "<INSERT API TOKEN HERE>"

-- Tags: A comma separated list of tags
CLOUDSHARK_TAGS = ""

-- User: The user name (only if login is required)
CLOUDSHARK_USER = ""

-- Password: The password (only if login is required)
CLOUDSHARK_PASSWORD = ""

-- Tshark: To enable tshark support for the plugin,
-- set the CLOUDSHARK_TSHARK setting to "y" for auto
-- mode or "prompt" for prompting mode.
CLOUDSHARK_TSHARK = "n"

-- Curl: The path to curl if non-standard
-- Paths should be formatted with [[path]]
-- Remove the -- below to uncomment
-- CLOUDSHARK_CURL = [[C:\example\curl.exe]]

-- CA Bundle: The path to an alternative CA bundle file in pem format
-- Paths should be formatted with [[path]]
-- Remove the -- below to uncomment
-- CLOUDSHARK_CABUNDLE = [[C:\example\curl-ca-bundle.crt]]

-- Certificate verification: You can disable certificate verification
-- by setting CLOUDSHARK_CERT_VERIFY to "n". This will use
-- curl's --insecure option.
-- CLOUDSHARK_CERT_VERIFY = "n"

-- When used from Wireshark, the plugin will attempt
-- to open a brower and load CloudShark after a capture
-- is uploaded. You can set CLOUDSHARK_OPEN_BROWSER to
-- "n" to disable this behavior.
CLOUDSHARK_OPEN_BROWSER = "y"
```

These options are defined as:

* **CLOUDSHARK_ENABLE:** The CLOUDSHARK_ENABLE entry controls the 
status of the Lua plugin. By default the plugin is active. You can turn off
the plugin by setting this value to "n".

* **CLOUDSHARK_URL:** The CLOUDSHARK_URL entry contains the URL used to 
reach your CloudShark appliance. It must also contain desired http or 
https transport.

* **CLOUDSHARK_API_KEY:** The CLOUDSHARK_API_KEY entry 
contains the API key for your CloudShark appliance. 

* **CLOUDSHARK_TAGS:** The CLOUDSHARK_TAGS entry is used to specify tags 
that should be applied to every Wireshark upload. Tags must be comma 
separated. Additional tags can also be specified at upload time in the 
Upload GUI. Useful tags include location information, device 
information, and security information.

* **CLOUDSHARK_USER:** The CLOUDSHARK_USER entry is required when the API 
key also requires user authentication. NOTE: The default API keys for 
<https://www.cloudshark.org> do not require user authentication.

* **CLOUDSHARK_PASSWORD:** The CLOUDSHARK_PASSWORD entry is required when 
the API key also requires user authentication. This entry must contain 
the password. NOTE: The default API keys for <https://www.cloudshark.org> do not 
require user authentication.

* **CLOUDSHARK_TSHARK:** The CLOUDSHARK_TSHARK entry is used to enable the 
CloudShark plugin for tshark. By default, the plugin does not perform 
any uploads when tshark is used. You can enable tshark support by 
setting this value to "y" for automatic uploads or "prompt" to prompt 
the user before uploading.

* **CLOUDSHARK_CURL:** The CLOUDSHARK_CURL entry is used to specify the 
command path to curl. By default, the plugin executes curl which must be 
in the path for the user running Wireshark. Paths should be entered 
using Lua's [[ ]] notation rather than using double quotes.

* **CLOUDSHARK_CABUNDLE:** The CLOUDSHARK_CABUNDLE entry is used to specify 
an alternative CA file. Paths should be entered using Lua's [[ ]] notation 
rather than using double quotes.

* **CLOUDSHARK_CERT_VERIFY:** The CLOUDSHARK_CERT_VERIFY entry is used 
to enable or disable certificate verification. By default, the plugin will attempt
to verify the CloudShark server's extension when using https URLs. You can turn
off certificate verification by setting this value to "n". When disabled, the
plugin using curl's --insecure option.

* **CLOUDSHARK_OPEN_BROWSER:** The CLOUDSHARK_OPEN_BROWSER entry is used 
to enable or disable launching of a web browser when using the Wireshark GUI. 
By default, the plugin will launch your local browser after uploading a capture
file to CloudShark. You can disable this behavior by setting this option to
"n".

## Uploading

A capture file can be uploaded by selecting the **Upload** option from 
the **Tools > CloudShark** menu. Capture files can be uploaded when a 
live capture is still in progress or stop the capture before the upload. 
If you upload a live capture, any new packets that arrive while the upload 
is happening may not be included. For precise results, we recommend that 
you stop a live capture before uploading.

The Upload dialog provides additional options for adding tags and naming 
your capture file. Both of these entries are optional. Any tags 
specified will be added in addition to any tags configured with the 
CLOUDSHARK_TAGS option. If a new name is specified, the plugin will 
copy the capture file to this name before uploading. The name field 
should also contain the desired extension such as .cap or .pcap. If no 
name is specified, the file name used in the CloudShark session is OS 
dependent.

A progress dialog will appear once an upload is started. At the 
completion of the upload, Wireshark will open another status dialog with 
either the location of the CloudShark session URL or an error 
indication. If the upload is successful, CloudShark will also attempt to 
open the CloudShark session URL using the default browser.

## Using Other Certificates

By default the CloudShark plugin will verify certificates using the systems
preloaded root certificates. If you need to use a different CA file to verify 
your CloudShark appliance, you can specify the path to a local CA file that 
contains the required CA certificates in PEM format. For example:

``` text
CLOUDSHARK_CABUNDLE = "/home/fred/my-ca.crt"
```

## Tshark Support

The plugin supports both the Wireshark GUI and tshark. To enable tshark 
support, configure the CLOUDSHARK_TSHARK setting to either **y** or 
**prompt**. The same configuration file is used for both Wireshark and 
tshark. When CLOUDSHARK_TSHARK is set to "y", the plugin will 
automatically upload the current capture file to CloudShark. When 
CLOUDSHARK_TSHARK is set to "prompt", the user will be prompted to 
confirm the upload. The capture file will not be uploaded in "prompt" 
mode unless the user specically enters "y" at the prompt.

### Tshark Example

``` text
tshark -i eth0 -q -c 5 
CloudShark plugin for Wireshark (c) 2012
Version 1.0 rev 136
Developed by QA Cafe
Capturing on eth0
5 packets captured

Uploading capture file to CloudShark via http://172.16.1.137
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  5048    0    66  100  4982    238  18007 --:--:-- --:--:-- --:--:-- 18050

HTTP Response Code: 200
A new CloudShark session has been created at:

http://172.16.1.137/captures/7d1e5e2645b3
```

## Security

Use of https uploads is recommended. The CloudShark plugin will always 
upload via https when the CLOUDSHARK_URL is specified using https. The 
default configuration for <https://www.cloudshark.org> defaults to https.

## Default Browser

The CloudShark plugin will open new CloudShark session URLs using the 
system's default browser. We recommend setting up your system with an 
updated version of one of the modern browsers as your default. This will 
maximize your CloudShark experience. The latest version of Chrome or 
Safari is recommended.

## Disk Space

The plugin uses the `cloudshark` directory in your Wireshark plugin
directory for working disk space.  You must have enough disk space in
this directory to support your captures.  A good rule of thumb is to
allocate three times as much disk space as your largest desired capture
file.  The plugin manages the capture files automatically.

## Errors

It is possible that an upload will fail. If the upload does fail, an 
error message will be reported. Some possible errors include:

* Invalid CLOUDSHARK_URL
* Invalid API Key
* Authentication failure
* Capture file is too big

## Upgrades

The plugin can safely be upgraded to a new version if available. By 
default, the installer will not overwrite any existing configuration 
file. Your configuration will be preserved if you have configured your 
plugin to work with a specific CloudShark appliance.

## Uninstall

The plugin can be removed by deleting the `cloudshark` directory in your
Wireshark plugin directory.

