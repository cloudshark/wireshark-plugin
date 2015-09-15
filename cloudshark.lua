--[[
 
CloudShark Plugin for WireShark
Developed by QA Cafe, 2012-2015

For additional help on using this plugin, please 
contact support@cloudshark.org.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  
02111-1307, USA.

]]

--
-- The CloudShark plugin for Wireshark allows users to send
-- their capture files to a CloudShark appliance or cloudshark.org.
-- The plugin works for both Wireshark and tshark. Normally, the
-- plugin is installed in the user's ~/.wireshark/plugins/cloudshark
-- direcory. The plugin has a dependency on curl which must be
-- installed in the user's PATH.

--
-- Lua functions for the CloudShark Plugin.
--

cloudshark_plugin_version = "1.0.4"
cloudshark_year = "2015"

--
-- Create the About CloudShark window.
--

function cloudshark_about_win()
   cs_about_win = TextWindow.new("About CloudShark")
   cs_about_win:append(string.format("CloudShark plugin for WireShark (c) %s\n", cloudshark_year))
   cs_about_win:append(string.format("Version %s\n", cloudshark_plugin_version))
   cs_about_win:append("Developed by QA Cafe\n")
   cs_about_win:append("\n")
   cs_about_win:append("This Wireshark plugin allows you to send your capture files to CloudShark.org ")
   cs_about_win:append("or your own CloudShark appliance. You can configure this plugin by selecting ")
   cs_about_win:append("the Preferences menu item or editing ")
   cs_about_win:append("the plugin configuration file at:\n\n")
   cs_about_win:append(cs_make_path( cs_config_name()  ))
   cs_about_win:append("\n")
   cs_about_win:append("\nVisit http://appliance.cloudshark.org/ for more help.\n")
   cs_about_win:append("\n")
end

--
-- Create the CloudShark Preferences window.
--

function cloudshark_prefs_win()
   local configFile = cs_config_name()
   local file = io.open(configFile, "r")
   local data = file:read('*a')
   io.close(file)

   cs_prefs = TextWindow.new("CloudShark Preferences")
   cs_prefs:set_editable(true)
   cs_prefs:add_button("Save", cloudshark_save_config)
   cs_prefs:append(data)

end

--
-- Save the contents of the prefs text window to the plugin
-- configuration file.
--

function cloudshark_save_config()
   local data = cs_prefs:get_text()
   local configFile = cs_config_name()
   local file = io.open(configFile, "w")
   file:write(data)
   file:close()

   -- now load the config again
   cs_load_config()
end

--
-- Display a CloudShark plugin message. This will either go to the
-- GUI text window or just print to stdout.
--

function cs_display(message)

  -- handle either gui or non gui mode
   if gui_enabled() == true then
      cs_win:append(message)
   else
      io.write(message)
      io.flush()
   end

end

--
-- Display a CloudShark standard contact message
--

function cs_display_help()
    cs_display("\n\nFor additional help, please contact support@cloudshark.org\n")
end

function cs_display_config_error(message)
    cs_display("Your CloudShark plugin is not configured or installed ")
    cs_display("properly.\n\n")
    cs_display(string.format("ERROR: %s\n", message))
    cs_display("\nPlease correct the configuration values in\n")
    cs_display(cs_make_path( cs_config_name() ))
    cs_display("\n")
    cs_display("For more help on installing and configuring the CloudShark ")
    cs_display("plugin, please visit:\n\nhttp://appliance.cloudshark.org\n")
    cs_display("\nOr contact support@cloudshark.org\n")
end

--
-- Prompt user for input
--

function cs_prompt(message)
   io.flush()
   io.write(message)
   io.flush()
   local line = io.read()
   return line
end

--
-- Pure Lua version of basename. Return the basename of
-- a directory path.
--

function cs_basename(path)
    local i = string.len(path)
    local delim = "/"

    -- check to see if this is a windows style path
    local found_back_slash = string.find( path, "\\" )
    if found_back_slash ~= nil then

       -- switch the delimiter
       delim = "\\"
    end

    while string.sub(path, i, i) == delim and i > 0 do
        path = string.sub(path, 1, i - 1)
        i = i - 1
    end
    while i > 0 do
        if string.sub(path, i, i) == delim then
            break
        end
        i = i - 1
    end
    if i > 0 then
        path = string.sub(path, i + 1, -1)
    end
    if path == "" then
        path = delim
    end

    return path
end

--
-- Return the name of the log directory for writting log files.
--

function cs_log_dir()
   return persconffile_path('plugins/cloudshark')
end

--
-- Return the name of the plugin configuration file
--

function cs_config_name()
   local configFile = string.format("%s/cloudshark_init.lua", cs_log_dir())
   return configFile
end

--
-- Load the CloudShark plugin configuration file.
--

function cs_load_config()

   -- set all available configuration variables to nil
   CLOUDSHARK_URL = nil
   CLOUDSHARK_API_KEY = nil
   CLOUDSHARK_TAGS = nil
   CLOUDSHARK_USER = nil
   CLOUDSHARK_PASSWORD = nil
   CLOUDSHARK_CURL = nil
   CLOUDSHARK_CABUNDLE = nil
   CLOUDSHARK_DEBUG = nil
   CLOUDSHARK_TSHARK = nil
   CLOUDSHARK_ENABLE = nil
   CLOUDSHARK_CERT_VERIFY = nil

   -- now load the config file which may set config variables
   local configFile = cs_config_name()
   cdebug(string.format("Loading configuration file %s", configFile))

   if cs_file_exists(configFile) == false then
     error(string.format("The config file %s does not exist", configFile))
   end

   dofile(configFile)

   if CLOUDSHARK_URL ~= nil then
      -- remove any trailing '/' character
      local trailing = string.sub( CLOUDSHARK_URL, -1 , -1 )

      if trailing == "/" then
         CLOUDSHARK_URL = string.sub(CLOUDSHARK_URL, 1, -2 )
      end
   end
end

--
-- Allocate a temporary file name. 
--

function cs_temp_file( extension )
   local mytemp = os.tmpname()
   cdebug(string.format("Received os.tmpname() of %s", mytemp))
   filename = cs_basename(mytemp)

   local tfile = string.format("%s/wireshark-plugin-%s", cs_log_dir(), filename)   
  
   -- add extension
   if extension ~= "" then
      tfile = string.format("%s.%s", tfile, extension )   
   end

   cdebug(string.format("Creating temp file %s", tfile))
   os.remove(mytemp)

   return tfile
end

--
-- Copy a file from one place to another.
--

function cs_file_copy ( origFile, newFile )

   -- open the new output file in write/binary mode
   local output = io.open( newFile, "wb")
   if output == nil then
      cdebug(string.format("Unable to create new file %s", newFile))
      return false
   end

   -- open the file to copy in read/binary mode
   local file = io.open( origFile, "rb")   

   -- need a better function that does not do this in one chunk
   local data = file:read('*a')

   -- write out the new file
   output:write(data)

   file:close()
   output:close()          

   return true
end

--
-- Check to see if a file exists.
--

function cs_file_exists( path )
   local output = io.open( path, "rb")
   if output == nil then
      return false
   else
      output:close()
      return true
   end
end

--
-- If the path is using windows style directory paths, convert everything to this format.
--

function cs_make_path(path)
   local found_back_slash = string.find( path, "\\" )
   if found_back_slash ~= nil then
      path = path:gsub("/", "\\")
   end
   return path
end

--
-- Start the CloudShark debug log.
--

function cs_log_start()

   -- NOTE: The debug log process only works with a single Wireshark or tshark
   -- process. If you enable CLOUDSHARK_DEBUG and then run multiple processes of
   -- of Wireshark or tshark, your log will get squashed by the newest process.

   if CLOUDSHARK_DEBUG ~= nil then
      local logFile = string.format("%s/cloudshark-log.txt", cs_log_dir())
      logHandle = assert(io.open(logFile, "w"))
      local date_stamp = os.date("%x %X")
      logHandle:write(string.format("DEBUG: %s| Starting new CloudShark plugin log\n", date_stamp ))
      logHandle:close()
   end
end

--
-- Print a log message.
--

function cs_print_log(message)
   local logFile = string.format("%s/cloudshark-log.txt", cs_log_dir())
   logHandle = assert(io.open(logFile, "a+"))
   logHandle:write(string.format("%s\n",message))
   logHandle:close(logHandle)
end

--
-- Print a debug message if CLOUDSHARK_DEBUG is enabled.
--

function cdebug(message)
   if CLOUDSHARK_DEBUG ~= nil then
      local date_stamp = os.date("%x %X")
      cs_print_log(string.format("DEBUG: %s| %s", date_stamp, message))
   end
end

--
-- Check for the presense of curl in the users OS path.
--

function cs_check_curl()
   local curl_bin = "curl"
   if CLOUDSHARK_CURL ~= nil and CLOUDSHARK_CURL ~= "" then
      curl_bin = CLOUDSHARK_CURL
        cdebug(string.format("Using CLOUDSHARK_CURL specified curl path %s", CLOUDSHARK_CURL))
   end
   
   -- try running curl
   command = assert(io.popen(string.format("\"%s\" -V", curl_bin), 'r'))
   result = command:read('*a')
   local curl_version = ""

   if result ~= nil then
      for word in string.gmatch(result, "curl %S+") do 
         curl_version = word
         break
      end
   end

   if curl_version ~= "" then
      cdebug(string.format("Found curl version %s, dumping full curl -V", curl_version))
      cdebug(result)
      return true
   else 
      cdebug("curl appears to be missing on this system.")
      cdebug(result)
      error("Can not find curl installed on your system.")
      return false
   end
end

--
-- Run curl and monitor the result using a coroutine.
--

function cs_curl_capture( cmd,  raw, direction, prog )

  -- we use a coroutine to allow a progress bar
  local co = coroutine.create(
    function()
       ecom = assert(io.popen(cmd, 'r'))

       local count = 0
       local progress = 0

       -- buffer needs to be global
       buffer = ""

       local message = "Starting upload"

       if direction == "download" then
         message = "Starting download"
       end

       local safe = ""

       while true do
          local c = ecom:read(1)

          if gui_enabled() == false then
             io.write(c)
	     io.flush()
          end

          safe = c
          if c == nil then
             break
          else
            count = count + 1 
            byte = string.byte(c)

            -- when we get a carriage return, we look into the current buffer

            if byte == 13 then
               index = 0
               result = {}
               for token in string.gmatch(buffer, "[^%s]+") do
                 result[index] = token
                 index = index + 1
               end

               if tonumber(result[0]) ~= nil then
                  progress = result[0]

                  if direction == "download" then
                       message = string.format("Received %s of %s", result[3], result[1])
                  else 
                       message = string.format("Sent %s of %s", result[5], result[1])
                  end

               else
                  progress = 0
                  message = ""
               end

               buffer = ""
            else
               buffer = string.format("%s%c", buffer, string.byte(safe))
            end

            coroutine.yield(progress/100, message)
         end
       end
       ecom:close()
    end
  )

  -- While curl is running, update the status bar. Not perfect, we will
  -- block is curl is blocked.

  while coroutine.status(co) ~= 'dead' do

      -- quit if STOP button pressed
      if prog ~= nil then
         if prog:stopped() then
           stopped = 1

           -- can't call close() on popen or else it will block. This leaves
           -- a stray curl process
           -- ecom:close()

          break
        end
      end

     local res, val, message = coroutine.resume(co)
     if not res or res == false then
         if val then
            cdebug(string.format("debug = %s", val))
         end

         cdebug("coroutine error")
         break
     end

     if prog ~= nil then
        prog:update(val, message)
     end

  end

  -- close the progress dialog
  if prog ~= nil then
     prog:close()
  end

  cdebug(string.format("final buffer %s", buffer))
  return buffer
end

--
-- Find the HTTP response code. We write this out specifically
-- using the -w option to curl.
--

function cs_http_code(buffer)

   local http_code = nil

   -- try to find the code string
   local http_buf = string.match(buffer, "HTTP Response Code: %d+")
   
   -- we found it, try to extract it
   if http_buf ~= nil then
      http_code = string.match(http_buf, "%d+")
   end

   return http_code
end

--
-- Reformat a HTTP status code into a class code.
-- 401 -> 4xx
-- 404 -> 4xx 
-- 500 -> 5xx
--

function cs_http_code_class(code)
   local code_class = string.format("%sxx", string.sub(code, 1, 1))
   return code_class
end

--
-- Load a URL using the cloudshark settings. If the expected result
-- is JSON, the 
--
-- Returns 5 arguments
--   response_code  -> HTTP response code or 000 if no response
--   response_curl  -> The raw curl response
--   response_page  -> The unparsed HTTP page
--   response_json  -> The parsed JSON
--   parseok        -> true if JSON parse succeeded, false otherwise
--

function cs_load_url( url, output_file, parse_json, use_progress_meter )
    local response_code = nil
    local response_page = nil
    local response_json = nil
    local response_curl = nil

    local auth = ""
    local auth_clean = ""
    local cert_verify = ""

    local curl_bin = "curl"

    local code_str = [[\nHTTP Response Code: %{http_code}\n]]

    local tname = os.tmpname()
    local tfile = cs_basename(tname)
    local newFile = string.format("%s/tmp/wireshark-plugin-%s%s", cs_log_dir(), tfile, ".json" )
    local parseok = false
    local prog = nil

    os.remove(tname)

    if output_file ~= nil then
       newFile = output_file
    end

    stopped = 0

    cdebug(string.format("Loading URL %s", url))

    -- setup the user authentication if needed
    if CLOUDSHARK_USER ~= nil and CLOUDSHARK_USER ~= "" and 
       CLOUDSHARK_PASSWORD ~= nil and CLOUDSHARK_PASSWORD ~= "" then
         auth = string.format("--user %s:%s", CLOUDSHARK_USER, CLOUDSHARK_PASSWORD)
         auth_clean = string.format("--user %s:%s", "xxx", "xxx")
         cdebug("User authentication requested")
    end

    -- Either use our curl-ca-bundle or a user specified ca bundle
    if CLOUDSHARK_CERT_VERIFY ~= nil and CLOUDSHARK_CERT_VERIFY == "n" then
        cert_verify = "--insecure"
    elseif CLOUDSHARK_CABUNDLE ~= nil and CLOUDSHARK_CABUNDLE ~= "" then
        cert_verify = string.format("--cacert \"%s\"", CLOUDSHARK_CABUNDLE)
    else
        cert_verify = ""
    end

    -- build the curl command-line
    if CLOUDSHARK_CURL ~= nil and CLOUDSHARK_CURL ~= "" then
       curl_bin = CLOUDSHARK_CURL
    end
 
    -- load the info for this file
    command = string.format("%s %s %s -w \"%s\" -o \"%s\"  \"%s\" 2>&1", 
                curl_bin, auth, cert_verify, code_str, newFile, url )

    command_clean = string.format("%s %s %s -w \"%s\" -o \"%s\"  \"%s\" 2>&1", 
                curl_bin, auth_clean, cert_verify, code_str, newFile, url )

    cdebug(string.format("Running %s", command_clean))

    -- create a new progress bar
    if use_progress_meter == true then
       prog = ProgDlg.new()
    end

    response_curl = cs_curl_capture( command, 0, "download", prog )
    response_code = cs_http_code(response_curl)

    if response_code ~= nil then
        cdebug(string.format("Found HTTP Response Code: %s", response_code))
    end

    if stopped == 0 then

       if parse_json == true then

           -- process json
           file = io.open(newFile, "r")
           if file ~= nil then
               response_page = file:read('*a')     
               io.close(file)
               os.remove(newFile)

               cdebug(string.format("Processing JSON response from %s", url))
               if response_page ~= "[]" then
                  parseok, response_json = pcall(json.decode, response_page)
               end
            else
               response_page = ""
           end
       end
   end

   -- return 5 arguments
   return response_code, response_curl, response_page, response_json, parseok

end

function cloudshark_url_escape(s)
    return string.gsub(s, "([^A-Za-z0-9_])", function(c)
        return string.format("%%%02x", string.byte(c))
    end)
end
 
function cloudshark_do_upload(tags, capture_name)

    -- update the upload count for tracking
    upload_count = upload_count + 1
    cdebug(string.format("Starting upload session %d", upload_count))

    -- reload the config
    cs_load_config()

    -- create a progress dialog
    if gui_enabled() == true then
        cs_prog = ProgDlg.new()	
    else
        cs_prog = nil
    end

    -- build the curl URL
    url = string.format("%s/api/v1/%s/upload", CLOUDSHARK_URL, CLOUDSHARK_API_KEY)

    capture_filename = capfile

    local newFile = nil

    if capture_name ~= nil and capture_name ~= "" then
       local cname = cs_basename(capture_name)
       newFile = string.format("%s/tmp/%s", cs_log_dir(), cname)
    else
       -- no filename specified, create a unique name automatically
       local tname = os.tmpname()
       local tfile = cs_basename(tname)
       newFile = string.format("%s/tmp/wireshark-plugin-%s%s", cs_log_dir(), tfile, ".cap" )
       os.remove(tname)
    end

    -- we always copy the file, expensive but avoids issues uploading live capture files
    cdebug(string.format("Copy %s to %s", capfile, newFile))
    if cs_file_copy( capfile, newFile ) == true then
       capture_filename = newFile
    end

    -- create a temporary file with no extension for the curl output
    output = cs_temp_file( "" )

    local auth = ""
    local auth_clean = ""
    local cert_verify = ""

    if CLOUDSHARK_USER ~= nil and CLOUDSHARK_USER ~= "" and 
       CLOUDSHARK_PASSWORD ~= nil and CLOUDSHARK_PASSWORD ~= "" then
         auth = string.format("--user %s:%s", CLOUDSHARK_USER, CLOUDSHARK_PASSWORD)
         auth_clean = string.format("--user %s:%s", "xxx", "xxx")
         cdebug("User authentication requested")
    end

    -- Either use our curl-ca-bundle or a user specified ca bundle
    if CLOUDSHARK_CERT_VERIFY ~= nil and CLOUDSHARK_CERT_VERIFY == "n" then
        cert_verify = "--insecure"
    elseif CLOUDSHARK_CABUNDLE ~= nil and CLOUDSHARK_CABUNDLE ~= "" then
        cert_verify = string.format("--cacert \"%s\"", CLOUDSHARK_CABUNDLE)
    else
        cert_verify = ""
    end

    -- build the curl command-line
    curl_bin = "curl"
    if CLOUDSHARK_CURL ~= nil and CLOUDSHARK_CURL ~= "" then
       curl_bin = CLOUDSHARK_CURL
    end


    -- build the curl command line
    local code_str = [[\nHTTP Response Code: %{http_code}\n]]
    command = string.format("%s %s %s -w \"%s\" -F \"file=@%s\" -F \"additional_tags=%s,%s\" -o \"%s\"  %s 2>&1", 
                curl_bin, auth, cert_verify, code_str, capture_filename, CLOUDSHARK_TAGS, tags, output, url)
 
    -- build a second clean command with the authentication details (for logging only)
    command_clean = string.format("%s %s %s -w \"%s\" -F \"file=@%s\" -F \"additional_tags=%s,%s\" -o \"%s\"  %s 2>&1", 
                curl_bin, auth_clean, cert_verify, code_str, capture_filename, CLOUDSHARK_TAGS, tags, output, url)

    stopped = 0

    -- only log the clean version of the curl command without the authentication
    cdebug(command_clean)
    curl_response = cs_curl_capture( command, 0, "upload", cs_prog )

    -- get HTTP status code if any otherwise http_code is nil
    local http_code = cs_http_code(curl_response)
    if http_code ~= nil then
        cdebug(string.format("Found HTTP Response Code: %s", http_code))
    end

    -- remove the upload file
    os.remove(newFile)

    if stopped == 1 then
       -- we are stopped, just abandon the process since we don't have real process management
       return
    end
   
    -- build a result window
    if gui_enabled() == true then
       cs_win = TextWindow.new("CloudShark")	
    end

    -- read the curl result
    file = io.open(output, "r")

    if file ~= nil then

        -- read the output file
        curl = file:read('*a')     
        io.close(file)

        -- clean up any temp files
        os.remove(output)

        cdebug(string.format("curl respose: %s", curl))
    else
        -- no output file found
        curl = ""
    end

        -- check for various errors
    if http_code == "401" then

         cs_display("The upload failed due to a HTTP 401 authentication error. Please check ")
         cs_display("that a valid CLOUDSHARK_USER and CLOUDSHARK_PASSWORD has been ")
         cs_display("configured. This API key requires authentication.\n")
         cs_display_help()

    elseif curl == "" then

         -- no result file?
         cs_display("The CloudShark upload failed.\n\n")

         if gui_enabled() == true then
            cs_display(curl_response)
            cs_display("\n")
         end

    else 

        -- parse the result, we are expecting JSON
        local parseok, t = pcall(json.decode,curl)

        if parseok then 
            cdebug("JSON parse of result is okay")

            if t.id then

              -- a normal response will have the id field set for URL building
              cdebug(string.format("CloudShark session id is %s", t.id ))     
              cs_display("A new CloudShark session has been created at:")
              cs_display("\n")
              cs_display("\n")
              url = string.format("%s/captures/%s",CLOUDSHARK_URL,t.id)

              -- get current filter if using GUI and get_filter
              -- function is defined
              if gui_enabled() and get_filter then
                  filter = get_filter()
                  if filter ~= nil and filter ~= "" then
                      filter = cloudshark_url_escape(filter)
                      url = string.format("%s?filter=%s",url,filter)
                  end
              end

              cs_display(url)
              cs_display("\n")
              cs_display("\n")

              if gui_enabled() == true then

                  if CLOUDSHARK_OPEN_BROWSER ~= nil and CLOUDSHARK_OPEN_BROWSER == "n" then   
                     cs_display("Please visit the URL above to view your CloudShark session.")
                     cs_display("\n")
                  else
                     cs_display("Wireshark will now open this URL with your default browser. ")
                     cs_display("If your browser does not load, please visit the URL above to ")
                     cs_display("view your CloudShark session.")
                     cs_display("\n")
                     browser_open_url(url)
                  end
              end

              cdebug(string.format("A new cloudshark session has been created at %s", url))

            elseif t.status and t.exceptions[1] then

              -- an error will have the status and exceptions fields set
              cs_display("The CloudShark upload failed.\n\n")
              cs_display(string.format("Message: %s", t.exceptions[1]))
              cs_display_help()

            else

              -- something else happened
              cs_display("The CloudShark upload failed.\n\n")
              cs_display(curl)
              cs_display_help()

           end

        else 

           -- could not parse the result as JSON
           cdebug("JSON parse failed, dumping result")
           cdebug(curl)

           cs_display("There was an unexpected error with the CloudShark API response. ")
           cs_display("Please check your CLOUDSHARK_URL to verify this is a valid CloudShark system.")
           cs_display_help()

        end
    end
end

function cs_check_config()

     -- make sure the configuration file exists
     local confFile = cs_config_name()
     if cs_file_exists(confFile) == false then
        error("The CloudShark plugin configuration file does not exist.")
     end

     -- load in the current config
     cs_load_config()

     -- check required parameters
     if CLOUDSHARK_URL == nill or CLOUDSHARK_URL == "" then
        error("CLOUDSHARK_URL is missing or not set")
     end

     -- must have an API key
     if CLOUDSHARK_API_KEY == nill or CLOUDSHARK_API_KEY == "" then
        error("CLOUDSHARK_API_KEY is missing or not set")
     end

     -- make sure we found curl
     if cs_check_curl() == false then
        error("curl was not found on this system")
     end
end

function cloudshark_dialog_win()

    -- first check configuration
    local configOk, message = pcall( cs_check_config )

    if configOk then

        -- config was okay, proceed
        local check_cap = nil

        -- check that the capture file has been created
        if capfile ~= nil then
           check_cap = io.open(capfile,"r")
        end

        if check_cap == nil then
            cs_win = TextWindow.new("CloudShark")	
            cs_win:append("Please create or load a capture file first!\n\n")
            cs_win:append("For more help on using the CloudShark plugin, ")
            cs_win:append("please visit:\n\nhttp://appliance.cloudshark.org\n")
        else

           -- we have a capture file, so close it
           check_cap:close()

           -- start the upload dialog
           new_dialog("Send to CloudShark",cloudshark_do_upload,"Additional Tags (optional)", "Capture Name (optional)")

        end
    else
        cs_win = TextWindow.new("CloudShark")	
        cs_display_config_error(message)
    end
end

function cloudshark_import_win()
   new_dialog("Import from CloudShark", cloudshark_do_import, "CloudShark Session ID (ex. f62e1db77ba0)")
end

-- Start 

-- some defaults for the plugin

-- capture_filename is used to store the name for the current capture file
capture_filename = ""

-- upload_count will be used to track the total number of attempted uploads
upload_count = 0
cs_last_id = 0

-- load the initial CloudShark Plugin config file
initialConfig, msg = pcall(cs_load_config)

-- start any loading if we are in debug mode i.e. CLOUDSHARK_DEBUG = "1"
cs_log_start()

-- Don't use the first os.tmpname(). Just call os.tmpname() and ignore the result.
-- We do this since some Windows flavors will allocate the first name ending in '.'
-- which looks a bit off for a filename.
cs_temp_file("")

-- Start some logging when debug is enabled
cdebug(string.format("Wireshark version %s", get_version()))
cdebug(string.format("The log dir is %s", cs_log_dir()))

-- the CLOUDSHARK_ENABLE variable can be y | n
if CLOUDSHARK_ENABLE ~= nil and CLOUDSHARK_ENABLE == "n" then

   -- we don't want to run the plugin, just return
   return
end

if gui_enabled() == true then

   cdebug("Running in Wireshark GUI mode")

   -- Add new menu items to WireShark under the Tools menu
   register_menu( "CloudShark/About",        cloudshark_about_win,   MENU_TOOLS_UNSORTED)
   register_menu( "CloudShark/Preferences",  cloudshark_prefs_win,   MENU_TOOLS_UNSORTED)
   register_menu( "CloudShark/Upload",       cloudshark_dialog_win,  MENU_TOOLS_UNSORTED)

else

   -- handle tshark mode, first check that tshark support is desired
   cdebug("Running in tshark non-GUI mode")

   -- the CLOUDSHARK_TSHARK variable can be n | y | prompt
   if CLOUDSHARK_TSHARK == nil or CLOUDSHARK_TSHARK == "n" then

      -- we don't want to run with tshark, just return
      return
   end

   -- check the config in tshark mode
   local configOk, message = pcall( cs_check_config )
   if configOk == false then

      -- display the standard config error message
      cs_display_config_error(message)

      -- we exit completely here when there is a config error
      os.exit()
   end

   -- display version info
   dofile(string.format("%s/version.lua", cs_log_dir()))
   print(string.format("CloudShark plugin for WireShark (c) %s", cloudshark_year))
   print(string.format("Version %s", cloudshark_plugin_version))
   print("Developed by QA Cafe")

   -- by default, we will prompt for CloudShark, unless 
   if CLOUDSHARK_TSHARK == "y" then
      cloudshark_prompt = false
   elseif CLOUDSHARK_TSHARK == "prompt" then
      cloudshark_prompt = true
   else
      error(string.format("ERROR: Bad value '%s'for CLOUDSHARK_TSHARK. Should be n, y, or prompt", CLOUDSHARK_TSHARK))
   end

end

--
-- Create and register a new tap listener.
--

do
   capfile = nil
   dump = nil
           
   local function init_listener()

      -- create a new listener        
      local tap = Listener.new()

      function tap.packet(pinfo,tvb,ip)
           if not dump then

               -- create a new temp file name
               capfile = cs_temp_file("cap")

               -- create a new dumper
               dump = Dumper.new_for_current(capfile)		
            end

            -- dump the current packet to the dumper file
            dump:dump_current()

            -- flush the dumper file
            dump:flush()
       end

       function tap.draw()

          if dump then
             -- just flush the dump file
             dump:flush()
          end

          -- handle tshark mode. For tshark, this is where the upload is triggered
          if gui_enabled() == false then

             -- default to uploading automatically
             local result = "y"
             local additional_tags = ""
             local upload_filename = ""
             local check_cap = nil

             -- check that the capture file has been created
	     if capfile ~= nil then
                 check_cap = io.open(capfile,"r")
             end

	     if check_cap == nil then
                 cdebug("Skipping CloudShark upload since capture file is empty")
                 return
             else
                 -- we have a capture file, so close it
                 check_cap:close()
             end

             -- reload the config
             cs_load_config()

             -- prompt user
             if cloudshark_prompt == true then
                 result = cs_prompt(string.format("Send to CloudShark via %s? (y|n=default) ", CLOUDSHARK_URL))

                 -- don't prompt for the rest if we are not uploading
                 if result == "y" then
                     additional_tags = cs_prompt("Additional Tags? (optional) ")
                     upload_filename = cs_prompt("Capture Name? (optional) ")
                 end
             end

             if result == "y" then
                 print(string.format("\nUploading capture file to CloudShark via %s", CLOUDSHARK_URL))

                 -- start the upload
                 cloudshark_do_upload(additional_tags,upload_filename)
             end

             -- clean up the capture file here in tshark (non-gui) mode
             if capfile ~= nil then
                 os.remove(capfile)
             end

          end
       end

       function tap.reset()
          if dump then

             -- close the dump file
             dump:close()

             -- delete any existing capture file
             os.remove(capfile)
          end

           -- mark the dump as nil, how does dump free resources?
           dump = nil
        end
    end

    -- Call the init function to get things started.
    init_listener()

end
