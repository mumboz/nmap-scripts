local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
Checks for the presence of a PrusaLink service and looks for its version number.

PrusaLink is embedded on certain Prusa 3D printers to allow some amount of remote management of the printer.
]]

---
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | PrusaLink v.3.12.0

author = "Rasmus Sandfeld Kristensen"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.portnumber(80)

action = function(host, port)
  -- Get root page
  stdnse.debug("Retrieving %s:%s/...", host.ip, port.number)
  local result = http.get(host, port, "/") 
  if not (result and result.status) then
    stdnse.debug("Failed to retrieve page - aborting")
    return nil 
  end

  -- Check for PrusaLink in html title
  if not string.find(result.body, "<title.-PrusaLink.-</title>") then
    stdnse.debug("'PrusaLink' not found in html title - aborting")
    return nil
  end
  
  -- Look for 'main.*.js' source file name in html source
  local i, j = string.find(result.body, "main%..-%.js")
  if not i then
    stdnse.debug("No 'main.<something>.js' found in html source - aborting")
    return nil
  end
  local srcFile = string.sub(result.body, i, j)
  
  -- Download the .js file
  stdnse.debug("Retrieving %s:%s/%s...", host.ip, port.number, srcFile)
  local jsFileResult = http.get(host, port, "/" .. srcFile)
  if not (jsFileResult and jsFileResult.status) then
    stdnse.debug("Failed to retrieve .js file - aborting")
    return nil 
  end
  
  -- Look for PrusaLink version in the .js file
  i,j = string.find(jsFileResult.body, "PrusaLink%sv%.[%d%.]*")
  if not i then
    stdnse.debug("Failed to find PrusaLink version in .js file - aborting")
    return nil  
  end
  local prusaLinkVersion = string.sub(jsFileResult.body, i, j)
  
  return prusaLinkVersion
end
