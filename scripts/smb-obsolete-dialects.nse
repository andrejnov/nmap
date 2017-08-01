local smb = require "smb"
local smb2 = require "smb2"
local stdnse = require "stdnse"
local string = require "string"
local bit = require "bit"
local table = require "table"
local nmap = require "nmap"

description = [[
Attempts to list the supported capabilities in a SMBv2 server for each
 enabled dialect.

The script sends a SMB2_COM_NEGOTIATE command and parses the response
 using the SMB dialects:
* 2.02
* 2.10
* 3.00
* 3.02
* 3.11
]]

---
-- @usage nmap -p 445 --script smb2-capabilities <target>
-- @usage nmap -p 139 --script smb2-capabilities <target>
--
-- @output
-- | smb2-capabilities: 
-- |   2.02: 
-- |     Distributed File System
-- |   2.10: 
-- |     Distributed File System
-- |     Leasing
-- |     Multi-credit operations
--
-- @xmloutput
-- <table key="2.02">
-- <elem>Distributed File System</elem>
-- </table>
-- <table key="2.10">
-- <elem>Distributed File System</elem>
-- <elem>Leasing</elem>
-- <elem>Multi-credit operations</elem>
-- </table>
---

author = "Paulino Calderon"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host,port)
  local status, smbstate, overrides 
  local output = stdnse.output_table()
  overrides = {}

  local smb_dialects = {"PC NETWORK PROGRAM 1.0", "XENIX CORE", 
                        "MICROSOFT NETWORKS 1.03", "LANMAN1.0",
                        "Windows for Workgroups 3.1a", "LM1.2X002",
                        "LANMAN2.1"}

  for i, dialect in pairs(smb_dialects) do
    -- we need a clean connection for each negotiate request
    status, smbstate = smb.start(host)
    if(status == false) then
      return false, smbstate
    end
    -- We set our overrides Dialects table with the dialect we are testing
    overrides['dialect'] = dialect
    status, _ = smb.negotiate_v1(smbstate, overrides)
    if status then
      stdnse.debug2("Dialect accepted:%s", dialect)
      table.insert(output, dialect)
    end
    smb.stop(smbstate)
    status = false
  end

    if #output>0 then
      return output
    else
      stdnse.debug1("No dialects were accepted.")
      if nmap.verbosity()>1 then
        return "Couldn't establish a SMBv1 connection."
      end
    end
end
