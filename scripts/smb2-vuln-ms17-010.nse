local smb = require "smb"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"
local smb2 = require "smb2"

description = [[
Attempts to detect if a Microsoft SMBv2 server is missing the patch for
ms17-010 by checking if the system has not been rebooted since March 14th, 2017.

SMB2's COM_NEGOTIATE command returns the system boot time pre authentication.
This information can be used to determine if a system is missing critical
patches without triggering IDS/IPS/AVs.

All the credit goes to Matt Kelly (@breakersall) for this great idea!

References:
* https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
* https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
* https://msdn.microsoft.com/en-us/library/ee441489.aspx
* https://twitter.com/breakersall/status/880496571581857793
]]

---
-- @usage nmap -p445 --script smb2-vuln-ms17-010 <target>
-- @usage nmap -p445 --script vuln <target>
--
-- @output
-- Host script results:
-- | smb2-vuln-ms17-010: 
-- |   VULNERABLE:
-- |   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-0143
-- |     Risk factor: HIGH
-- |       A critical remote code execution vulnerability exists in Microsoft SMBv1
-- |        servers (ms17-010).
-- |       
-- |     Disclosure date: 2017-03-14
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
-- |       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
-- |_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
--
-- @xmloutput
-- <table key="CVE-2017-0143">
-- <elem key="title">Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="ids">
-- <elem>CVE:CVE-2017-0143</elem>
-- </table>
-- <table key="description">
-- <elem>A critical remote code execution vulnerability exists in Microsoft SMBv1&#xa; servers (ms17-010).&#xa;</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="month">03</elem>
-- <elem key="year">2017</elem>
-- <elem key="day">14</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2017-03-14</elem>
-- <table key="refs">
-- <elem>https://technet.microsoft.com/en-us/library/security/ms17-010.aspx</elem>
-- <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143</elem>
-- <elem>https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/</elem>
-- </table>
-- </table>
---

author = "Paulino Calderon <calderon()websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

local function check_ms17010(host, port, sharename)
  local smbstate, status, overrides
  overrides = {}
  overrides['Dialects'] = {0x0202}
  status, smbstate = smb.start(host)
  status, _ = smb2.negotiate_v2(smbstate, overrides)
  if status then
    stdnse.debug2("SMB2: Date: %s (%s) Start date:%s (%s)",
                  smbstate['date'], smbstate['time'],
                  smbstate['start_date'], smbstate['start_time'])
    if smbstate['start_time'] < 1489471200 then -- March 14th, 2017
      stdnse.debug2("This system is missing the ms17-010 patch")
      return true
    else
      stdnse.debug2("This system was booted after March 14th, 2017")
      return false, string.format("(Inconclusive test) System boot time: %s", smbstate['start_date'])
    end
  else
    stdnse.debug2("Negotiation failed")
    return nil, "Protocol negotiation failed (SMB2)"
  end

end

action = function(host,port)
  local vuln_status, err
  local vuln = {
    title = "System missing critical patch ms17-010",
    IDS = {CVE = 'CVE-2017-0143'},
    risk_factor = "HIGH",
    description = [[
This system is missing the patch ms17-010 and is affected by remote code 
execution vulnerabilies.
]],
    references = {
    'https://technet.microsoft.com/en-us/library/security/ms17-010.aspx',
    'https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/'
    },
    dates = {
      disclosure = {year = '2017', month = '03', day = '14'},
    }
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln.state = vulns.STATE.NOT_VULN

  vuln_status, err = check_ms17010(host, port)
  if vuln_status then
    vuln.state = vulns.STATE.VULN
  else
    if nmap.verbosity() >=2 then
      return err
    end
  end
  return report:make_output(vuln)
end
