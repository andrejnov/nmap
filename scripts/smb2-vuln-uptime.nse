local smb = require "smb"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"
local smb2 = require "smb2"

description = [[
Attempts to detect missing patches in Windows systems by checking the
uptime returned during SMB2's protocol negotiation process. 

SMB2's protocol negotiation the system boot time is returned pre-authentication.
This information can be used to determine if a system is missing critical
patches without triggering IDS/IPS/AVs.
]]

---
-- @usage nmap -p445 --script smb2-vuln-uptime <target>
-- @usage nmap -p445 --script vuln <target>
--
-- @output
--
-- @xmloutput
---

author = "Paulino Calderon <calderon()websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

local ms_vulns = {
  {
    title = 'MS17-010: Security update for Windows SMB Server',
    ids = {ms = "ms17-010", CVE = "2017-0147"},
    desc = [[
This system is missing a security update that resolves vulnerabilities in
 Microsoft Windows SMB Server.
]],
    disclosure_time = 1489471200,
    disclosure_date = {year=2017, month=3, day=14},
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms17-010.aspx',
    },
  },
  {
    title = 'Microsoft Kerberos Checksum Vulnerability',
    ids = {ms = "ms14-068", CVE = "2014-6324"},
    desc = [[
This security update resolves a privately reported vulnerability in Microsoft
 Windows Kerberos KDC that could allow an attacker to elevate unprivileged
 domain user account privileges to those of the domain administrator account.
]],
    disclosure_time = 1416290400,
    disclosure_date = {year=2014, month=11, day=18},
    references = {
      'https://technet.microsoft.com/en-us/library/security/ms14-068.aspx'
    },
  },
}

local function check_vulns(host, port)
  local smbstate, status, overrides
  local vulns_detected = {}

  overrides = {}
  overrides['Dialects'] = {0x0202}
  status, smbstate = smb.start(host)
  status, _ = smb2.negotiate_v2(smbstate, overrides)

  if status then
    stdnse.debug2("SMB2: Date: %s (%s) Start date:%s (%s)",
                        smbstate['date'], smbstate['time'],
            smbstate['start_date'], smbstate['start_time'])

    for _, vuln in pairs(ms_vulns) do
      if smbstate['start_time'] < vuln['disclosure_time'] then 
        stdnse.debug2("Vulnerability detected")
        table.insert(vulns_detected, vuln)
      end
    end

  else
    stdnse.debug2("Negotiation failed")
    return nil, "Protocol negotiation failed (SMB2)"
  end
  return true, vulns_detected
end

action = function(host,port)
  local status, vulnerabilities
  local report = vulns.Report:new(SCRIPT_NAME, host, port)

  status, vulnerabilities = check_vulns(host, port)
  if status then
    for i, v in pairs(vulnerabilities) do
      local vuln = { title = v['title'], description = v['desc'],
            references = v['references'], disclosure_date = v['disclosure_date'],
            IDS = v['ids']}
      vuln.state = vulns.STATE.VULN
      report:add_vulns(SCRIPT_NAME, vuln)
    end
  end
  return report:make_output()
end
