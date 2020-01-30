A simple API for haproxy-consul-template lb7 reverse proxy.
## Releases notes :
### v{version_num}: {version_aka}
  - Features
     - NeW ! update fqdn without disruption ! (no more unpublilsh when put)
     - status fqdn is much much more readable now
     - buggyclient option to define also an fqdn:443 for named clients
     - separate api from administrative features
     - impersonate user for support assist
     - ability to delete a certificate

  - Fixes
     - check if fqdn is already defined either http or tcp
     - cleaner api entries structure

  - Code
     - embedded consul-templates templates

### v0.1.25: ABC you and me
  - Features
     - uri /maintenance for AB swap
     - uri pages/releasenotes for this release notes

### v0.1.24: Machine Feedback to the future
 - Fixes
    - bug on certificate publication not effective
    - deploy playbook missed step

### v0.1.23: Machine Feedback
 - Features
    - subdomains option to forward all subdomain requests !
    - Feedback from haproxy when publishing fqdn or certificate ! Check 'message' in json response
    - Backend Stats from haproxy in /fqdn/(fqdn)/hastats
    - Backend Status from haproxy in /fqdn/(fqdn)/status (stats shortened)
 - Fixes
    - Update fqdn with erroneous data that leads to blacklist
    - API on export/import backups
    - A/B canary updates abilities
 - Code
    - Control checks on some parameters
    - Improve logging infos for better bug catching
    - Direct templating instead of event based

### v0.1.22: Cleanup
 - Code
    - full trivia cleanup from first release !