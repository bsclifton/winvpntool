# winvpntool
Simple Windows VPN configuration tool (using RAS API)

This repo was put together to demonstrate the Windows API calls needed to enum entries/devices/connections and also create/remove/connect to entries. 
I tried to link back to the MSDN documentation where possible and document non-obvious findings. The compiled binary does function as a standalone executable.

On Windows 10, you can view your VPNs by opening Settings (bottom right corner of screen) and opening the VPN control panel. The calls here will update the status there in realtime.
For creating entries, this code is defaulting to a policy which works on an IKEv2 connection and has a hard-coded policy in place.

## Command line usage
### Print details about existing entries and connections
- `winvpntool.exe --connections`
- `winvpntool.exe --devices`
- `winvpntool.exe --entries`

### Create, connect to, and remove a VPN entry
- `winvpntool.exe --create MYVPN1 test.domain-name-here.com bubba Password1!`
- `winvpntool.exe --connect MYVPN1`
- `winvpntool.exe --remove MYVPN1`
