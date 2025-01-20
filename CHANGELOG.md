# Release History

## v1.0.13

> Released: 2025-01-20

- Enhanced `New-RebuiltVsanDatastore` to handle VSAN_MAX clusters correctly
- Added `New-RemountRemoteVsanDatastore` to map previously mounted remote vSAN datastore on compute only cluster

## v1.0.12

> Released: 2024-09-02

- Enhanced `New-ExtractDataFromSDDCBackup` to leverage the vCenter Server backup for additional data.
- Added `New-PartialManagementDomainDeployment` to perform the partial bringup.
- Added support for clusters with multiple vDS.
- Added support for VMware Cloud Foundation 5.2.x.
- Enhanced ` upport for vSAN ESA configurations.
- Enhanced `Remove-NonResponsiveHosts` to resolve handling transport node cleanup in versions of VCF using NSX 3.1.3 or higher.
- Added check to `Confirm-VCFInstanceRecoveryPreReqs` for more than 1 concurrent VI server connections.
- Added documentation for new & updated functions.

## v1.0.10

> Released: 2024-05-29

- Made `New-RebuiltVdsConfigure` more idempotent so that it can be rerun.

## v1.0.9

> Released: 2024-03-27

- Initial release of `VMware.CloudFoundation.InstanceRecovery`.
