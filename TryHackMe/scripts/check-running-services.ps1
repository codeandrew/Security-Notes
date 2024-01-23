# Get all running services
$services = Get-Service | Where-Object { $_.Status -eq "Running" }

# Initialize empty arrays for Microsoft and Non-Microsoft services
$msftServices = @()
$nonMsftServices = @()

# Loop through each running service
foreach ($service in $services) {
    # Check if the service is a Microsoft service
    if ($service.Name -like "Microsoft*") {
        # Add to Microsoft services table
        $msftServices += [PSCustomObject]@{
            "Microsoft Service" = $service.Name
            "Binary Path" = $service.PathName
            "Description" = $service.Description
        }
    }
    else {
        # Add to Non-Microsoft services table
        $nonMsftServices += [PSCustomObject]@{
            "Non-Microsoft Service" = $service.Name
            "Binary Path" = $service.PathName
            "Description" = $service.Description
        }
    }
}

# Display Microsoft services table
Write-Host "Microsoft Services"
$msftServices | Format-Table

# Display Non-Microsoft services table
Write-Host "Non-Microsoft Services"
$nonMsftServices | Format-Table
