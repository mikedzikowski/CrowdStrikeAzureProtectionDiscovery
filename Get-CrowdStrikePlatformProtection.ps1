# Azure Resource Protection Mapping Script
# This script identifies Azure resources and maps them to CrowdStrike protection capabilities

# Ensure Az CLI is installed and logged in
Write-Host "Checking Az CLI login status..." -ForegroundColor Cyan
try {
    $loginStatus = az account show 2>$null
    if (-not $loginStatus) {
        Write-Host "Please login to Azure CLI first using 'az login'" -ForegroundColor Red
        exit
    }
}
catch {
    Write-Host "Error checking login status: $_" -ForegroundColor Red
    Write-Host "Please ensure Az CLI is installed and run 'az login'" -ForegroundColor Red
    exit
}

Write-Host "Azure CLI is logged in. Proceeding with resource discovery..." -ForegroundColor Green

# Initialize results array
$results = @()

# Function to safely execute Az CLI commands with error handling
function Invoke-AzCommand {
    param (
        [string]$Command,
        [string]$ErrorMessage
    )
    
    try {
        $output = Invoke-Expression $Command 2>$null
        return $output | ConvertFrom-Json
    }
    catch {
        Write-Host "$($ErrorMessage): $_" -ForegroundColor Yellow
        return $null
    }
}

# Get all subscriptions
$subscriptions = Invoke-AzCommand -Command "az account list --query '[].{Name:name, Id:id}' -o json" -ErrorMessage "Error retrieving subscriptions"
if (-not $subscriptions) {
    Write-Host "No subscriptions found or error occurred. Exiting." -ForegroundColor Red
    exit
}

Write-Host "Found $($subscriptions.Count) subscription(s)" -ForegroundColor Cyan

foreach ($subscription in $subscriptions) {
    Write-Host "Processing subscription: $($subscription.Name)" -ForegroundColor Yellow
    az account set --subscription $subscription.Id

    # Check for Entra ID (formerly Azure AD)
    Write-Host "Checking for Entra ID..." -ForegroundColor Cyan
    $entraID = Invoke-AzCommand -Command "az ad signed-in-user show" -ErrorMessage "Error checking Entra ID"
    if ($entraID) {
        $results += [PSCustomObject]@{
            ResourceType = "Entra ID"
            ResourceName = "Entra ID"
            ResourceGroup = ""
            Subscription = $subscription.Name
            ProtectionCapabilities = "CIEM, SSPM"
        }
    }

    # Get Virtual Machines (IaaS workloads)
    Write-Host "Finding Virtual Machines..." -ForegroundColor Cyan
    $vms = Invoke-AzCommand -Command "az vm list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving VMs"
    if ($vms) {
        foreach ($vm in $vms) {
            $results += [PSCustomObject]@{
                ResourceType = "Virtual Machine"
                ResourceName = $vm.Name
                ResourceGroup = $vm.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "EDR, CSPM, CIEM"
            }
        }
    }

    # Get Virtual Machine Scale Sets
    Write-Host "Finding Virtual Machine Scale Sets..." -ForegroundColor Cyan
    $vmss = Invoke-AzCommand -Command "az vmss list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving VM Scale Sets"
    if ($vmss) {
        foreach ($scaleSet in $vmss) {
            $results += [PSCustomObject]@{
                ResourceType = "Virtual Machine Scale Set"
                ResourceName = $scaleSet.Name
                ResourceGroup = $scaleSet.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "EDR, CSPM, CIEM"
            }
        }
    }

    # Get AKS Clusters
    Write-Host "Finding AKS Clusters..." -ForegroundColor Cyan
    $aksClusters = Invoke-AzCommand -Command "az aks list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving AKS clusters"
    if ($aksClusters) {
        foreach ($cluster in $aksClusters) {
            $results += [PSCustomObject]@{
                ResourceType = "Kubernetes"
                ResourceName = $cluster.Name
                ResourceGroup = $cluster.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "EDR, CSPM, CIEM, Image Assessment, Kubernetes Admission Controller"
            }
        }
    }

    # Get Storage Accounts (data stores)
    Write-Host "Finding Storage Accounts..." -ForegroundColor Cyan
    $storageAccounts = Invoke-AzCommand -Command "az storage account list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving storage accounts"
    if ($storageAccounts) {
        foreach ($storage in $storageAccounts) {
            $results += [PSCustomObject]@{
                ResourceType = "Storage Account"
                ResourceName = $storage.Name
                ResourceGroup = $storage.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, DSPM"
            }
        }
    }

    # Get SQL Servers and Databases
    Write-Host "Finding SQL Databases..." -ForegroundColor Cyan
    $sqlServers = Invoke-AzCommand -Command "az sql server list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving SQL servers"
    if ($sqlServers) {
        foreach ($server in $sqlServers) {
            $databases = Invoke-AzCommand -Command "az sql db list --resource-group $($server.ResourceGroup) --server $($server.Name) --query '[].{Name:name}' -o json" -ErrorMessage "Error retrieving databases for server $($server.Name)"
            if ($databases) {
                foreach ($db in $databases) {
                    $results += [PSCustomObject]@{
                        ResourceType = "SQL Database"
                        ResourceName = "$($server.Name)/$($db.Name)"
                        ResourceGroup = $server.ResourceGroup
                        Subscription = $subscription.Name
                        ProtectionCapabilities = "CSPM, DSPM"
                    }
                }
            }
        }
    }

    # Get SQL Server (as a separate resource)
    if ($sqlServers) {
        foreach ($server in $sqlServers) {
            $results += [PSCustomObject]@{
                ResourceType = "SQL Server"
                ResourceName = $server.Name
                ResourceGroup = $server.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get App Services
    Write-Host "Finding App Services..." -ForegroundColor Cyan
    $appServices = Invoke-AzCommand -Command "az webapp list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving app services"
    if ($appServices) {
        foreach ($app in $appServices) {
            $results += [PSCustomObject]@{
                ResourceType = "App Service"
                ResourceName = $app.Name
                ResourceGroup = $app.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, ASPM"
            }
        }
    }

    # Get Azure Functions
    Write-Host "Finding Azure Functions..." -ForegroundColor Cyan
    $functions = Invoke-AzCommand -Command "az functionapp list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Azure Functions"
    if ($functions) {
        foreach ($function in $functions) {
            $results += [PSCustomObject]@{
                ResourceType = "Azure Function"
                ResourceName = $function.Name
                ResourceGroup = $function.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, ASPM"
            }
        }
    }

    # Get Container Instances
    Write-Host "Finding Container Instances..." -ForegroundColor Cyan
    $containerInstances = Invoke-AzCommand -Command "az container list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving container instances"
    if ($containerInstances) {
        foreach ($container in $containerInstances) {
            $results += [PSCustomObject]@{
                ResourceType = "Container Instance"
                ResourceName = $container.Name
                ResourceGroup = $container.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "EDR, CSPM, Image Assessment"
            }
        }
    }

    # Get Container Registries - Updated with EDR, Image Assessment, CSPM
    Write-Host "Finding Container Registries..." -ForegroundColor Cyan
    $containerRegistries = Invoke-AzCommand -Command "az acr list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving container registries"
    if ($containerRegistries) {
        foreach ($registry in $containerRegistries) {
            $results += [PSCustomObject]@{
                ResourceType = "Container Registry"
                ResourceName = $registry.Name
                ResourceGroup = $registry.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "EDR, CSPM, Image Assessment"
            }
        }
    }

    # Get Container Apps - Added with EDR
    Write-Host "Finding Container Apps..." -ForegroundColor Cyan
    try {
        # First check if the extension is installed
        $extensionCheck = az extension show --name containerapp 2>&1
        if ($extensionCheck -like "*not installed*") {
            Write-Host "Container Apps extension not installed. Attempting to install..." -ForegroundColor Yellow
            az extension add --name containerapp --yes 2>$null
        }
        
        # Now try to list container apps
        $containerApps = Invoke-AzCommand -Command "az containerapp list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving container apps"
        if ($containerApps) {
            foreach ($app in $containerApps) {
                $results += [PSCustomObject]@{
                    ResourceType = "Container Apps"
                    ResourceName = $app.Name
                    ResourceGroup = $app.ResourceGroup
                    Subscription = $subscription.Name
                    ProtectionCapabilities = "EDR, CSPM, Image Assessment"
                }
            }
        }
    }
    catch {
        Write-Host "Container Apps may not be available in your environment: $_" -ForegroundColor Yellow
        
        # Fallback to generic resource search
        try {
            $containerAppsGeneric = Invoke-AzCommand -Command "az resource list --resource-type Microsoft.App/containerApps --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving container apps with generic method"
            
            if ($containerAppsGeneric) {
                foreach ($app in $containerAppsGeneric) {
                    $results += [PSCustomObject]@{
                        ResourceType = "Container Apps"
                        ResourceName = $app.Name
                        ResourceGroup = $app.ResourceGroup
                        Subscription = $subscription.Name
                        ProtectionCapabilities = "EDR, CSPM, Image Assessment"
                    }
                }
            }
        }
        catch {
            Write-Host "Container Apps could not be detected with fallback method" -ForegroundColor Yellow
        }
    }

    # Get Key Vaults
    Write-Host "Finding Key Vaults..." -ForegroundColor Cyan
    $keyVaults = Invoke-AzCommand -Command "az keyvault list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving key vaults"
    if ($keyVaults) {
        foreach ($vault in $keyVaults) {
            $results += [PSCustomObject]@{
                ResourceType = "Key Vault"
                ResourceName = $vault.Name
                ResourceGroup = $vault.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, CIEM"
            }
        }
    }

    # Get Cosmos DB
    Write-Host "Finding Cosmos DB..." -ForegroundColor Cyan
    $cosmosDBs = Invoke-AzCommand -Command "az cosmosdb list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Cosmos DB"
    if ($cosmosDBs) {
        foreach ($cosmosDB in $cosmosDBs) {
            $results += [PSCustomObject]@{
                ResourceType = "Cosmos DB"
                ResourceName = $cosmosDB.Name
                ResourceGroup = $cosmosDB.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, DSPM"
            }
        }
    }

    # Get Azure Firewall
    Write-Host "Finding Azure Firewalls..." -ForegroundColor Cyan
    $firewalls = Invoke-AzCommand -Command "az network firewall list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Azure Firewalls"
    if ($firewalls) {
        foreach ($firewall in $firewalls) {
            $results += [PSCustomObject]@{
                ResourceType = "Azure Firewall"
                ResourceName = $firewall.Name
                ResourceGroup = $firewall.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Network Security Groups
    Write-Host "Finding Network Security Groups..." -ForegroundColor Cyan
    $nsgs = Invoke-AzCommand -Command "az network nsg list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving NSGs"
    if ($nsgs) {
        foreach ($nsg in $nsgs) {
            $results += [PSCustomObject]@{
                ResourceType = "Network Security Group"
                ResourceName = $nsg.Name
                ResourceGroup = $nsg.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Virtual Networks
    Write-Host "Finding Virtual Networks..." -ForegroundColor Cyan
    $vnets = Invoke-AzCommand -Command "az network vnet list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Virtual Networks"
    if ($vnets) {
        foreach ($vnet in $vnets) {
            $results += [PSCustomObject]@{
                ResourceType = "Virtual Network"
                ResourceName = $vnet.Name
                ResourceGroup = $vnet.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Load Balancers
    Write-Host "Finding Load Balancers..." -ForegroundColor Cyan
    $lbs = Invoke-AzCommand -Command "az network lb list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Load Balancers"
    if ($lbs) {
        foreach ($lb in $lbs) {
            $results += [PSCustomObject]@{
                ResourceType = "Load Balancer"
                ResourceName = $lb.Name
                ResourceGroup = $lb.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Application Gateways
    Write-Host "Finding Application Gateways..." -ForegroundColor Cyan
    $appGateways = Invoke-AzCommand -Command "az network application-gateway list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Application Gateways"
    if ($appGateways) {
        foreach ($gateway in $appGateways) {
            $results += [PSCustomObject]@{
                ResourceType = "Application Gateway"
                ResourceName = $gateway.Name
                ResourceGroup = $gateway.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get PostgreSQL servers
    Write-Host "Finding PostgreSQL Servers..." -ForegroundColor Cyan
    $postgreSQLServers = Invoke-AzCommand -Command "az postgres server list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving PostgreSQL servers"
    if ($postgreSQLServers) {
        foreach ($server in $postgreSQLServers) {
            $results += [PSCustomObject]@{
                ResourceType = "PostgreSQL"
                ResourceName = $server.Name
                ResourceGroup = $server.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, DSPM"
            }
        }
    }

    # Get MySQL servers
    Write-Host "Finding MySQL Servers..." -ForegroundColor Cyan
    $mySQLServers = Invoke-AzCommand -Command "az mysql server list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving MySQL servers"
    if ($mySQLServers) {
        foreach ($server in $mySQLServers) {
            $results += [PSCustomObject]@{
                ResourceType = "MySQL"
                ResourceName = $server.Name
                ResourceGroup = $server.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, DSPM"
            }
        }
    }

    # Get MariaDB servers
    Write-Host "Finding MariaDB Servers..." -ForegroundColor Cyan
    $mariaDBServers = Invoke-AzCommand -Command "az mariadb server list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving MariaDB servers"
    if ($mariaDBServers) {
        foreach ($server in $mariaDBServers) {
            $results += [PSCustomObject]@{
                ResourceType = "MariaDB"
                ResourceName = $server.Name
                ResourceGroup = $server.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, DSPM"
            }
        }
    }

    # Get Event Hubs
    Write-Host "Finding Event Hubs..." -ForegroundColor Cyan
    $eventHubs = Invoke-AzCommand -Command "az eventhubs namespace list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Event Hubs"
    if ($eventHubs) {
        foreach ($hub in $eventHubs) {
            $results += [PSCustomObject]@{
                ResourceType = "Event Hub"
                ResourceName = $hub.Name
                ResourceGroup = $hub.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Front Door
    Write-Host "Finding Front Door..." -ForegroundColor Cyan
    $frontDoors = Invoke-AzCommand -Command "az network front-door list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Front Door"
    if ($frontDoors) {
        foreach ($fd in $frontDoors) {
            $results += [PSCustomObject]@{
                ResourceType = "Front Door"
                ResourceName = $fd.Name
                ResourceGroup = $fd.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Azure OpenAI
    Write-Host "Finding Azure OpenAI Services..." -ForegroundColor Cyan
    $openAIServices = Invoke-AzCommand -Command "az cognitiveservices account list --query '[?kind==''OpenAI''].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Azure OpenAI services"
    if ($openAIServices) {
        foreach ($service in $openAIServices) {
            $results += [PSCustomObject]@{
                ResourceType = "OpenAI"
                ResourceName = $service.Name
                ResourceGroup = $service.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Service Fabric clusters
    Write-Host "Finding Service Fabric Clusters..." -ForegroundColor Cyan
    $serviceFabricClusters = Invoke-AzCommand -Command "az sf cluster list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Service Fabric clusters"
    if ($serviceFabricClusters) {
        foreach ($cluster in $serviceFabricClusters) {
            $results += [PSCustomObject]@{
                ResourceType = "Service Fabric"
                ResourceName = $cluster.Name
                ResourceGroup = $cluster.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Synapse workspaces
    Write-Host "Finding Synapse Workspaces..." -ForegroundColor Cyan
    $synapseWorkspaces = Invoke-AzCommand -Command "az synapse workspace list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Synapse workspaces"
    if ($synapseWorkspaces) {
        foreach ($workspace in $synapseWorkspaces) {
            $results += [PSCustomObject]@{
                ResourceType = "Synapse"
                ResourceName = $workspace.Name
                ResourceGroup = $workspace.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, DSPM"
            }
        }
    }

    # Get Azure Arc servers
    Write-Host "Finding Azure Arc Servers..." -ForegroundColor Cyan
    $arcServers = Invoke-AzCommand -Command "az connectedmachine list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Azure Arc servers"
    if ($arcServers) {
        foreach ($server in $arcServers) {
            $results += [PSCustomObject]@{
                ResourceType = "Azure Arc"
                ResourceName = $server.Name
                ResourceGroup = $server.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "EDR, CSPM, CIEM"
            }
        }
    }

    # Get Azure Machine Learning workspaces
    Write-Host "Finding Azure Machine Learning Workspaces..." -ForegroundColor Cyan
    $mlWorkspaces = Invoke-AzCommand -Command "az ml workspace list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Machine Learning workspaces"
    if ($mlWorkspaces) {
        foreach ($workspace in $mlWorkspaces) {
            $results += [PSCustomObject]@{
                ResourceType = "Azure Machine Learning"
                ResourceName = $workspace.Name
                ResourceGroup = $workspace.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get CDN profiles
    Write-Host "Finding CDN Profiles..." -ForegroundColor Cyan
    $cdnProfiles = Invoke-AzCommand -Command "az cdn profile list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving CDN profiles"
    if ($cdnProfiles) {
        foreach ($profile in $cdnProfiles) {
            $results += [PSCustomObject]@{
                ResourceType = "CDN"
                ResourceName = $profile.Name
                ResourceGroup = $profile.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Defender for Cloud
    Write-Host "Finding Defender for Cloud..." -ForegroundColor Cyan
    try {
        $defenderStatus = Invoke-AzCommand -Command "az security auto-provisioning-setting list --query '[0].{Name:name}' -o json" -ErrorMessage "Error retrieving Defender for Cloud status"
        if ($defenderStatus) {
            $results += [PSCustomObject]@{
                ResourceType = "Defender for Cloud"
                ResourceName = "Defender for Cloud"
                ResourceGroup = ""
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }
    catch {
        Write-Host "Defender for Cloud may not be configured: $_" -ForegroundColor Yellow
    }

    # Get Disks
    Write-Host "Finding Disks..." -ForegroundColor Cyan
    $disks = Invoke-AzCommand -Command "az disk list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving disks"
    if ($disks) {
        foreach ($disk in $disks) {
            $results += [PSCustomObject]@{
                ResourceType = "Disk"
                ResourceName = $disk.Name
                ResourceGroup = $disk.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get DNS zones
    Write-Host "Finding DNS Zones..." -ForegroundColor Cyan
    $dnsZones = Invoke-AzCommand -Command "az network dns zone list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving DNS zones"
    if ($dnsZones) {
        foreach ($zone in $dnsZones) {
            $results += [PSCustomObject]@{
                ResourceType = "DNS"
                ResourceName = $zone.Name
                ResourceGroup = $zone.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Monitor components (Log Analytics workspaces)
    Write-Host "Finding Monitor Components (Log Analytics)..." -ForegroundColor Cyan
    $logAnalytics = Invoke-AzCommand -Command "az monitor log-analytics workspace list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Log Analytics workspaces"
    if ($logAnalytics) {
        foreach ($workspace in $logAnalytics) {
            $results += [PSCustomObject]@{
                ResourceType = "Monitor"
                ResourceName = $workspace.Name
                ResourceGroup = $workspace.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Spring Cloud services
    Write-Host "Finding Spring Cloud Services..." -ForegroundColor Cyan
    $springCloud = Invoke-AzCommand -Command "az spring-cloud list --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving Spring Cloud services"
    if ($springCloud) {
        foreach ($service in $springCloud) {
            $results += [PSCustomObject]@{
                ResourceType = "Spring Cloud"
                ResourceName = $service.Name
                ResourceGroup = $service.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM"
            }
        }
    }

    # Get Identity resources (AAD Domain Services)
    Write-Host "Finding AAD Domain Services..." -ForegroundColor Cyan
    $aadDS = Invoke-AzCommand -Command "az resource list --resource-type Microsoft.AAD/domainServices --query '[].{Name:name, ResourceGroup:resourceGroup}' -o json" -ErrorMessage "Error retrieving AAD Domain Services"
    if ($aadDS) {
        foreach ($ds in $aadDS) {
            $results += [PSCustomObject]@{
                ResourceType = "AD Domain Services"
                ResourceName = $ds.Name
                ResourceGroup = $ds.ResourceGroup
                Subscription = $subscription.Name
                ProtectionCapabilities = "CSPM, CIEM, SSPM"
            }
        }
    }
}

# Display results
if ($results.Count -eq 0) {
    Write-Host "`nNo resources found." -ForegroundColor Yellow
}
else {
    Write-Host "`nResource Protection Mapping Results:" -ForegroundColor Green
    $results | Format-Table -AutoSize

    # Export results to CSV
    $csvPath = ".\AzureResourceProtectionMapping_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Results exported to $csvPath" -ForegroundColor Green

    # Summary of protection coverage
    $protectionSummary = @{
        "EDR" = ($results | Where-Object { $_.ProtectionCapabilities -like "*EDR*" }).Count
        "CSPM" = ($results | Where-Object { $_.ProtectionCapabilities -like "*CSPM*" }).Count
        "CIEM" = ($results | Where-Object { $_.ProtectionCapabilities -like "*CIEM*" }).Count
        "SSPM" = ($results | Where-Object { $_.ProtectionCapabilities -like "*SSPM*" }).Count
        "ASPM" = ($results | Where-Object { $_.ProtectionCapabilities -like "*ASPM*" }).Count
        "DSPM" = ($results | Where-Object { $_.ProtectionCapabilities -like "*DSPM*" }).Count
        "Image Assessment" = ($results | Where-Object { $_.ProtectionCapabilities -like "*Image Assessment*" }).Count
        "Kubernetes Admission Controller" = ($results | Where-Object { $_.ProtectionCapabilities -like "*Kubernetes Admission Controller*" }).Count
    }

    Write-Host "`nProtection Coverage Summary:" -ForegroundColor Green
    $protectionSummary.GetEnumerator() | Sort-Object Name | Format-Table @{Label="Protection Type"; Expression={$_.Key}}, @{Label="Resources Covered"; Expression={$_.Value}} -AutoSize

    # Resource type summary
    $resourceTypeSummary = $results | Group-Object -Property ResourceType | Select-Object Name, Count | Sort-Object -Property Name
    
    Write-Host "`nResource Type Summary:" -ForegroundColor Green
    $resourceTypeSummary | Format-Table -AutoSize
}
