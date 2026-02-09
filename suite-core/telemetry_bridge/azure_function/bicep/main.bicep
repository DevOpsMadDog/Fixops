@description('Location for all resources')
param location string = resourceGroup().location

@description('Prefix for resource names')
param prefix string = 'fixops'

@description('Path to fixops.overlay.yml')
param overlayPath string = '../../../config/fixops.overlay.yml'

@description('FixOps API key for authentication')
@secure()
param fixopsApiKey string

@description('Tags to apply to all resources')
param tags object = {
  Project: 'FixOps'
  Component: 'TelemetryBridge'
  ManagedBy: 'Bicep'
}

// Load overlay configuration
var overlayData = loadYamlContent(overlayPath)
var telemetryConfig = overlayData.telemetry_bridge
var azureConfig = telemetryConfig.azure
var retentionDays = telemetryConfig.retention_days

// Storage account for Function App
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: '${prefix}telemetrysa'
  location: azureConfig.location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
  tags: tags
}

// Evidence storage account with lifecycle management
resource evidenceStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: azureConfig.storage_account
  location: azureConfig.location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    accessTier: 'Hot'
  }
  tags: tags
}

// Blob lifecycle management for evidence storage
resource lifecyclePolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2023-01-01' = {
  parent: evidenceStorage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          name: 'raw-logs-lifecycle'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['raw/']
            }
            actions: {
              baseBlob: {
                tierToCool: {
                  daysAfterModificationGreaterThan: retentionDays.raw
                }
                delete: {
                  daysAfterModificationGreaterThan: retentionDays.raw + 7
                }
              }
            }
          }
        }
        {
          name: 'summary-logs-lifecycle'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['summary/']
            }
            actions: {
              baseBlob: {
                tierToCool: {
                  daysAfterModificationGreaterThan: retentionDays.summary
                }
                delete: {
                  daysAfterModificationGreaterThan: retentionDays.summary + 30
                }
              }
            }
          }
        }
        {
          name: 'evidence-bundles-lifecycle'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['evidence/']
            }
            actions: {
              baseBlob: {
                tierToCool: {
                  daysAfterModificationGreaterThan: 90
                }
                tierToArchive: {
                  daysAfterModificationGreaterThan: 180
                }
              }
            }
          }
        }
      ]
    }
  }
}

// Key Vault for secrets
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: azureConfig.key_vault_name
  location: azureConfig.location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
  }
  tags: tags
}

// Store FixOps API key in Key Vault
resource apiKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'fixops-api-key'
  properties: {
    value: fixopsApiKey
  }
}

// Event Hub namespace
resource eventHubNamespace 'Microsoft.EventHub/namespaces@2023-01-01-preview' = {
  name: '${prefix}-telemetry-ns'
  location: azureConfig.location
  sku: {
    name: 'Standard'
    tier: 'Standard'
    capacity: 1
  }
  properties: {
    minimumTlsVersion: '1.2'
  }
  tags: tags
}

// Event Hub
resource eventHub 'Microsoft.EventHub/namespaces/eventhubs@2023-01-01-preview' = {
  parent: eventHubNamespace
  name: azureConfig.event_hub
  properties: {
    messageRetentionInDays: 1
    partitionCount: 2
  }
}

// Event Hub consumer group
resource consumerGroup 'Microsoft.EventHub/namespaces/eventhubs/consumergroups@2023-01-01-preview' = {
  parent: eventHub
  name: 'fixops-telemetry'
}

// App Service Plan for Function App
resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: '${prefix}-telemetry-plan'
  location: azureConfig.location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
  tags: tags
}

// Application Insights
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-telemetry-insights'
  location: azureConfig.location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    RetentionInDays: retentionDays.summary
  }
  tags: tags
}

// Function App
resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: '${prefix}-telemetry-function'
  location: azureConfig.location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.11'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsights.properties.InstrumentationKey
        }
        {
          name: 'EventHubConnection'
          value: listKeys('${eventHubNamespace.id}/authorizationRules/RootManageSharedAccessKey', eventHubNamespace.apiVersion).primaryConnectionString
        }
        {
          name: 'EventHubName'
          value: eventHub.name
        }
        {
          name: 'FIXOPS_OVERLAY_PATH'
          value: '/home/site/wwwroot/config/fixops.overlay.yml'
        }
        {
          name: 'FIXOPS_API_KEY'
          value: '@Microsoft.KeyVault(SecretUri=${apiKeySecret.properties.secretUri})'
        }
      ]
    }
    httpsOnly: true
  }
  tags: tags
}

// Grant Function App access to Key Vault
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: keyVault
  name: guid(keyVault.id, functionApp.id, 'Key Vault Secrets User')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6') // Key Vault Secrets User
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Grant Function App access to evidence storage
resource storageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: evidenceStorage
  name: guid(evidenceStorage.id, functionApp.id, 'Storage Blob Data Contributor')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe') // Storage Blob Data Contributor
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output functionAppName string = functionApp.name
output eventHubNamespace string = eventHubNamespace.name
output eventHubName string = eventHub.name
output storageAccountName string = evidenceStorage.name
output keyVaultName string = keyVault.name
output functionAppIdentity string = functionApp.identity.principalId
