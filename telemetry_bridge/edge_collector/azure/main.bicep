@description('Location for all resources')
param location string = resourceGroup().location

@description('Prefix for resource names')
param prefix string = 'fixops'

@description('Path to fixops.overlay.yml')
param overlayPath string = '../../../config/fixops.overlay.yml'

@description('FixOps API key')
@secure()
param fixopsApiKey string

@description('Tags to apply to all resources')
param tags object = {
  project: 'fixops'
  component: 'telemetry-bridge'
  'managed-by': 'bicep'
}

// Load overlay configuration
var overlayData = loadYamlContent(overlayPath)
var telemetryConfig = overlayData.telemetry_bridge
var azureConfig = telemetryConfig.azure
var retentionDays = telemetryConfig.retention_days
var ringBuffer = telemetryConfig.ring_buffer
var fluentbitConfig = telemetryConfig.fluentbit

// Storage account for evidence
resource evidenceStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: azureConfig.storage_account
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
  tags: tags
}

// Blob containers with lifecycle management
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: evidenceStorage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource rawContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'raw'
  properties: {
    publicAccess: 'None'
  }
}

resource summaryContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'summary'
  properties: {
    publicAccess: 'None'
  }
}

resource evidenceContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'evidence'
  properties: {
    publicAccess: 'None'
  }
}

// Lifecycle management policy
resource lifecyclePolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2023-01-01' = {
  parent: evidenceStorage
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          enabled: true
          name: 'raw-logs-retention'
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['raw/']
            }
            actions: {
              baseBlob: {
                delete: {
                  daysAfterModificationGreaterThan: retentionDays.raw
                }
              }
            }
          }
        }
        {
          enabled: true
          name: 'summary-retention'
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: ['summary/']
            }
            actions: {
              baseBlob: {
                delete: {
                  daysAfterModificationGreaterThan: retentionDays.summary
                }
              }
            }
          }
        }
        {
          enabled: true
          name: 'evidence-lifecycle'
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
                delete: {
                  daysAfterModificationGreaterThan: retentionDays.evidence + 365
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
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
  }
  tags: tags
}

// Store FixOps API key in Key Vault
resource fixopsApiKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'fixops-api-key'
  properties: {
    value: fixopsApiKey
  }
}

// Event Hub namespace
resource eventHubNamespace 'Microsoft.EventHub/namespaces@2023-01-01-preview' = {
  name: '${prefix}-eventhub-ns'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Standard'
    capacity: 1
  }
  properties: {
    isAutoInflateEnabled: false
  }
  tags: tags
}

// Event Hub for telemetry
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
  name: 'collector-consumer-group'
}

// Log Analytics workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${prefix}-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionDays.summary
  }
  tags: tags
}

// Container Apps environment
resource containerAppEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: '${prefix}-container-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
    daprAIInstrumentationKey: ''
  }
  tags: tags
}

// Dapr component for Event Hub
resource daprEventHub 'Microsoft.App/managedEnvironments/daprComponents@2023-05-01' = {
  parent: containerAppEnv
  name: 'eventhub-pubsub'
  properties: {
    componentType: 'pubsub.azure.eventhubs'
    version: 'v1'
    metadata: [
      {
        name: 'connectionString'
        value: eventHubNamespace.listKeys().primaryConnectionString
      }
      {
        name: 'consumerGroup'
        value: consumerGroup.name
      }
    ]
    scopes: ['collector-api']
  }
}

// Container App for collector API
resource collectorApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: '${prefix}-collector-api'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: false
        targetPort: 8080
        transport: 'http'
      }
      dapr: {
        enabled: true
        appId: 'collector-api'
        appPort: 8080
        appProtocol: 'http'
      }
      secrets: [
        {
          name: 'fixops-api-key'
          keyVaultUrl: fixopsApiKeySecret.properties.secretUri
          identity: 'system'
        }
        {
          name: 'storage-connection-string'
          value: 'DefaultEndpointsProtocol=https;AccountName=${evidenceStorage.name};AccountKey=${evidenceStorage.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'collector-api'
          image: 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest' // Replace with actual image
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            {
              name: 'FIXOPS_OVERLAY_PATH'
              value: '/app/config/fixops.overlay.yml'
            }
            {
              name: 'CLOUD_PROVIDER'
              value: 'azure'
            }
            {
              name: 'FIXOPS_API_KEY'
              secretRef: 'fixops-api-key'
            }
            {
              name: 'AZURE_STORAGE_CONNECTION_STRING'
              secretRef: 'storage-connection-string'
            }
            {
              name: 'RING_BUFFER_MAX_LINES'
              value: string(ringBuffer.max_lines)
            }
            {
              name: 'RING_BUFFER_MAX_SECONDS'
              value: string(ringBuffer.max_seconds)
            }
          ]
        }
        {
          name: 'fluent-bit'
          image: 'fluent/fluent-bit:2.2' // Replace with custom image
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            {
              name: 'INPUT_PATH'
              value: fluentbitConfig.input_path
            }
            {
              name: 'AGGREGATION_INTERVAL'
              value: string(fluentbitConfig.aggregation_interval)
            }
            {
              name: 'RETRY_LIMIT'
              value: string(fluentbitConfig.retry_limit)
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 10
        rules: [
          {
            name: 'eventhub-scaling'
            custom: {
              type: 'azure-eventhub'
              metadata: {
                connectionFromEnv: 'EVENTHUB_CONNECTION_STRING'
                eventHubName: eventHub.name
                consumerGroup: consumerGroup.name
                unprocessedEventThreshold: '10'
              }
            }
          }
        ]
      }
    }
  }
  tags: tags
}

// Role assignments
resource storageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(evidenceStorage.id, collectorApp.id, 'StorageBlobDataContributor')
  scope: evidenceStorage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe') // Storage Blob Data Contributor
    principalId: collectorApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, collectorApp.id, 'KeyVaultSecretsUser')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6') // Key Vault Secrets User
    principalId: collectorApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output containerAppUrl string = 'https://${collectorApp.properties.configuration.ingress.fqdn}'
output containerAppName string = collectorApp.name
output eventHubNamespace string = eventHubNamespace.name
output eventHubName string = eventHub.name
output storageAccountName string = evidenceStorage.name
output keyVaultName string = keyVault.name
output containerAppIdentity string = collectorApp.identity.principalId
