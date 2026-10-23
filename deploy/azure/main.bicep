// The Altiward server on Azure Container Apps, behind the Deploy to Azure button
// (README.md). Postgres sits on a private network, the database URL and tokens are kept in
// Key Vault, and a caddy container next to Altiward keeps the console to the networks you
// list while Macs report from anywhere.
//
// The button deploys azuredeploy.json, compiled from this file: edit this one, then run
// make azure-template and commit both. scripts/azure-template.sh moves the version at release.

metadata description = 'The Altiward server on Azure Container Apps, with Postgres on a private network and its tokens in Key Vault.'

@description('Where to create everything. Defaults to the resource group\'s region.')
param location string = resourceGroup().location

@description('The start of every resource name: 3 to 12 lowercase letters and digits, starting with a letter. The console\'s address starts with it.')
@minLength(3)
@maxLength(12)
param namePrefix string = 'altiward'

@description('Your organisation\'s short name, which the tokens carry: letters, digits and hyphens.')
@minLength(1)
@maxLength(40)
param organisationName string

@description('The password for the database\'s admin user, altiward: at least 12 characters, with three of upper case, lower case, digits and symbols.')
@secure()
@minLength(12)
@maxLength(128)
param postgresAdminPassword string

@description('The networks allowed to open the console, space separated, such as your office\'s public addresses: 203.0.113.0/24 198.51.100.7/32. Macs report from anywhere whatever this says. 0.0.0.0/0 allows everyone.')
@minLength(7)
param consoleAllowedNetworks string

@description('The token Macs enroll with, the profile\'s EnrollmentToken. Leave it out to generate one.')
@secure()
@minLength(16)
param agentToken string = replace(newGuid(), '-', '')

@description('The console token, for signing in before single sign-on is set up and as a break-glass login after. Leave it out to generate one.')
@secure()
@minLength(16)
param consoleToken string = replace(newGuid(), '-', '')

// The release this template runs: scripts/azure-template.sh moves it, and the release
// workflow refuses a tag it doesn't match.
var version = '0.2.0-rc.2'
var image = 'ghcr.io/altiward/altiward-api:${version}'
// The Docker Official Image, copied next to Altiward's by each server release
// (release-server.yml): Docker Hub and other public mirrors limit anonymous pulls by
// address, and container apps share their outbound addresses.
var caddyImage = 'ghcr.io/altiward/caddy:2.8-alpine'

var suffix = uniqueString(resourceGroup().id, namePrefix)
var names = {
  workspace: '${namePrefix}-logs'
  network: '${namePrefix}-network'
  identity: '${namePrefix}-identity'
  vault: take('${namePrefix}-${suffix}', 24) // unique in Azure
  database: '${namePrefix}-db-${suffix}' // unique in Azure
  environment: '${namePrefix}-environment'
  app: namePrefix
}
var keyVaultSecretsUser = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var keyVaultSecretsOfficer = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: names.workspace
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// The container apps environment and Postgres each get a subnet delegated to them.
resource network 'Microsoft.Network/virtualNetworks@2024-07-01' = {
  name: names.network
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.42.0.0/16'] }
    subnets: [
      {
        name: 'apps'
        properties: {
          addressPrefix: '10.42.0.0/24'
          delegations: [{ name: 'apps', properties: { serviceName: 'Microsoft.App/environments' } }]
        }
      }
      {
        name: 'database'
        properties: {
          addressPrefix: '10.42.1.0/28'
          delegations: [{ name: 'database', properties: { serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers' } }]
        }
      }
    ]
  }

  resource appsSubnet 'subnets' existing = {
    name: 'apps'
  }

  resource databaseSubnet 'subnets' existing = {
    name: 'database'
  }
}

// The database's name resolves to its private address only inside the network.
resource databaseZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: '${names.database}.private.postgres.database.azure.com'
  location: 'global'

  resource link 'virtualNetworkLinks' = {
    name: names.network
    location: 'global'
    properties: {
      registrationEnabled: false
      virtualNetwork: { id: network.id }
    }
  }
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers@2025-08-01' = {
  name: names.database
  location: location
  sku: { name: 'Standard_B1ms', tier: 'Burstable' }
  properties: {
    version: '17'
    administratorLogin: 'altiward'
    administratorLoginPassword: postgresAdminPassword
    storage: { storageSizeGB: 32 }
    backup: { backupRetentionDays: 7, geoRedundantBackup: 'Disabled' }
    highAvailability: { mode: 'Disabled' }
    network: {
      delegatedSubnetResourceId: network::databaseSubnet.id
      privateDnsZoneArmResourceId: databaseZone.id
      publicNetworkAccess: 'Disabled'
    }
  }
  dependsOn: [databaseZone::link] // the zone must resolve in the network before the server joins it

  resource altiward 'databases' = {
    name: 'altiward'
    properties: { charset: 'UTF8', collation: 'en_US.utf8' }
  }
}

// The app reads its secrets as this identity; Sentinel's export can sign in as it too.
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: names.identity
  location: location
}

resource vault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  name: names.vault
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    // The platform reads the secrets from outside the network.
    publicNetworkAccess: 'Enabled'
  }

  resource databaseUrl 'secrets' = {
    name: 'database-url'
    properties: {
      value: 'postgres://altiward:${uriComponent(postgresAdminPassword)}@${database.properties.fullyQualifiedDomainName}:5432/altiward?sslmode=verify-full'
    }
  }

  resource agentTokens 'secrets' = {
    name: 'agent-tokens'
    properties: { value: '${organisationName}=${agentToken}' }
  }

  resource consoleTokens 'secrets' = {
    name: 'console-tokens'
    properties: { value: '${organisationName}=${consoleToken}' }
  }
}

resource appReadsSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, identity.id, keyVaultSecretsUser)
  properties: {
    roleDefinitionId: keyVaultSecretsUser
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Whoever deploys can read the tokens, and change them later.
resource deployerManagesSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, deployer().objectId, keyVaultSecretsOfficer)
  properties: {
    roleDefinitionId: keyVaultSecretsOfficer
    principalId: deployer().objectId
  }
}

resource appEnvironment 'Microsoft.App/managedEnvironments@2025-07-01' = {
  name: names.environment
  location: location
  properties: {
    workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }]
    vnetConfiguration: {
      infrastructureSubnetId: network::appsSubnet.id
      internal: false
    }
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: workspace.properties.customerId
        sharedKey: workspace.listKeys().primarySharedKey
      }
    }
  }
}

var healthz = { path: '/healthz', port: 8080 }

resource app 'Microsoft.App/containerApps@2025-07-01' = {
  name: names.app
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    environmentId: appEnvironment.id
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      // TLS ends here; caddy (8081) passes requests on to Altiward (8080).
      ingress: {
        external: true
        targetPort: 8081
        transport: 'http'
        allowInsecure: false
      }
      // Versionless references, so a changed token reaches the app.
      secrets: [
        { name: 'database-url', keyVaultUrl: vault::databaseUrl.properties.secretUri, identity: identity.id }
        { name: 'agent-tokens', keyVaultUrl: vault::agentTokens.properties.secretUri, identity: identity.id }
        { name: 'console-tokens', keyVaultUrl: vault::consoleTokens.properties.secretUri, identity: identity.id }
        // Not a secret: a secret is how a container app mounts a file.
        #disable-next-line use-secure-value-for-secure-inputs
        { name: 'caddyfile', value: loadTextContent('Caddyfile') }
      ]
    }
    template: {
      containers: [
        {
          name: 'altiward'
          image: image
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'ALTIWARD_DATABASE_URL', secretRef: 'database-url' }
            { name: 'ALTIWARD_AGENT_TOKENS', secretRef: 'agent-tokens' }
            { name: 'ALTIWARD_CONSOLE_TOKENS', secretRef: 'console-tokens' }
            // Single sign-on's redirect address. Change it with a custom domain (README.md).
            { name: 'ALTIWARD_CONSOLE_URL', value: 'https://${names.app}.${appEnvironment.properties.defaultDomain}' }
          ]
          probes: [
            // Migrations run before the server listens: allow an upgrade's about 5 minutes on
            // a large database before the replica is restarted, which would roll them back.
            { type: 'Startup', httpGet: healthz, initialDelaySeconds: 5, periodSeconds: 30, failureThreshold: 10 }
            { type: 'Liveness', httpGet: healthz, periodSeconds: 10, failureThreshold: 3 }
            { type: 'Readiness', httpGet: healthz, periodSeconds: 5, failureThreshold: 3 }
          ]
        }
        {
          name: 'caddy'
          image: caddyImage
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: [{ name: 'ALTIWARD_CONSOLE_ALLOW', value: consoleAllowedNetworks }]
          volumeMounts: [{ volumeName: 'caddy-config', mountPath: '/etc/caddy' }]
          probes: [
            { type: 'Readiness', httpGet: { path: '/healthz', port: 8081 }, periodSeconds: 5, failureThreshold: 3 }
          ]
        }
      ]
      volumes: [
        // Only the Caddyfile: the other secrets stay out of caddy's container.
        { name: 'caddy-config', storageType: 'Secret', secrets: [{ secretRef: 'caddyfile', path: 'Caddyfile' }] }
      ]
      // One is enough for most fleets, and more are safe (README.md, "Replicas").
      scale: { minReplicas: 1, maxReplicas: 1 }
    }
  }
  // The identity must be able to read the secrets before the app starts.
  dependsOn: [appReadsSecrets, database::altiward]
}

@description('The console, and the ServerURL for the Macs\' configuration profile until you add your own domain.')
output consoleUrl string = 'https://${app.properties.configuration.ingress.fqdn}'

@description('The tokens, in Key Vault: agent-tokens and console-tokens, each your organisation\'s name, =, then the token.')
output tokensUrl string = '${environment().portal}/#@${tenant().tenantId}/resource${vault.id}/secrets'

@description('The key vault holding the tokens, for az keyvault secret show --vault-name.')
output vaultName string = vault.name

output appName string = app.name

@description('The app\'s managed identity, for integrations/sentinel/setup.sh --identity.')
output identityClientId string = identity.properties.clientId

@description('For your own domain: the asuid TXT record\'s value.')
output customDomainVerificationId string = app.properties.customDomainVerificationId

@description('For your own domain: the CNAME record\'s target.')
output fqdn string = app.properties.configuration.ingress.fqdn
