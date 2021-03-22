<# 
 .Synopsis
  Represents an Azure Active Directory (Azure AD) identity provider. The identity provider can be Microsoft, Google, Facebook, Amazon, LinkedIn, or Twitter. The following Identity Providers are in Preview: Weibo, QQ, WeChat, GitHub and any OpenID Connect supported providers.

 .Description
  GET /identityProviders
  https://docs.microsoft.com/en-us/graph/api/identityprovider-list

 .Example
  Get-AADExportIdentityProviders
#>

Function Get-AADExportIdentityProviders {
  Invoke-Graph 'identityProviders'
}