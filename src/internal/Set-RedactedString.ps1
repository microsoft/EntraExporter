function Set-RedactedString {
    <#
    .SYNOPSIS
        Redact sensitive information from strings such as error messages.
    .DESCRIPTION
        Set-RedactedString takes a string and redacts any sensitive information like Bearer tokens, connection strings,
        passwords, and other secrets that might be contained in the message.
    .EXAMPLE
        Set-RedactedString -InputString $_

        Returns the string with sensitive information replaced with "[REDACTED]".
    .EXAMPLE
        $SensitiveString | Set-RedactedString

        Accepts pipeline input for the input string.
    .INPUTS
        System.String
    .OUTPUTS
        System.String
    .NOTES
        This function helps prevent sensitive information from appearing in logs or being displayed to users.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # The string that may contain sensitive information to redact.
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$InputString
    )

    process {
        # Pattern matches 'Bearer ' followed by a token (non-whitespace characters)
        $Pattern = '(?i)(Bearer\s+)[^\s]+'

        # Replace the token with [REDACTED], keeping the 'Bearer ' prefix
        $RedactedString = [regex]::Replace($InputString, $pattern, '${1}[REDACTED]')
        $RedactedString
    }

}
