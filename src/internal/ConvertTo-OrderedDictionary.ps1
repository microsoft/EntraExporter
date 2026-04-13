function ConvertTo-OrderedDictionary
{
    <#
    .SYNOPSIS
    Converts an input object into a recursively ordered structure.

    .DESCRIPTION
    Recursively processes dictionaries, arrays, enumerables, and custom objects to produce deterministic ordering.
    Dictionaries and object properties are ordered by name, and collection items are ordered by a stable helper sort key.
    Scalar-like values are returned unchanged.

    .PARAMETER InputObject
    Object to convert. Supports pipeline input. If null is provided, null is returned.

    .OUTPUTS
    System.Object

    .EXAMPLE
    $result = @{ b = 2; a = 1 } | ConvertTo-OrderedDictionary
    $result

    returns the same data with keys ordered deterministically.

    .EXAMPLE
    ConvertTo-OrderedDictionary -InputObject $graphResponse

    Converts nested API response objects into a stable ordered representation useful for compare/export scenarios.

    .EXAMPLE
    $inputObject = [PSCustomObject]@{
        service = 'contoso-app'
        users = @(
            [PSCustomObject]@{ id = 3; displayName = 'Cecil'; department = 'Ops' }
            [PSCustomObject]@{ department = 'HR'; displayName = 'Anna'; id = 1 }
            [PSCustomObject]@{ displayName = 'Boris'; id = 2; department = 'IT' }
        )
        metadata = [PSCustomObject]@{ z = 'last'; a = 'first' }
    }

    $ordered = ConvertTo-OrderedDictionary -InputObject $inputObject

    Keeps property names ordered (for example metadata.a before metadata.z) and also stabilizes ordering
    in users array items that contain unsorted property declarations.

    OUTPUT:
    metadata           service     users
    --------           -------     -----
    @{a=first; z=last} contoso-app {@{department=HR; displayName=Anna; id=1}, @{department=IT; displayName=Boris; id=2}, @{department=Ops; displayName=Cecil; id=3}}

    .EXAMPLE
    $inputObject = [PSCustomObject]@{
        groups = @(
            [PSCustomObject]@{
                name = 'team-b'
                members = @(
                    [PSCustomObject]@{ role = 'Owner'; userId = 20; upn = 'b-owner@contoso.com' }
                    [PSCustomObject]@{ upn = 'b-member@contoso.com'; userId = 21; role = 'Member' }
                )
            }
            [PSCustomObject]@{
                members = @(
                    [PSCustomObject]@{ userId = 10; upn = 'a-owner@contoso.com'; role = 'Owner' }
                    [PSCustomObject]@{ role = 'Member'; upn = 'a-member@contoso.com'; userId = 11 }
                )
                name = 'team-a'
            }
        )
    }

    ConvertTo-OrderedDictionary -InputObject $inputObject | ConvertTo-Json -Depth 5

    Recursively orders group and member properties and makes nested array output deterministic for reliable compare/export.

    OUTPUT:
    {
    "groups": [
        {
        "members": [
            {
            "role": "Member",
            "upn": "a-member@contoso.com",
            "userId": 11
            },
            {
            "role": "Owner",
            "upn": "a-owner@contoso.com",
            "userId": 10
            }
        ],
        "name": "team-a"
        },
        {
        "members": [
            {
            "role": "Member",
            "upn": "b-member@contoso.com",
            "userId": 21
            },
            {
            "role": "Owner",
            "upn": "b-owner@contoso.com",
            "userId": 20
            }
        ],
        "name": "team-b"
        }
    ]
    }

    .NOTES
    Intended for deterministic output in diffing, testing, and serialization workflows.
    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        $InputObject
    )

    begin
    {
        function Get-OrderedDictionarySortKey
        {
            <#
            .SYNOPSIS
            Builds a stable sort key for mixed object items.

            .DESCRIPTION
            Extracts up to three scalar values from an input dictionary or object properties and joins them
            into a deterministic string key, so collection sorting remains stable between runs.

            .PARAMETER Item
            Item used to generate the sort key.

            .OUTPUTS
            System.String
            #>

            param($Item)

            if ($null -eq $Item) { return '' }

            if (
                $Item.GetType().IsPrimitive -or
                $Item -is [string] -or
                $Item -is [decimal] -or
                $Item -is [datetime] -or
                $Item -is [datetimeoffset] -or
                $Item -is [timespan] -or
                $Item -is [guid] -or
                $Item -is [enum]
            )
            {
                return [string]$Item
            }

            $keyParts = [System.Collections.Generic.List[string]]::new()

            if ($Item -is [System.Collections.IDictionary])
            {
                # use first scalar dictionary values (sorted by key) as a lightweight stable signature.
                foreach ($key in ($Item.Keys | Sort-Object { [string]$_ }))
                {
                    if ($keyParts.Count -ge 3) { break }
                    $val = $Item[$key]
                    if (
                        $null -eq $val -or
                        $val.GetType().IsPrimitive -or
                        $val -is [string] -or
                        $val -is [decimal] -or
                        $val -is [datetime] -or
                        $val -is [datetimeoffset] -or
                        $val -is [timespan] -or
                        $val -is [guid] -or
                        $val -is [enum]
                    )
                    {
                        $keyParts.Add([string]$val)
                    }
                }
            }
            else
            {
                try
                {
                    $props = @(
                        $Item.PSObject.Properties |
                            Where-Object {
                                $_.IsGettable -and
                                $_.MemberType -in [System.Management.Automation.PSMemberTypes]::NoteProperty, [System.Management.Automation.PSMemberTypes]::Property
                            } |
                            Sort-Object Name
                    )

                    # use first scalar property values (sorted by name) for deterministic ordering.
                    foreach ($prop in $props)
                    {
                        if ($keyParts.Count -ge 3) { break }
                        try { $val = $prop.Value } catch { continue }
                        if (
                            $null -eq $val -or
                            $val.GetType().IsPrimitive -or
                            $val -is [string] -or
                            $val -is [decimal] -or
                            $val -is [datetime] -or
                            $val -is [datetimeoffset] -or
                            $val -is [timespan] -or
                            $val -is [guid] -or
                            $val -is [enum]
                        )
                        {
                            $keyParts.Add([string]$val)
                        }
                    }
                }
                catch { }
            }

            return $keyParts -join "`0"
        }
    }

    process
    {
        if ($null -eq $InputObject)
        {
            return $null
        }

        if (
            # keep scalar-like values as-is to avoid unnecessary wrapping.
            $InputObject.GetType().IsPrimitive -or
            $InputObject -is [string] -or
            $InputObject -is [decimal] -or
            $InputObject -is [datetime] -or
            $InputObject -is [datetimeoffset] -or
            $InputObject -is [timespan] -or
            $InputObject -is [guid] -or
            $InputObject -is [enum]
        )
        {
            return $InputObject
        }

        if ($InputObject -is [System.Collections.IDictionary])
        {
            $outputObject = [ordered]@{}
            $sortedKeys = [System.Collections.Generic.List[Object]]::new()

            # insert keys using ordinal comparison to keep ordering deterministic and culture-independent.
            foreach ($key in $InputObject.Keys)
            {
                $insertAt = $sortedKeys.Count

                for ($i = 0; $i -lt $sortedKeys.Count; $i++)
                {
                    if ([string]::CompareOrdinal([string]$key, [string]$sortedKeys[$i]) -lt 0)
                    {
                        $insertAt = $i
                        break
                    }
                }

                $sortedKeys.Insert($insertAt, $key)
            }

            foreach ($key in $sortedKeys)
            {
                $outputObject[$key] = ConvertTo-OrderedDictionary -InputObject $InputObject[$key]
            }

            return $outputObject
        }

        if ($InputObject -is [System.Array])
        {
            $outputArray = @()
            # sort complex items using the helper key so output is stable between runs.
            foreach ($item in ($InputObject | Sort-Object { Get-OrderedDictionarySortKey $_ }))
            {
                $outputArray += ConvertTo-OrderedDictionary -InputObject $item
            }

            return $outputArray
        }

        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string])
        {
            $outputArray = @()
            # treat non-array enumerables the same way for consistent ordering.
            foreach ($item in ($InputObject | Sort-Object { Get-OrderedDictionarySortKey $_ }))
            {
                $outputArray += ConvertTo-OrderedDictionary -InputObject $item
            }

            return $outputArray
        }

        $properties = @(
            $InputObject.PSObject.Properties |
                Where-Object {
                    $_.MemberType -in [System.Management.Automation.PSMemberTypes]::NoteProperty, [System.Management.Automation.PSMemberTypes]::Property -and
                    $_.IsGettable
                }
        )

        if ($properties.Count -gt 0)
        {
            $outputObject = [ordered]@{}
            $sortedProperties = [System.Collections.Generic.List[Object]]::new()

            # keep property ordering explicit (ordinal by name) before recursive conversion.
            foreach ($property in $properties)
            {
                $insertAt = $sortedProperties.Count

                for ($i = 0; $i -lt $sortedProperties.Count; $i++)
                {
                    if ([string]::CompareOrdinal([string]$property.Name, [string]$sortedProperties[$i].Name) -lt 0)
                    {
                        $insertAt = $i
                        break
                    }
                }

                $sortedProperties.Insert($insertAt, $property)
            }

            foreach ($property in $sortedProperties)
            {
                try
                {
                    $propertyValue = $property.Value
                }
                catch
                {
                    continue
                }

                $outputObject[$property.Name] = ConvertTo-OrderedDictionary -InputObject $propertyValue
            }

            return [PSCustomObject]$outputObject
        }

        return $InputObject
    }
}