function ConvertTo-OrderedDictionary
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $InputObject
    )

    process
    {
        
        if($InputObject -is [array]){
            $outputArray = @()
            foreach($item in $InputObject){
                $outputArray += ConvertTo-OrderedDictionary $item
            }
            return $outputArray
        }
        elseif($InputObject -is [hashtable]){ 
            $outputObject = [ordered]@{}
            foreach ($Item in ($InputObject.GetEnumerator() | Sort-Object -Property Key)) {
                $value = Get-ObjectProperty $Item 'Value'
                if($value -is [hashtable]){ #if child is a hashtable, sort it too
                    $Item.Value = ConvertTo-OrderedDictionary $value
                }
                $outputObject[$Item.Key] = $Item.Value
            }
            return $outputObject
        }
    }
}
