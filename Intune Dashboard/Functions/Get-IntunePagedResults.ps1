function Get-IntunePagedResults {
    <#
    ...existing comment block...
    #>

    param (
        [Parameter()]
        [ValidateSet('Get', 'Post', 'Put', 'Delete')]
        [string]$Method = 'Get',
        [Parameter()]
        [string]$tenantId,
        [Parameter(Mandatory)]
        [string]$applicationId,
        [Parameter(Mandatory)]
        [string]$clientSecret,
        [Parameter()]
        [string]$baseUrl = "https://graph.microsoft.com",
        [Parameter(Mandatory)]
        [string]$appendURL
    )

    # Connect to Microsoft Graph using the application ID and secret
    $authURL = "https://login.windows.net/$tenantId/oauth2/token"

    $body = @{ 
        client_id     = $applicationId
        resource      = $baseURL
        grant_type    = "client_credentials"
        client_secret = $clientSecret 
    }

    # Invoke the REST method to get the token
    $tokenResponse = Invoke-RestMethod -uri $authURL -Body $body -Method Post
    
    # Prepare the headers for the request
    $header = @{
        'Authority'        = $baseURL
        'Path'             = $appendURL
        'Method'           = $Method
        'Authorization'    = "$($tokenResponse.token_type) $($tokenResponse.access_token)"
        'Content-type'     = "application/json"
        'ODataVersion'     = 4
        'Implementation'   = "2.0"
        'ConsistencyLevel' = "eventual"
    }

    # Construct the full URL for the request
    $url = $baseURL + $appendURL

    # Initialize an empty list to hold all results
    [System.Collections.Generic.List[pscustomobject]]$allResults = @()

    # Loading bar setup
    $loadingChars = @('|', '/', '-', '\')
    $loadingIndex = 0
    $pageCount = 0

    # This loop will continue until there are no more pages (i.e., no '@odata.nextlink')
    $commandTime = Measure-Command {
        do {
            # Show loading bar
            Write-Host -NoNewline ("`rLoading $($appendURL.Split("/")[-1].Split("&")[0].Replace("?",'')) page {0} {1}" -f ($pageCount + 1), $loadingChars[$loadingIndex])
            $loadingIndex = ($loadingIndex + 1) % $loadingChars.Count

            $response = Invoke-RestMethod -Headers $header -Uri $url 
            $allResults.Add($response.value)
            $url = $response.'@odata.nextlink'
            $pageCount++
        } while ($url)
    }

    Write-Host "`rLoading $($appendURL.Split("/")[-1]) complete. Fetched $pageCount page(s). Time elapsed: $($commandTime.toString()).        "

    # Flatten the list if needed (since .Add adds arrays as items)
    If ($null -eq $allresults[0]) { 
        Return $response
    }
    Else {
        return $allResults | ForEach-Object { $_ }
    }
}