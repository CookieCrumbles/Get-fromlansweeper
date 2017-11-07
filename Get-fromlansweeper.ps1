function get-fromlansweeper ($user) 
{
		# You need HtmlAgilityPack in order for this to work.
		[Reflection.Assembly]::LoadFile("C:\HtmlAgilityPack\lib\Net45\HtmlAgilityPack.dll") | Out-Null
		[HtmlAgilityPack.HtmlWeb]$web = @{}
		$url = "http://lansweeper:80/user.aspx?username=$user&userdomain=domain"	
		
		<#
		$webclient = new-object System.Net.WebClient
		$username = "username"
		$password = "password"
		$domain = "domain"
			
		$webclient.Credentials = new-object System.Net.NetworkCredential($username, $password,$domain)
		$defaultCredentials =  $webclient.Credentials				
		#>
		# This gets your current and active user. This was enough in my case.
		# You can however create your own object as shown in the code just above.
		$cred = new-object System.Net.NetworkCredential
		$defaultCredentials =  $cred.UseDefaultCredentials

		<#
		$proxyAddr = (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
		$proxy = new-object System.Net.WebProxy
		$proxy.Address = $proxyAddr
		$proxy.useDefaultCredentials = $true # https://msdn.microsoft.com/en-us/library/system.net.webclient.usedefaultcredentials(v=vs.110).aspx
		$proxy.BypassArrayList
		$proxy
		#>

		[HtmlAgilityPack.HtmlDocument]$doc = $web.Load($url,"GET","ourproxy:80",$defaultCredentials) 				
		$itstaff = @("x","y","z") # for some reason, it staff members have an added TD
		if($user -in $itstaff){
			$td = 5
		}else{
			$td = 4
		}
		$ErrorActionPreference = ‘SilentlyContinue’ 
		$lastknownpclist = ([HtmlAgilityPack.HtmlNodeCollection]$nodes = $doc.DocumentNode.SelectNodes("//html[1]/body[1]//div[@id='Maincontent']//td[@id = 'usercontent']//table[$td]//tr//td[3]")).innerText
		$lastdatelist = ([HtmlAgilityPack.HtmlNodeCollection]$nodes = $doc.DocumentNode.SelectNodes("//html[1]/body[1]//div[@id='Maincontent']//td[@id = 'usercontent']//table[$td]//tr//td[2]")).innerText 

		write-host "Last logged on to computer:"($lastknownpclist | select -First 1 -Skip 1)"@"($lastdatelist | select -First 1 -Skip 1)  -ForegroundColor Green 
				
		$arr = @()
		for($i = 1; $i -lt $lastknownpclist.count; $i ++) # $i must be one because first row are the headers
		{	         
			$output = get-adcomputer $lastknownpclist[$i] -Properties Description | select -ExpandProperty Description 
			if($output)
			{
				$arr += [pscustomobject]@{     
				"Computer" =  $lastknownpclist[$i]
				"Date" = $lastdatelist[$i]
				"AD Description" =  $output
				}
			}#end if
			else
			{
				$arr += [pscustomobject]@{     
				"Computer" =  $lastknownpclist[$i]
				"Date" = $lastdatelist[$i]
				"AD Description" = ""
				}
			}
		}
	 ($arr | select -First 5 -Skip 0)  | ft		
	 $ErrorActionPreference = ‘Continue’
}


function Get-phone {
    [cmdletbinding()]
    param(
	 [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
	 [string[]]$user			 
    )
    begin{}
    process
	{
	   if($user -match "[0-9]"){
			$payload = Get-ADUser -Filter "SamAccountName -eq '$user'"  -prop TelephoneNumber, Mobile, MobilePhone,Description,mail,givenname,pobox   
			| Select Name, SamAccountName, Mobile, MobilePhone, TelephoneNumber,Description,POBox| sort Name                
		   $payload               	
		   get-fromlansweeper($user)               
		}
		else{       
			$payload = get-aduser  -LDAPFilter "(name=*$user*)"  -prop TelephoneNumber, Mobile, MobilePhone , Description,mail,POBox |
			Select Name,SamAccountName,Mobile, MobilePhone, TelephoneNumber,Description,POBox | sort Name
			$payload			
		}
    }
    end{}
}