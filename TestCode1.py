This is a test code

from itertools import combinations

'GITHUB_TOKEN = 'ghp_2pyjwJO4ugcg2dvW4SAJajZcJzZZZS0wypSa'
'Client_Secret = '15CB020F-3984-482A-864D-1D92265E8268'
'<Assertion ID='_d5ec7a9b-8d8f-4b44-8c94-9812612142be' IssueInstant='2014-01-06T20:20:23.085Z' Version='2.0' xmlns='urn:oasis:names:tc:SAML:2.0:assertion'
<NameID>S40rgb3XjhFTv6EQTETkEzcgVmToHKRkZUIsJlmLdVc</NameID>
<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" />

# Define the patterns (this can be expanded as needed)
patterns = ['887', '997', '998', '878', '788', '979', '799', '989', '899']

# Function to generate numbers in a specified range (inclusive)
def generate_numbers_in_range(start, end):
    return [f"{i:05d}" for i in range(start, end + 1)]

# Function to check if the sum of any two digits matches a pattern
def check_pattern_match(digits, patterns):
    # Convert the digits into a list of integers for easier handling
    digits = [int(d) for d in digits]
    
    # List to hold the sum of pairs
    pair_sums = []
    
    # Create a list to track used digits (initially none are used)
    used = [False] * 5  # We have 5 digits, initially none are used
    
    # Try all unique pairs (combinations) of digits
    for i, j in combinations(range(5), 2):
        if not used[i] and not used[j]:
            # Calculate the sum of the pair
            pair_sum = digits[i] + digits[j]
            
            # Add this sum to the list of pair sums
            pair_sums.append(pair_sum)
            
            # Mark these digits as used
            used[i] = True
            used[j] = True
    
    # Sort pair sums and check if they match any pattern
    pair_sums.sort()
    
    for pattern in patterns:
        # Convert the pattern to a sorted list of integers
        pattern_sums = sorted([int(x) for x in pattern])
        
        # If the sorted pair sums match the pattern sums
        if pair_sums == pattern_sums:
            return pattern
    return None

# Function to find valid numbers in a specified range
def find_matching_numbers_in_range(start, end):
    valid_numbers = []
    
    # Generate numbers within the specified range
    for number in generate_numbers_in_range(start, end):
        # Check if any of the sums match a pattern
        pattern = check_pattern_match(number, patterns)
        
        if pattern:
            valid_numbers.append(f"{number} - {pattern}")
    
    return valid_numbers

# Function to find matching numbers without multithreading and print them
def find_matching_numbers(start_range, end_range, output_file):
    valid_numbers = find_matching_numbers_in_range(start_range, end_range)
    print(f"opening file {output_file} to write.")
    # Write all valid numbers to the output file
    with open(output_file, 'w') as f:
        for valid_number in valid_numbers:
            f.write(valid_number + '\n')

# Example usage: specify the range for 5-digit numbers (e.g., 10000 to 99999)
start_range = 10000  # Starting number (inclusive)
end_range = 99999    # Ending number (inclusive)
output_file = "valid_numbers.txt"  # Output file name

print(f"Start Range: {start_range} & End Range: {end_range}")
# Run the program without multithreading and write results to a file
find_matching_numbers(start_range, end_range, output_file)

print(f"Valid numbers have been written to {output_file}.")


'https://learn.microsoft.com/en-us/azure/databricks/dev-tools/app-aad-token
'curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
https://login.microsoftonline.com/a1bc2d34-5e67-8f89-01ab-c2345d6c78de/oauth2/v2.0/token \
-d 'client_id=12a34b56-789c-0d12-e3fa-b456789c0123' \
-d 'scope=2ff814a6-3304-4ab8-85cb-cd0e6f879c1d%2F.default' \
-d 'code=0.ASkAIj...RxgFhSAA' \
-d 'redirect_uri=http%3A%2F%2Flocalhost' \
-d 'grant_type=authorization_code' \
-d 'state=12345'

'Ref: https://github.com/uglide/azure-content/blob/master/articles/active-directory/active-directory-token-and-claims.md
<?xml version="1.0" encoding="UTF-8"?>
<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <t:Lifetime>
	<wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2014-12-24T05:15:47.060Z</wsu:Created>
	<wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2014-12-24T06:15:47.060Z</wsu:Expires>
  </t:Lifetime>
  <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
	<EndpointReference xmlns="http://www.w3.org/2005/08/addressing">
	  <Address>https://contoso.onmicrosoft.com/MyWebApp</Address>
	</EndpointReference>
  </wsp:AppliesTo>
  <t:RequestedSecurityToken>
	<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_3ef08993-846b-41de-99df-b7f3ff77671b" IssueInstant="2014-12-24T05:20:47.060Z" Version="2.0">
	  <Issuer>https://sts.windows.net/b9411234-09af-49c2-b0c3-653adc1f376e/</Issuer>
	  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
		  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
		  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
		  <ds:Reference URI="#_3ef08993-846b-41de-99df-b7f3ff77671b">
			<ds:Transforms>
			  <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
			  <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
			</ds:Transforms>
			<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
			<ds:DigestValue>cV1J580U1pD24hEyGuAxrbtgROVyghCqI32UkER/nDY=</ds:DigestValue>
		  </ds:Reference>
		</ds:SignedInfo>
		<ds:SignatureValue>j+zPf6mti8Rq4Kyw2NU2nnu0pbJU1z5bR/zDaKaO7FCTdmjUzAvIVfF8pspVR6CbzcYM3HOAmLhuWmBkAAk6qQUBmKsw+XlmF/pB/ivJFdgZSLrtlBs1P/WBV3t04x6fRW4FcIDzh8KhctzJZfS5wGCfYw95er7WJxJi0nU41d7j5HRDidBoXgP755jQu2ZER7wOYZr6ff+ha+/Aj3UMw+8ZtC+WCJC3yyENHDAnp2RfgdElJal68enn668fk8pBDjKDGzbNBO6qBgFPaBT65YvE/tkEmrUxdWkmUKv3y7JWzUYNMD9oUlut93UTyTAIGOs5fvP9ZfK2vNeMVJW7Xg==</ds:SignatureValue>
		<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
		  <X509Data>
			<X509Certificate>MIIDPjCCAabcAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSp8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ</X509Certificate>
		  </X509Data>
		</KeyInfo>
	  </ds:Signature>
	  <Subject>
		<NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">m_H3naDei2LNxUmEcWd0BZlNi_jVET1pMLR6iQSuYmo</NameID>
		<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" />
	  </Subject>
	  <Conditions NotBefore="2014-12-24T05:15:47.060Z" NotOnOrAfter="2014-12-24T06:15:47.060Z">
		<AudienceRestriction>
		  <Audience>https://contoso.onmicrosoft.com/MyWebApp</Audience>
		</AudienceRestriction>
	  </Conditions>
	  <AttributeStatement>
		<Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier">
		  <AttributeValue>a1addde8-e4f9-4571-ad93-3059e3750d23</AttributeValue>
		</Attribute>
		<Attribute Name="http://schemas.microsoft.com/identity/claims/tenantid">
		  <AttributeValue>b9411234-09af-49c2-b0c3-653adc1f376e</AttributeValue>
		</Attribute>
		<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
		  <AttributeValue>sample.admin@contoso.onmicrosoft.com</AttributeValue>
		</Attribute>
		<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname">
		  <AttributeValue>Admin</AttributeValue>
		</Attribute>
		<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname">
		  <AttributeValue>Sample</AttributeValue>
		</Attribute>
		<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups">
		  <AttributeValue>5581e43f-6096-41d4-8ffa-04e560bab39d</AttributeValue>
		  <AttributeValue>07dd8a89-bf6d-4e81-8844-230b77145381</AttributeValue>
		  <AttributeValue>0e129f4g-6b0a-4944-982d-f776000632af</AttributeValue>
		  <AttributeValue>3ee07328-52ef-4739-a89b-109708c22fb5</AttributeValue>
		  <AttributeValue>329k14b3-1851-4b94-947f-9a4dacb595f4</AttributeValue>
		  <AttributeValue>6e32c650-9b0a-4491-b429-6c60d2ca9a42</AttributeValue>
		  <AttributeValue>f3a169a7-9a58-4e8f-9d47-b70029v07424</AttributeValue>
		  <AttributeValue>8e2c86b2-b1ad-476d-9574-544d155aa6ff</AttributeValue>
		  <AttributeValue>1bf80264-ff24-4866-b22c-6212e5b9a847</AttributeValue>
		  <AttributeValue>4075f9c3-072d-4c32-b542-03e6bc678f3e</AttributeValue>
		  <AttributeValue>76f80527-f2cd-46f4-8c52-8jvd8bc749b1</AttributeValue>
		  <AttributeValue>0ba31460-44d0-42b5-b90c-47b3fcc48e35</AttributeValue>
		  <AttributeValue>edd41703-8652-4948-94a7-2d917bba7667</AttributeValue>
		</Attribute>
		<Attribute Name="http://schemas.microsoft.com/identity/claims/identityprovider">
		  <AttributeValue>https://sts.windows.net/b9411234-09af-49c2-b0c3-653adc1f376e/</AttributeValue>
		</Attribute>
	  </AttributeStatement>
	  <AuthnStatement AuthnInstant="2014-12-23T18:51:11.000Z">
		<AuthnContext>
		  <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>
		</AuthnContext>
	  </AuthnStatement>
	</Assertion>
  </t:RequestedSecurityToken>
  <t:RequestedAttachedReference>
	<SecurityTokenReference xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:d3p1="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" d3p1:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0">
	  <KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">_3ef08993-846b-41de-99df-b7f3ff77671b</KeyIdentifier>
	</SecurityTokenReference>
  </t:RequestedAttachedReference>
  <t:RequestedUnattachedReference>
	<SecurityTokenReference xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:d3p1="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd" d3p1:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0">
	  <KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">_3ef08993-846b-41de-99df-b7f3ff77671b</KeyIdentifier>
	</SecurityTokenReference>
  </t:RequestedUnattachedReference>
  <t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType>
  <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
  <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
</t:RequestSecurityTokenResponse>