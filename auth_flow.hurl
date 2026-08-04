# Generate a unique email for every run
POST {{base_url}}/auth/register
Content-Type: application/json

{
  "email": "{{email}}",
  "password": "{{password}}",
  "display_name": "Test User"
}

HTTP 201

# Save the email for login
[Captures]
email: jsonpath "$.email"

###

POST {{base_url}}/auth/login
Content-Type: application/json

{
  "email": "{{email}}",
  "password": "{{password}}"
}

HTTP 200

[Captures]
token: jsonpath "$.access_token"

###

GET {{base_url}}/users/me
Authorization: Bearer {{token}}

HTTP 200

[Asserts]
jsonpath "$.email" == "{{email}}"
jsonpath "$.display_name" == "Test User"

###

PATCH {{base_url}}/users/me
Authorization: Bearer {{token}}
Content-Type: application/json

{
  "display_name": "Updated User"
}

HTTP 200

[Asserts]
jsonpath "$.display_name" == "Updated User"

###

GET {{base_url}}/users/me
Authorization: Bearer {{token}}

HTTP 200

[Asserts]
jsonpath "$.display_name" == "Updated User"