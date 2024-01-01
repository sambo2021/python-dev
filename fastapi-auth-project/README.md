- request token 
```sh
curl --location 'http://localhost:9095/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'username=tom' \
--data-urlencode 'password=tom123' \
--data-urlencode 'grant_type=password'
```

- in post token request set variable in tests 
```sh
var token = pm.response.json()['access_token'];
pm.collectionVariables.set("accessToken", token);
console.log(pm.collectionVariables.get("accessToken"));
```

- in get users request select auth baerer {{accessToken}}

- in get users/{{user_name}} add user_name you want to search for in the url and select auth baerer {{accessToken}}
