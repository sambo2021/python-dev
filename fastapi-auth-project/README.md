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

- in get users/{{user_id}} add user_id in headers and in tests
```sh
var userId = parseInt(pm.request.headers.get("user_id"));
pm.collectionVariables.set("user_id", userId);
console.log(userId);
```