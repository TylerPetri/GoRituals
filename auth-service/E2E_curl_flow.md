1) Sign up
    ```
    curl -sS -X POST http://localhost:8080/v1/auth/signup \
      -H 'Content-Type: application/json' \
      -d '{"email":"alice@example.com","password":"Secret123!","first_name":"Alice","last_name":"A"}' \
    | tee /tmp/signup.json
    ```
    Grab tokens:
    ```
    AT=$(jq -r '.access_token' /tmp/signup.json)
    RT=$(jq -r '.refresh_token' /tmp/signup.json)   # format: "<id>.<plaintext>"
    echo "AT len: ${#AT}, RT preview: ${RT%%.*}.[...]"
    ```
2) Call a protected route (/v1/me)
    ```
    curl -sS http://localhost:8080/v1/me \
    -H "Authorization: Bearer $AT" | jq
    ```
3) Refresh (rotate refresh token, get new access token)
    - Bearer header (most common for APIs)
        ```
        curl -sS -X POST http://localhost:8080/v1/tokens/refresh \
        -H "Authorization: Bearer $RT" | tee /tmp/refresh.json
        ```
    - JSON body
        ```
        curl -sS -X POST http://localhost:8080/v1/tokens/refresh \
        -H 'Content-Type: application/json' \
        -d "{\"refresh_token\":\"$RT\"}" | tee /tmp/refresh.json
        ```
    - Cookie (if CookieRefresh=true on server)
        ```
        curl -sS -X POST http://localhost:8080/v1/tokens/refresh \
        -H 'Content-Type: application/json' \
        --cookie "refresh_token=$RT" | tee /tmp/refresh.json
        ```
    Extract the new tokens:
    ```
    AT=$(jq -r '.access_token' /tmp/refresh.json)
    RT=$(jq -r '.refresh_token' /tmp/refresh.json)
    echo "rotated -> new RT id: ${RT%%.*}"
    ```
4) Logout (revoke a specific refresh token):
    ```
    curl -sS -X POST http://localhost:8080/v1/auth/logout \
    -H "Authorization: Bearer $RT" -i 
    ```
    Try to refresh with that RT again → should fail:
    ```
    curl -sS -X POST http://localhost:8080/v1/tokens/refresh \
    -H "Authorization: Bearer $RT" -i
    ```
5) Login (get fresh tokens)
    ```
    curl -sS -X POST http://localhost:8080/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"alice@example.com","password":"Secret123!"}' \
    | tee /tmp/login.json
    AT=$(jq -r '.access_token' /tmp/login.json)
    RT=$(jq -r '.refresh_token' /tmp/login.json)
    ```
6) Logout all (revoke all refresh tokens for the user)\
    Use access token:
    ```
    curl -sS -X POST http://localhost:8080/v1/auth/logout-all \
    -H "Authorization: Bearer $AT" -i
    ```