# Kubernetes

## INSEKUBE
- https://tryhackme.com/room/insekube 

TASK 2

Test all methods in an endpoint

**scan-methods.sh**
```bash
#!/bin/bash

# Define the URL to test
URL="http://localhost"

# Test GET request
echo "Testing GET request..."
GET_RESULT=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
if [[ $GET_RESULT != 200 ]]; then
  echo "GET request failed with status code $GET_RESULT"
else
  echo "GET request successful"
fi

# Test POST request
echo "Testing POST request..."
POST_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL")
if [[ $POST_RESULT != 405 ]]; then
  echo "POST request failed with status code $POST_RESULT"
else
  echo "POST request successful"
fi

# Test PUT request
echo "Testing PUT request..."
PUT_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$URL")
if [[ $PUT_RESULT != 405 ]]; then
  echo "PUT request failed with status code $PUT_RESULT"
else
  echo "PUT request successful"
fi

# Test DELETE request
echo "Testing DELETE request..."
DELETE_RESULT=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$URL")
if [[ $DELETE_RESULT != 405 ]]; then
  echo "DELETE request failed with status code $DELETE_RESULT"
else
  echo "DELETE request successful"
fi
```

Loop the methods
**loop-scan-method.sh**
```bash
#!/bin/bash

METHODS=(GET POST PUT DELETE HEAD OPTIONS TRACE CONNECT)

for method in "${METHODS[@]}"
do
    response=$(curl -s -o /dev/null -w "%{http_code}" -X $method http://localhost)

    if [ "$response" != "200" ]; then
        echo "Error with $method request"
    fi
done

```


##  References

- https://tryhackme.com/room/insekube#
- https://tryhackme.com/room/islandorchestration
- https://tryhackme.com/room/frankandherbytryagain
- https://tryhackme.com/room/palsforlife
- https://tryhackme.com/room/kubernetesforyouly
- https://tryhackme.com/room/jumpbox