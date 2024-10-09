# dns-resolver
A simple implementation of DNS resolver in Golang

### Steps:

- [x] Setup base server that takes in domain name as argument to process remaining things
- [ ] Build Header for the Query Message
- [ ] Send request to a name server and check the response
- [ ] Parse the Response we received from the name server and log it properly
    - [ ] Parse Headers
    - [ ] Parse Question
    - [ ] Parse Answer
- [ ] Query Root Name server to get the Name server for any domain
- [ ] Query for multiple types of requests such as A, CNAME, AA, MX, etc. records

