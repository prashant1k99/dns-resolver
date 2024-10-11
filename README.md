# dns-resolver
A simple implementation of DNS resolver in Golang

### Steps:

- [x] Setup base server that takes in domain name as argument to process remaining things
- [x] Build Header for the Query Message
- [x] Send request to a name server and check the response
- [x] Parse the Response we received from the name server and log it properly
    - [x] Parse Headers
    - [x] Parse Question
    - [x] Parse Answer
- [ ] Format the complete response in Human Readable
- [ ] Query Root Name server to get the Name server for any domain
- [ ] Query for multiple types of requests such as A, CNAME, AA, MX, etc. records

