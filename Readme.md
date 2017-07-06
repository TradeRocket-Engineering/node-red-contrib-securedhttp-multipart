node-red-contrib-securedhttp-multipart
=========================
[Node-RED](http://nodered.org) nodes is extended from httpmultipart 
(<a target="_blank" href="https://github.com/sax1johno/node-red-contrib-http-multipart">
    node-red-contrib-http-multipart</a>) but with built-in security.  If 
secured field is set to false, it has the same features as httpmultipart
in the default installation.  It uses a predefined OAuth endpoint 
to validate the token in authorization header or query string in a request and to check 
if the user with the token has privilege to access this node.

Install
-------
Install from [npm](http://npmjs.org)
```
npm install node-red-contrib-securedhttp-multipart
```

Usage
-----
This package contains node similar to the httpmultipart and
but securedhttpmultipart must be authenticated with a 
token in Authorization header or access_token query string for 
privileged user to access it if the "Secured" field is set to true.
When "Secured" field is set to true, user will need to have the
privilege specified in "Privileges" field.  If the "Privileges" is not
set but "Secured" field is set to true, an access token will need to 
be validated.  The OAuth user endpoint will need to specify in the 
settting.js file with "oauth2UserUrl" key.  For example,

  oauth2UserUrl: "https://localhost:8080/oauth/user",

You will need to fill in the following fields:

-- Ignore the "Start" field.

-- Secured field is set to true to enable security.  False to disable.

-- User will need to have privilege to access this endpoint even if the 
token is valid if this field is set to non-empty string.  Multiple 
privileges can be specified with comma delimiters but user will need to
have one of thoese specified privilege to access this endpoint.

Please refer to <a target="_blank" href="https://flows.nodered.org/node/node-red-contrib-http-multipart">
    node-red-contrib-http-multipart</a> for helps.


Authors
-------
* Kehang Chen - [kehangchen@yahoo.com](mailto:kehangchen@yahoo.com)
