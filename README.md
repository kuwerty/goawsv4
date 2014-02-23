# Signature v4 generation for Amazon AWS APIs

# Overview
For whatever reason Amazon have still not created a complete AWS implementation for Go yet. Many 3rd party Go libraries that interface with AWS services lack access to all APIs.

To unlock all features of AWS you may end up creating requests of your own.

Creating HTTP requests to interface with AWS is pretty simple but signing the requests has a number of pitfalls.

This library aims to provide support for signing requests in a simple manner as possible.

# Example

We will create a code snipped that posts a message to Amazon SQS.

First we create a client for the given region and service:

    client := &AWSClient {
        accessKey   : "...",
        secretKey   : "...",
        region      : "us-east-1",
        service     : "sqs",
    }

Now create the HTTP request that posts a message to the queue. You will need to find an sqs queue url yourself (the AWS console will show it).

    values := make(url.Values)
    values.Set("Action", "SendMessage")
    values.Set("Version", "2012-11-05")
    values.Set("MessageBody", "Hello World!")

    req,_ := http.NewRequest("POST", sqsQueueUrl, strings.NewReader(values.Encode()))

Now that you have a request, sign the request using the client:

    client.signv4(req)

Finally send the request.

    resp,_ := http.DefaultClient.Do(req)

