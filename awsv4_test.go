package goawsv4

import (
  "testing"
  "net/url"
  "net/http"
  "log"
  "strings"
)

func TestSign(t *testing.T) {
  if true {
    // Taken from the examples in the AWS documentaiton.
    //
    //  http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    client := &AWSClient {
      AccessKey  : "AKIAIOSFODNN7EXAMPLE",
      SecretKey  : "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      Region     : "us-east-1",
      Service    : "iam",
    }

    values := make(url.Values)
    values.Set("Action", "ListUsers")
    values.Set("Version", "2010-05-08")
    body := values.Encode()

    req, err := http.NewRequest("POST", "http://iam.amazonaws.com/", strings.NewReader(body))
    if err != nil {
      log.Fatal(err)
    }

    req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
    req.Header.Set("Date", "2011-09-09T23:36:00Z")

    client.SignV4(req)

    log.Printf("url:%s\n", req.URL.String())
    log.Printf("headers:%s\n", req.Header)

    if req.Header.Get("Authorization") != "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c" {
      t.Fail()
    }
  }
}
