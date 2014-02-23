package goawsv4

import (
  "log"
  "net/url"
  "crypto/sha256"
  "crypto/hmac"
  "strings"
  "net/http"
  "sort"
  "time"
  "io/ioutil"
  "fmt"
  "encoding/hex"
  "bytes"
)

type AWSClient struct {
  AccessKey   string
  SecretKey   string
  Region      string
  Service     string
}

func sum256(text []byte) string {
  b := sha256.Sum256(text)
  return hex.EncodeToString(b[:])
}

//v4 signing is hmac+sha256
func hmacv4(key []byte, text string) []byte {
  mac := hmac.New(sha256.New, []byte(key))
  mac.Write([]byte(text))
  texthash := mac.Sum(nil)
  return texthash
}

func deriveKey(secret string, date string, region string, service string) []byte {
  return hmacv4(hmacv4(hmacv4(hmacv4([]byte("AWS4" + secret), date),region),service),"aws4_request")
}

//
// Given a complete HTTP request this function will sign the request and add
// the authorization header to the result.
//
func (c *AWSClient) SignV4(req *http.Request) error {

  // Compute sha256 hash of body. To avoid reading the body (if it is large) we look for the
  // Amazon header that lists it. If present we assume the client computed that correctly and
  // use it.
  contenthash := req.Header.Get("X-Amz-Content-Sha256")
  if contenthash == "" {
    // We need to read the body in order to compute the hash. We read the body into an array
    // and then create a bytes reader for the http client to read the actual request again.
    body, err := ioutil.ReadAll(req.Body)
    if err != nil {
      return err
    }

    // create new body object
    req.Body = ioutil.NopCloser(bytes.NewReader(body))

    contenthash = sum256(body)
  }

  // Get a date for the request. Either use a date the client supplies or use the current time.
  var now time.Time
  var err error

  if date := req.Header.Get("Date"); date != "" {
    now, err = time.Parse(time.RFC3339, date)
    if err != nil {
      return err
    }
    req.Header.Del("Date")  // we will add x-amz-date
  } else {
    now = time.Now().UTC()
  }

  // e.g. '20140223T033310Z'
  fulldate := fmt.Sprintf("%04d%02d%02dT%02d%02d%02dZ",
      now.Year(), now.Month(), now.Day(),
      now.Hour(), now.Minute(), now.Second())

  // e.g. '20140223'
  shortdate := fulldate[0:8]

  credential := fmt.Sprintf("%s/%s/%s/%s/aws4_request", c.AccessKey, shortdate, c.Region, c.Service)

  // add required headers to the requests
  req.Header.Set("Host", req.URL.Host)
  req.Header.Set("X-Amz-Date", fulldate)
  //req.Header.Set("X-Amz-Content-Sha256", contenthash)


  signedv := make([]string, 0)    // signed headers
  queryv := make([]string,0)      // query values
  headersv := make([]string, 0)   // header values


  queryValues := req.URL.Query()

  // build array of url query parameters
  for key, vals := range(queryValues) {
    for _, val := range(vals) {
      key = url.QueryEscape(key)
      val = url.QueryEscape(val)
      queryv = append(queryv, key+"="+val)
    }
  }

  // build array of http headers
  for key, vals := range(req.Header) {
    for _, val := range(vals) {
      key := strings.ToLower(key)
      headersv = append(headersv, key+":"+val)
      signedv = append(signedv, key)
    }
  }

  // sort the arrays
  sort.Strings(signedv)
  signed := strings.Join(signedv, ";")

  sort.Strings(headersv)
  headers := strings.Join(headersv, "\n") + "\n"

  sort.Strings(queryv)
  query := strings.Join(queryv, "&")

  // construct the canonical request
  canreqv := []string{ req.Method, req.URL.Path, query, headers, signed, contenthash }
  canreq := strings.Join(canreqv, "\n")
  canreqhash := sum256([]byte(canreq))

  // create the StringToSign
  stsv := []string {
    "AWS4-HMAC-SHA256",
    fulldate,
    fmt.Sprintf("%s/%s/%s/aws4_request", shortdate, c.Region, c.Service),
    canreqhash,
  }

  sts := strings.Join(stsv, "\n")

  // derive the signing key...
  signingKey := deriveKey(c.SecretKey, shortdate, c.Region, c.Service)

  // sign the the StringToSign 
  signature := hex.EncodeToString(hmacv4(signingKey, sts))

  // create the authorization header and append it to the request.
  authorization := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s", credential, signed, signature)

  req.Header.Set("Authorization", authorization)

  if false {
    log.Printf("contenthash:%s\n", contenthash)
    log.Printf("req:%s\n", canreq)
    log.Printf("reqhash:%s\n", canreqhash)
    log.Printf("sts:'%s'\n", sts)
    log.Printf("signingKey:%s\n", hex.EncodeToString(signingKey))
    log.Printf("signature:%s\n", signature)
  }

  return nil
}

