// This file is part of MLDB. Copyright 2015 mldb.ai inc. All rights reserved.

/* aws_test.cc
   Jeremy Barnes, 12 May 2013
   Copyright (c) 2013 mldb.ai inc.  All rights reserved.

   Test of the basic functionality of authenticating AWS requests.
*/


#define BOOST_TEST_MAIN
#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>
#include "mldb/soa/service/sqs.h"
#include "mldb/jml/utils/file_functions.h"
#include <iostream>
#include <stdlib.h>
#include "mldb/jml/utils/vector_utils.h"
#include "mldb/jml/utils/pair_utils.h"


using namespace std;
using namespace MLDB;
using namespace ML;

// These are all of those on http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/RESTAuthentication.html?r=1821

string accessKeyId = "AKIAIOSFODNN7EXAMPLE";
string accessKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

BOOST_AUTO_TEST_CASE( test_signing_1 )
{
    string correctDigest = 
        "GET\n"
        "\n"
        "\n"
        "Tue, 27 Mar 2007 19:42:41 +0000\n"
        "/johnsmith/";
        
    BOOST_CHECK_EQUAL(AwsApi::getStringToSignV2("GET", "johnsmith", "/", "", "", "",
                                                "Tue, 27 Mar 2007 19:42:41 +0000",
                                                {}),
                      correctDigest);
    
    string correctAuth = "htDYFYduRNen8P9ZfE/s9SuKy0U=";

    BOOST_CHECK_EQUAL(AwsApi::signV2(correctDigest, accessKey),
                      correctAuth);
}

BOOST_AUTO_TEST_CASE ( test_signing_2 )
{
    /* PUT /photos/puppy.jpg HTTP/1.1
       Content-Type: image/jpeg
       Content-Length: 94328
       Host: johnsmith.s3.amazonaws.com
       Date: Tue, 27 Mar 2007 21:15:45 +0000

       Authorization: AWS AKIAIOSFODNN7EXAMPLE:
       MyyxeRY7whkBe+bq8fHCL/2kKUg=
    */

    string correctDigest = 
        "PUT\n"
        "\n"
        "image/jpeg\n"
        "Tue, 27 Mar 2007 21:15:45 +0000\n"
        "/johnsmith/photos/puppy.jpg";

    string correctAuth = "MyyxeRY7whkBe+bq8fHCL/2kKUg=";

    BOOST_CHECK_EQUAL(AwsApi::getStringToSignV2("PUT", "johnsmith", "/photos/puppy.jpg", "",
                                                "image/jpeg", "",
                                                "Tue, 27 Mar 2007 21:15:45 +0000",
                                                {}),
                      correctDigest);
    
    
    BOOST_CHECK_EQUAL(AwsApi::signV2(correctDigest, accessKey),
                      correctAuth);
}


BOOST_AUTO_TEST_CASE ( test_signing_3 )
{
    /* GET /?prefix=photos&max-keys=50&marker=puppy HTTP/1.1
       User-Agent: Mozilla/5.0
       Host: johnsmith.s3.amazonaws.com
       Date: Tue, 27 Mar 2007 19:42:41 +0000

       Authorization: AWS AKIAIOSFODNN7EXAMPLE:
       htDYFYduRNen8P9ZfE/s9SuKy0U=
    */

    string correctDigest = 
        "GET\n"
        "\n"
        "\n"
        "Tue, 27 Mar 2007 19:42:41 +0000\n"
        "/johnsmith/";
    
    string correctAuth = "htDYFYduRNen8P9ZfE/s9SuKy0U=";

    BOOST_CHECK_EQUAL(AwsApi::getStringToSignV2("GET", "johnsmith", "/", "",
                                                "", "",
                                                "Tue, 27 Mar 2007 19:42:41 +0000",
                                                {}),
                      correctDigest);
    

    BOOST_CHECK_EQUAL(AwsApi::signV2(correctDigest, accessKey),
                      correctAuth);
}


BOOST_AUTO_TEST_CASE ( test_signing_4 )
{
    /* GET /?acl HTTP/1.1
       Host: johnsmith.s3.amazonaws.com
       Date: Tue, 27 Mar 2007 19:44:46 +0000
       
       Authorization: AWS AKIAIOSFODNN7EXAMPLE:
       c2WLPFtWHVgbEmeEG93a4cG37dM=
    */

    string correctDigest = 
        "GET\n"
        "\n"
        "\n"
        "Tue, 27 Mar 2007 19:44:46 +0000\n"
        "/johnsmith/?acl";
    
    string correctAuth = "c2WLPFtWHVgbEmeEG93a4cG37dM=";

    BOOST_CHECK_EQUAL(AwsApi::getStringToSignV2("GET", "johnsmith", "/", "acl",
                                                "", "",
                                                "Tue, 27 Mar 2007 19:44:46 +0000",
                                                {}),
                      correctDigest);
    
    
    BOOST_CHECK_EQUAL(AwsApi::signV2(correctDigest, accessKey),
                      correctAuth);
}

BOOST_AUTO_TEST_CASE ( test_signing_5 )
{
    /* PUT /db-backup.dat.gz HTTP/1.1
       User-Agent: curl/7.15.5
       Host: static.johnsmith.net:8080
       Date: Tue, 27 Mar 2007 21:06:08 +0000

       x-amz-acl: public-read
       content-type: application/x-download
       Content-MD5: 4gJE4saaMU4BqNR0kLY+lw==
       X-Amz-Meta-ReviewedBy: joe@johnsmith.net
       X-Amz-Meta-ReviewedBy: jane@johnsmith.net
       X-Amz-Meta-FileChecksum: 0x02661779
       X-Amz-Meta-ChecksumAlgorithm: crc32
       Content-Disposition: attachment; filename=database.dat
       Content-Encoding: gzip
       Content-Length: 5913339

       Authorization: AWS AKIAIOSFODNN7EXAMPLE:
       ilyl83RwaSoYIEdixDQcA4OnAnc=
    */

    string correctDigest = 
        "PUT\n"
        "4gJE4saaMU4BqNR0kLY+lw==\n"
        "application/x-download\n"
        "Tue, 27 Mar 2007 21:06:08 +0000\n"
        "x-amz-acl:public-read\n"
        "x-amz-meta-checksumalgorithm:crc32\n"
        "x-amz-meta-filechecksum:0x02661779\n"
        "x-amz-meta-reviewedby:joe@johnsmith.net,jane@johnsmith.net\n"
        "/static.johnsmith.net/db-backup.dat.gz";
    
    string correctAuth = "ilyl83RwaSoYIEdixDQcA4OnAnc=";

    vector<pair<string, string> > headers = {
        {"x-amz-acl", "public-read" },
        { "X-Amz-Meta-ReviewedBy", "joe@johnsmith.net" },
        { "X-Amz-Meta-ReviewedBy", "jane@johnsmith.net" },
        { "X-Amz-Meta-FileChecksum", "0x02661779" },
        { "X-Amz-Meta-ChecksumAlgorithm", "crc32" }
    };

    BOOST_CHECK_EQUAL(AwsApi::getStringToSignV2Multi("PUT", "static.johnsmith.net",
                                                     "/db-backup.dat.gz", "",
                                                     "application/x-download",
                                                     "4gJE4saaMU4BqNR0kLY+lw==",
                                                     "Tue, 27 Mar 2007 21:06:08 +0000",
                                                     headers),
                      correctDigest);
    
    
    BOOST_CHECK_EQUAL(AwsApi::signV2(correctDigest, accessKey),
                      correctAuth);
}

BOOST_AUTO_TEST_CASE( test_signing_v4 )
{
    // Test cases are from
    // http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    
    string sampleSigningKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    string digest = AwsApi::signingKeyV4(sampleSigningKey, "20110909","us-east-1","iam","aws4_request");
    string hexDigest = AwsApi::hexEncodeDigest(digest);

    BOOST_CHECK_EQUAL(hexDigest, "98f1d889fec4f4421adc522bab0ce1f82e6929c262ed15e5a94c90efd1e3b0e7");

    
    string stringToSign =
        "AWS4-HMAC-SHA256\n"
        "20110909T233600Z\n"
        "20110909/us-east-1/iam/aws4_request\n"
        "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2";

    string signature = AwsApi::signV4(stringToSign, sampleSigningKey, "20110909", "us-east-1", "iam", "aws4_request");

    BOOST_CHECK_EQUAL(signature, "ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c");
}


BOOST_AUTO_TEST_CASE( check_canonical_request_v4 )
{
    // See here:

    // http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

    /*
      POST http://iam.amazonaws.com/ HTTP/1.1
      host: iam.amazonaws.com
      Content-type: application/x-www-form-urlencoded; charset=utf-8
      x-amz-date: 20110909T233600Z

      Action=ListUsers&Version=2010-05-08
    */

    // Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c

    
    //QueryParams params;
    //params.push_back({"Action","ListUsers"});
    //params.push_back({"Version","2010-05-08"});

    string accessKeyId = "AKIDEXAMPLE";
    string accessKey   = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    AwsApi::BasicRequest request;
    request.method = "POST";
    request.relativeUri = "";
    request.headers.push_back({"host", "iam.amazonaws.com"});
    request.headers.push_back({"Content-Type", "application/x-www-form-urlencoded; charset=utf-8"});
    //request.headers.push_back({"x-amz-date", "20110909T233600Z"});
    request.payload = "Action=ListUsers&Version=2010-05-08";


    AwsApi::addSignatureV4(request, "iam", "us-east-1",
                           accessKeyId, accessKey,
                           Date(2011,9,9,23,36,00), AwsApi::PLD_IMPLICIT);
    
    Utf8String auth;

    for (auto h: request.headers)
        if (h.first == "Authorization")
            auth = h.second;

    BOOST_CHECK_EQUAL(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c");
}

BOOST_AUTO_TEST_CASE( check_canonical_request_v4_again )
{
    /*
      GET /jeremytest/hello.txt HTTP/1.1
      Host: s3.amazonaws.com
      Accept-Encoding: identity
      x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      Authorization: AWS4-HMAC-SHA256 Credential=PSFBZZZZZZZZ/20180329/US/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=f81209a792f55e50f1b59c3257474127e299e6663e29687ac8394c982ca674d2
      x-amz-date: 20180329T192537Z

      Key Id: PSFBZZZZZZZZ
      Key:    0123/456789AB/CDEF
    */

    string accessKeyId = "PSFBZZZZZZZZ";
    string accessKey   = "0123/456789AB/CDEF";

    AwsApi::BasicRequest request;
    request.method = "GET";
    request.relativeUri = "jeremytest/hello.txt";
    request.headers.push_back({"Host", "s3.amazonaws.com"});
    //request.headers.push_back({"x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"});

    AwsApi::addSignatureV4(request, "s3", "US", accessKeyId, accessKey, Date(2018,3,29,19,25,37));

    string auth;

    for (auto h: request.headers)
        if (h.first == "Authorization")
            auth = h.second.rawString();

    /*
      canonical request GET
      /jeremytest/hello.txt

      host:s3.amazonaws.com
      x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      x-amz-date:20180329T201205Z

      host;x-amz-content-sha256;x-amz-date
      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      signed request e3a078a4523f99862dd67af882f6e7f83beb4ffdb4ae9a85642d66e091dc34da
      string_to_sign AWS4-HMAC-SHA256
      20180329T201205Z
      20180329/US/s3/aws4_request
      e3a078a4523f99862dd67af882f6e7f83beb4ffdb4ae9a85642d66e091dc34da

    */
    
    string authExpected = "AWS4-HMAC-SHA256 Credential=PSFBZZZZZZZZ/20180329/US/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=f81209a792f55e50f1b59c3257474127e299e6663e29687ac8394c982ca674d2";

    cerr << auth << endl;
    cerr << authExpected << endl;
    
    BOOST_CHECK_EQUAL(auth, authExpected);
    BOOST_CHECK_EQUAL_COLLECTIONS(auth.begin(), auth.end(),
                                  authExpected.begin(), authExpected.end());
}
