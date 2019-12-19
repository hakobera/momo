#include "aws_wss_auth_signer.h"

#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/core/Region.h>

#include "rtc_base/logging.h"
#include "util.h"

static const char* EQ = "=";
static const char* AMP = "&";
static const char* AWS_HMAC_SHA256 = "AWS4-HMAC-SHA256";
static const char* AWS4_REQUEST = "aws4_request";
static const char* NEWLINE = "\n";
static const char* SIGNING_KEY = "AWS4";

static const char* LONG_DATE_FORMAT_STR = "%Y%m%dT%H%M%SZ";
static const char* SIMPLE_DATE_FORMAT_STR = "%Y%m%d";
static const char* EMPTY_STRING_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

static const char* X_AMZ_ALGORITHM = "X-Amz-Algorithm";
static const char* X_AMZ_CHANNEL_ARN = "X-Amz-ChannelARN";
static const char* X_AMZ_CREDENTIAL = "X-Amz-Credential";
static const char* X_AMZ_DATE = "X-Amz-Date";
static const char* X_AMZ_EXPIRES = "X-Amz-Expires";
static const char* X_AMZ_SIGNED_HEADERS = "X-Amz-SignedHeaders";
static const char* X_AMZ_SIGNATURE = "X-Amz-Signature";

static const char* SERVICE = "kinesisvideo";
static const char v4LogTag[] = "AwsWssAuthSigner";

AwsWssAuthSigner::AwsWssAuthSigner(
  const std::shared_ptr<Aws::Auth::AWSCredentialsProvider>& credentialsProvider,
  const Aws::String& region) :
  credentialsProvider_(credentialsProvider),
  region_(region),
  service_name_(SERVICE),
  hash_(Aws::MakeUnique<Aws::Utils::Crypto::Sha256>(v4LogTag)),
  HMAC_(Aws::MakeUnique<Aws::Utils::Crypto::Sha256HMAC>(v4LogTag))
{
}

AwsWssAuthSigner::~AwsWssAuthSigner()
{
}

Aws::Utils::DateTime AwsWssAuthSigner::GetSigningTimestamp() const
{
  return Aws::Utils::DateTime::Now();
}

Aws::String AwsWssAuthSigner::GenerateSignedURL(const Aws::String& endpoint, const Aws::String& channel_arn) const
{
  Aws::Auth::AWSCredentials credentials = credentialsProvider_->GetAWSCredentials();

  auto now = GetSigningTimestamp();
  auto date_string = now.ToGmtString(SIMPLE_DATE_FORMAT_STR);
  auto datetime_string = now.ToGmtString(LONG_DATE_FORMAT_STR);
  //auto date_string = "20191201";
  //auto datetime_string = "20191201T000000Z";

  RTC_LOG(LS_INFO) << __FUNCTION__ << " date_string = " << date_string;
  RTC_LOG(LS_INFO) << __FUNCTION__ << " datetime_string = " << datetime_string;

  Aws::String protocol = "wss";
  Aws::String url_protocol = protocol + "://";
  
  // Path パラメーターはない前提
  auto host = endpoint.substr(url_protocol.length());
  auto path = "/";

  auto signed_headers = Aws::String("host");
  auto method = Aws::String("GET");

  RTC_LOG(LS_INFO) << __FUNCTION__ << " host = " << host;
  RTC_LOG(LS_INFO) << __FUNCTION__ << " path = " << path;
  RTC_LOG(LS_INFO) << __FUNCTION__ << " signed_headers = " << signed_headers;
  RTC_LOG(LS_INFO) << __FUNCTION__ << " method = " << method;

  Aws::StringStream cs;
  cs << date_string << "/" << region_ << "/" << service_name_ << "/" << AWS4_REQUEST;
  auto credential_scope = cs.str();
  
  RTC_LOG(LS_INFO) << __FUNCTION__ << " credential_scope = " << credential_scope;
 
  auto canonical_query_string = GenerateCanonicalQueryString(channel_arn, credentials.GetAWSAccessKeyId(), credential_scope, datetime_string, signed_headers);
  auto canonical_headers_string = GenerateCanonicalHeadersString(host);
  auto payload_hash = EMPTY_STRING_SHA256;

  RTC_LOG(LS_INFO) << __FUNCTION__ << " canonical_query_string = " << canonical_query_string;
  RTC_LOG(LS_INFO) << __FUNCTION__ << " canonical_headers_string = " << canonical_headers_string;
  RTC_LOG(LS_INFO) << __FUNCTION__ << " payload_hash = " << payload_hash;
  
  Aws::StringStream request;
  request << method << NEWLINE;
  request << path << NEWLINE;
  request << canonical_query_string << NEWLINE;
  request << canonical_headers_string << NEWLINE;
  request << signed_headers << NEWLINE;
  request << payload_hash;
  
  auto request_hash = Aws::Utils::HashingUtils::HexEncode(hash_->Calculate(request).GetResult());
  
  RTC_LOG(LS_INFO) << __FUNCTION__ << " request = " << request.str();
  RTC_LOG(LS_INFO) << __FUNCTION__ << " request_hash = " << request_hash;

  Aws::StringStream ss;
  ss << AWS_HMAC_SHA256 << NEWLINE;
  ss << datetime_string << NEWLINE;
  ss << credential_scope << NEWLINE;
  ss << request_hash;
  auto signing_string = ss.str();

  auto signing_key = GetSignatureKey(credentials.GetAWSSecretKey(), date_string, region_, service_name_);
  auto signing_hash = HMAC_->Calculate(Aws::Utils::ByteBuffer((unsigned char*)signing_string.c_str(), signing_string.length()), signing_key);
  auto signature = Aws::Utils::HashingUtils::HexEncode(signing_hash.GetResult());

  RTC_LOG(LS_INFO) << __FUNCTION__ << " signing_string = " << signing_string;
  RTC_LOG(LS_INFO) << __FUNCTION__ << " signature = " << signature;

  Aws::StringStream url;
  url << endpoint << path << "?" << canonical_query_string << AMP << X_AMZ_SIGNATURE << EQ << signature;
  return url.str();
}

Aws::String AwsWssAuthSigner::GenerateCanonicalQueryString(const Aws::String& channel_arn, const Aws::String& access_key_id, const Aws::String& credential_scope, const Aws::String& datetime_string, const Aws::String& signed_headers) const
{
  Aws::StringStream qs;
  qs << X_AMZ_ALGORITHM << EQ << AWS_HMAC_SHA256;
  qs << AMP << X_AMZ_CHANNEL_ARN << EQ << Aws::Utils::StringUtils::URLEncode(channel_arn.c_str());
  qs << AMP << X_AMZ_CREDENTIAL << EQ << Aws::Utils::StringUtils::URLEncode((access_key_id + "/" + credential_scope).c_str());
  qs << AMP << X_AMZ_DATE << EQ << Aws::Utils::StringUtils::URLEncode(datetime_string.c_str());
  qs << AMP << X_AMZ_EXPIRES << EQ << "299";
  qs << AMP << X_AMZ_SIGNED_HEADERS << EQ << Aws::Utils::StringUtils::URLEncode(signed_headers.c_str());
  return qs.str();
}

Aws::String AwsWssAuthSigner::GenerateCanonicalHeadersString(const Aws::String& host) const
{
  Aws::StringStream hs;
  hs << "host:" << host << NEWLINE;
  return hs.str();
}

Aws::Utils::ByteBuffer AwsWssAuthSigner::GetSignatureKey(const Aws::String& secret_key, const Aws::String& simple_date, const Aws::String& region, const Aws::String& service_name) const
{
  Aws::String signing_key(SIGNING_KEY);
  signing_key.append(secret_key);
  auto hash_result = HMAC_->Calculate(
    Aws::Utils::ByteBuffer((unsigned char*)simple_date.c_str(), simple_date.length()),
    Aws::Utils::ByteBuffer((unsigned char*)signing_key.c_str(), signing_key.length()));
  
  auto k_date = hash_result.GetResult();
  hash_result = HMAC_->Calculate(Aws::Utils::ByteBuffer((unsigned char*)region.c_str(), region.length()), k_date);

  auto k_region = hash_result.GetResult();
  hash_result = HMAC_->Calculate(Aws::Utils::ByteBuffer((unsigned char*)service_name.c_str(), service_name.length()), k_region);

  auto k_service = hash_result.GetResult();
  hash_result = HMAC_->Calculate(Aws::Utils::ByteBuffer((unsigned char*)AWS4_REQUEST, strlen(AWS4_REQUEST)), k_service);

  return hash_result.GetResult();
}
